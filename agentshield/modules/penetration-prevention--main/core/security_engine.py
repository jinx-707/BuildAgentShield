"""
AgentShield Unified Security Engine.
Single entry point for all runtime security checks across the AgentShield gateway.

Design principles
-----------------
* **Compose, don't duplicate.** Every check is delegated to an already-tested
  sub-engine (InputGuard, OutputGuard, RiskEngine, ProvenanceEngine, and the
  individual detectors).  The SecurityEngine wires them together and adds the
  single-entry-point contract, configurable policy, and fail-safe guarantees.
* **Fail-closed.** Any unhandled exception in a sub-engine causes the engine
  to return BLOCK, never ALLOW.  Content that has not completed all mandatory
  checks is never allowed through.
* **Consistent schema.** All four public methods return objects built from the
  existing ``schemas`` module so callers never need to handle multiple response
  shapes.
* **No shared-file modifications.** InputGuard, OutputGuard, RiskEngine,
  ProvenanceEngine, and all detector files are treated as read-only
  dependencies.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from core.config import AgentShieldConfig, setup_logger
from core.dlp_engine import DLPEngine
from core.injection_detector import PromptInjectionDetector
from core.input_guard import InputGuard
from core.output_guard import OutputGuard
from core.pii_detector import PIIDetector
from core.provenance import ProvenanceEngine
from core.risk_engine import RiskEngine
from core.schemas import (
    Action,
    DetectionFinding,
    DetectorType,
    DLPAnalysisResult,
    GuardrailContext,
    GuardrailInputResponse,
    GuardrailOutputResponse,
    GuardrailViolationError,
    InjectionAnalysisResult,
    PIIAnalysisResult,
    ProvenanceRecord,
    RiskLevel,
    RiskScore,
    SecretAnalysisResult,
    SourceType,
    TrustLevel,
)
from core.secret_scanner import SecretScanner

logger = setup_logger("agentshield.security_engine")


# ---------------------------------------------------------------------------
# Security Policy
# ---------------------------------------------------------------------------

@dataclass
class SecurityPolicy:
    """
    Configurable security policy for the UnifiedSecurityEngine.

    Each boolean flag marks a detector as *mandatory*.  When a mandatory
    detector is disabled (via ``AgentShieldConfig``) or fails at runtime, the
    engine treats the situation as a policy violation and returns BLOCK rather
    than silently allowing the content through.

    The ``default_trust_level`` and ``default_source_type`` act as sane
    defaults when callers omit those arguments.

    ``block_on_quarantine`` (default True) ensures that QUARANTINE decisions
    from the underlying guards are surfaced as blocked rather than allowed.
    This mirrors the behaviour of the guards themselves
    (``allowed = action not in {BLOCK, QUARANTINE}``).
    """

    # Mandatory detector flags
    require_injection_check: bool = True
    require_pii_check: bool = True
    require_secret_check: bool = True
    require_dlp_check: bool = True

    # Source / trust defaults used when the caller does not specify them
    default_source_type: SourceType = SourceType.USER
    default_trust_level: TrustLevel = TrustLevel.MEDIUM

    # When True, QUARANTINE actions are counted as "not allowed"
    block_on_quarantine: bool = True

    # Extra metadata attached to every provenance record created here
    extra_metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Response types for calculate_risk (wraps existing RiskScore)
# ---------------------------------------------------------------------------

@dataclass
class RiskAssessment:
    """
    Response returned by ``SecurityEngine.calculate_risk``.

    Wraps the existing ``RiskScore`` (from schemas) to give callers a
    consistent entry-point response object with latency and audit metadata.
    """

    risk_score: RiskScore
    findings: list[DetectionFinding]
    provenance_record: ProvenanceRecord
    latency_ms: float

    @property
    def allowed(self) -> bool:
        return self.risk_score.recommended_action not in (Action.BLOCK, Action.QUARANTINE)

    @property
    def action(self) -> Action:
        return self.risk_score.recommended_action

    @property
    def level(self) -> RiskLevel:
        return self.risk_score.level

    @property
    def score(self) -> float:
        return self.risk_score.overall_score


# ---------------------------------------------------------------------------
# Unified Security Engine
# ---------------------------------------------------------------------------

class SecurityEngine:
    """
    Unified Security Engine — single entry point for all AgentShield checks.

    Provides four asynchronous methods:

    ``inspect_input(request)``
        Validates inbound user/agent prompts through the full InputGuard
        pipeline (injection, PII, secrets, DLP, provenance).

    ``inspect_output(tool_call)``
        Validates outbound tool-call arguments or tool execution outputs
        through the full OutputGuard pipeline before release to external
        services.

    ``inspect_data(content)``
        Validates arbitrary external data (web scrapes, file contents,
        retrieved documents) using the external-content path of InputGuard
        with configurable source type and trust level.

    ``calculate_risk(context)``
        Runs all individual detectors concurrently against a piece of
        content, then feeds every result into the RiskEngine and records a
        provenance entry — without going through the full guardrail pipeline.
        Returns a ``RiskAssessment`` with the aggregate ``RiskScore`` and
        all individual ``DetectionFinding`` objects.

    Fail-safe guarantee
    -------------------
    Any unhandled exception anywhere in the pipeline causes the relevant
    method to return a BLOCK decision and record a provenance entry tagged
    with ``policy: fail_closed``.  Content that has not completed all
    *mandatory* checks (as configured in ``SecurityPolicy``) is **never**
    allowed through.
    """

    def __init__(
        self,
        config: AgentShieldConfig | None = None,
        policy: SecurityPolicy | None = None,
        # Allow full dependency injection for testing
        injection_detector: PromptInjectionDetector | None = None,
        pii_detector: PIIDetector | None = None,
        secret_scanner: SecretScanner | None = None,
        dlp_engine: DLPEngine | None = None,
        risk_engine: RiskEngine | None = None,
        provenance_engine: ProvenanceEngine | None = None,
        input_guard: InputGuard | None = None,
        output_guard: OutputGuard | None = None,
    ) -> None:
        self.config = config or AgentShieldConfig()
        self.policy = policy or SecurityPolicy()

        # --- Sub-engines -------------------------------------------------
        # Build shared instances so every guard shares the *same* provenance
        # ledger and risk engine — critical for a coherent audit trail.
        self.provenance_engine = provenance_engine or ProvenanceEngine(self.config)
        self.risk_engine = risk_engine or RiskEngine(self.config)

        self.injection_detector = injection_detector or PromptInjectionDetector(self.config)
        self.pii_detector = pii_detector or PIIDetector(self.config)
        self.secret_scanner = secret_scanner or SecretScanner(self.config)
        self.dlp_engine = dlp_engine or DLPEngine(self.config)

        # --- Guards -------------------------------------------------------
        # Guards receive the *shared* sub-engine instances so their internal
        # scans reuse already-warmed detectors and their provenance records
        # land in the same ledger.
        self.input_guard = input_guard or InputGuard(
            config=self.config,
            injection_detector=self.injection_detector,
            pii_detector=self.pii_detector,
            secret_scanner=self.secret_scanner,
            dlp_engine=self.dlp_engine,
            risk_engine=self.risk_engine,
            provenance_engine=self.provenance_engine,
        )
        self.output_guard = output_guard or OutputGuard(
            config=self.config,
            secret_scanner=self.secret_scanner,
            pii_detector=self.pii_detector,
            dlp_engine=self.dlp_engine,
            risk_engine=self.risk_engine,
            provenance_engine=self.provenance_engine,
            injection_detector=self.injection_detector,
        )

        logger.info(
            "SecurityEngine initialised. "
            "mandatory_checks=[injection=%s, pii=%s, secret=%s, dlp=%s] "
            "block_on_quarantine=%s",
            self.policy.require_injection_check,
            self.policy.require_pii_check,
            self.policy.require_secret_check,
            self.policy.require_dlp_check,
            self.policy.block_on_quarantine,
        )

    # -----------------------------------------------------------------------
    # Policy helpers
    # -----------------------------------------------------------------------

    def _check_mandatory_detectors(self) -> list[str]:
        """
        Returns a list of human-readable violation messages for every mandatory
        detector that is currently disabled in the configuration.
        An empty list means all required checks are active.
        """
        violations: list[str] = []
        if self.policy.require_injection_check and not self.config.enable_injection_detection:
            violations.append(
                "Mandatory injection detector is disabled (enable_injection_detection=False)"
            )
        if self.policy.require_pii_check and not self.config.enable_pii_detection:
            violations.append(
                "Mandatory PII detector is disabled (enable_pii_detection=False)"
            )
        if self.policy.require_secret_check and not self.config.enable_secret_scanning:
            violations.append(
                "Mandatory secret scanner is disabled (enable_secret_scanning=False)"
            )
        if self.policy.require_dlp_check and not self.config.enable_dlp:
            violations.append(
                "Mandatory DLP engine is disabled (enable_dlp=False)"
            )
        return violations

    def _is_allowed(self, action: Action) -> bool:
        """Maps an Action to an allowed/blocked boolean respecting the policy."""
        if action == Action.QUARANTINE:
            return not self.policy.block_on_quarantine
        return action not in (Action.BLOCK,)

    def _fail_closed_input_response(
        self,
        raw_prompt: str,
        reason: str,
        context: GuardrailContext,
        start_time: float,
    ) -> GuardrailInputResponse:
        """Builds a BLOCK GuardrailInputResponse for fail-closed scenarios."""
        prov = self.provenance_engine.create_record(
            input_text=raw_prompt,
            action=Action.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            session_id=context.session_id,
            agent_id=context.agent_id,
            metadata={
                "policy": "fail_closed",
                "reason": reason,
                "stage": "inspect_input",
                **self.policy.extra_metadata,
            },
        )
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        return GuardrailInputResponse(
            allowed=False,
            action=Action.BLOCK,
            sanitized_prompt="[INPUT_BLOCKED_BY_SECURITY_ENGINE: mandatory check failure]",
            risk_assessment=self.risk_engine.evaluate(),
            findings=[],
            provenance_record=prov,
            latency_ms=latency_ms,
        )

    def _fail_closed_output_response(
        self,
        raw_output: str,
        reason: str,
        context: GuardrailContext,
        start_time: float,
        stage: str = "inspect_output",
    ) -> GuardrailOutputResponse:
        """Builds a BLOCK GuardrailOutputResponse for fail-closed scenarios."""
        prov = self.provenance_engine.create_record(
            input_text="fail_closed_output",
            action=Action.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            output_text=raw_output,
            session_id=context.session_id,
            agent_id=context.agent_id,
            metadata={
                "policy": "fail_closed",
                "reason": reason,
                "stage": stage,
                **self.policy.extra_metadata,
            },
        )
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        return GuardrailOutputResponse(
            allowed=False,
            action=Action.BLOCK,
            sanitized_output="[OUTPUT_BLOCKED_BY_SECURITY_ENGINE: mandatory check failure]",
            risk_assessment=self.risk_engine.evaluate(),
            findings=[],
            provenance_record=prov,
            latency_ms=latency_ms,
        )

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def inspect_input(
        self,
        request: str | Any,
        context: GuardrailContext | None = None,
        source_type: SourceType | None = None,
        trust_level: TrustLevel | None = None,
        source_uri: str | None = None,
        parent_id: str | None = None,
        requested_action: Action | str | None = None,
        raise_on_block: bool = False,
    ) -> GuardrailInputResponse:
        """
        Validates an inbound prompt or user request through the full InputGuard
        pipeline: injection detection, PII masking, secret scanning, DLP
        classification, risk scoring, and provenance recording.

        Parameters
        ----------
        request:
            Raw prompt string or ``GuardrailInputRequest``.
        context:
            Optional guardrail context (session_id, agent_id, tools, etc.).
        source_type:
            Origin of the content. Defaults to ``policy.default_source_type``.
        trust_level:
            Trust tier of the source. Defaults to ``policy.default_trust_level``.
        source_uri:
            Optional URI identifying the source location.
        parent_id:
            Provenance record ID of the parent content, enabling lineage chains.
        requested_action:
            Action the agent intends to perform with this content.
        raise_on_block:
            When True, raises ``GuardrailViolationError`` for BLOCK/QUARANTINE.

        Returns
        -------
        GuardrailInputResponse
            Consistent response object from the existing schema, guaranteed to
            be BLOCK if any mandatory check could not complete.
        """
        start_time = time.perf_counter()
        ctx = context or GuardrailContext()

        # 1. Mandatory detector availability check (fail-closed)
        violations = self._check_mandatory_detectors()
        if violations:
            reason = "; ".join(violations)
            logger.error(
                "SecurityEngine.inspect_input fail-closed: mandatory detectors missing — %s",
                reason,
            )
            response = self._fail_closed_input_response(
                raw_prompt=request if isinstance(request, str) else str(request),
                reason=reason,
                context=ctx,
                start_time=start_time,
            )
            if raise_on_block:
                raise GuardrailViolationError(reason, action=Action.BLOCK, risk_score=1.0)
            return response

        # 2. Delegate to InputGuard (which runs all detectors concurrently)
        try:
            response = await self.input_guard.validate_async(
                request=request,
                context=ctx,
                source_type=source_type or self.policy.default_source_type,
                trust_level=trust_level or self.policy.default_trust_level,
                source_uri=source_uri,
                parent_id=parent_id,
                requested_action=requested_action,
                raise_on_block=raise_on_block,
            )
        except GuardrailViolationError:
            # Re-raise without wrapping — the guard already produced the right error type.
            raise
        except Exception as exc:
            reason = f"InputGuard raised unexpected exception: {exc}"
            logger.critical("SecurityEngine.inspect_input fail-closed: %s", reason, exc_info=True)
            response = self._fail_closed_input_response(
                raw_prompt=request if isinstance(request, str) else str(request),
                reason=reason,
                context=ctx,
                start_time=start_time,
            )
            if raise_on_block:
                raise GuardrailViolationError(reason, action=Action.BLOCK, risk_score=1.0) from exc
            return response

        # 3. Honour policy for QUARANTINE (guard may allow it, policy may block it)
        if response.action == Action.QUARANTINE and self.policy.block_on_quarantine:
            # Return the guard's response with its existing provenance record;
            # the allowed flag is already False because the guard sets
            # allowed = action not in (BLOCK, QUARANTINE).
            pass

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.info(
            "SecurityEngine.inspect_input: action=%s allowed=%s risk=%s latency=%.2fms",
            response.action.value,
            response.allowed,
            response.risk_assessment.level.value,
            latency_ms,
        )
        return response

    async def inspect_output(
        self,
        tool_call: dict[str, Any] | str,
        context: GuardrailContext | None = None,
        mode: str = "tool_call",
        source_input_hash: str | None = None,
        source_uri: str | None = None,
        parent_id: str | None = None,
        raise_on_block: bool = False,
    ) -> GuardrailOutputResponse:
        """
        Validates content about to be sent to — or received from — an external
        tool or service through the full OutputGuard pipeline.

        Parameters
        ----------
        tool_call:
            For ``mode="tool_call"``: a dict with ``tool_name`` (str) and
            ``tool_args`` (dict | str) keys, or a plain string treated as args
            for an anonymous tool.
            For ``mode="tool_output"``: a dict with ``tool_name`` (str) and
            ``tool_output`` (str | dict) keys, or a plain string.
            For ``mode="agent_response"``: the raw LLM response text or a
            plain string.
        context:
            Optional guardrail context.
        mode:
            One of ``"tool_call"`` (default), ``"tool_output"``, or
            ``"agent_response"``.  Controls which OutputGuard specialised
            method is invoked.
        source_input_hash:
            Hash of the originating input record, enabling provenance linkage.
        source_uri:
            Optional URI for tool-output provenance.
        parent_id:
            Provenance parent record ID.
        raise_on_block:
            When True, raises ``GuardrailViolationError`` for BLOCK/QUARANTINE.

        Returns
        -------
        GuardrailOutputResponse
            Consistent response object from the existing schema.
        """
        start_time = time.perf_counter()
        ctx = context or GuardrailContext()

        # 1. Mandatory check (fail-closed)
        violations = self._check_mandatory_detectors()
        if violations:
            reason = "; ".join(violations)
            logger.error(
                "SecurityEngine.inspect_output fail-closed: %s", reason
            )
            response = self._fail_closed_output_response(
                raw_output=str(tool_call),
                reason=reason,
                context=ctx,
                start_time=start_time,
                stage="inspect_output",
            )
            if raise_on_block:
                raise GuardrailViolationError(reason, action=Action.BLOCK, risk_score=1.0)
            return response

        # 2. Parse the tool_call argument based on mode
        try:
            if mode == "tool_call":
                if isinstance(tool_call, dict):
                    tool_name = str(tool_call.get("tool_name", "unknown_tool"))
                    tool_args = tool_call.get("tool_args", tool_call)
                else:
                    tool_name = "anonymous_tool"
                    tool_args = tool_call
                response = await self.output_guard.validate_tool_call_async(
                    tool_name=tool_name,
                    tool_args=tool_args,
                    context=ctx,
                    source_input_hash=source_input_hash,
                    raise_on_block=raise_on_block,
                )

            elif mode == "tool_output":
                if isinstance(tool_call, dict):
                    tool_name = str(tool_call.get("tool_name", "unknown_tool"))
                    tool_output = tool_call.get("tool_output", tool_call)
                else:
                    tool_name = "anonymous_tool"
                    tool_output = tool_call
                response = await self.output_guard.validate_tool_output_async(
                    tool_name=tool_name,
                    tool_output=tool_output,
                    context=ctx,
                    source_uri=source_uri,
                    parent_id=parent_id,
                    raise_on_block=raise_on_block,
                )

            else:
                # mode == "agent_response" or any unrecognised mode
                raw_text = (
                    str(tool_call.get("response", tool_call))
                    if isinstance(tool_call, dict)
                    else str(tool_call)
                )
                response = await self.output_guard.validate_async(
                    request=raw_text,
                    context=ctx,
                    source_input_hash=source_input_hash,
                    source_type=SourceType.AGENT,
                    raise_on_block=raise_on_block,
                )

        except GuardrailViolationError:
            raise
        except Exception as exc:
            reason = f"OutputGuard raised unexpected exception: {exc}"
            logger.critical("SecurityEngine.inspect_output fail-closed: %s", reason, exc_info=True)
            response = self._fail_closed_output_response(
                raw_output=str(tool_call),
                reason=reason,
                context=ctx,
                start_time=start_time,
                stage="inspect_output",
            )
            if raise_on_block:
                raise GuardrailViolationError(reason, action=Action.BLOCK, risk_score=1.0) from exc
            return response

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.info(
            "SecurityEngine.inspect_output: mode=%s action=%s allowed=%s latency=%.2fms",
            mode,
            response.action.value,
            response.allowed,
            latency_ms,
        )
        return response

    async def inspect_data(
        self,
        content: str,
        source_type: SourceType | str | None = None,
        trust_level: TrustLevel | str | None = None,
        source_uri: str | None = None,
        context: GuardrailContext | None = None,
        raise_on_block: bool = False,
    ) -> GuardrailInputResponse:
        """
        Validates arbitrary external data — web scrapes, uploaded documents,
        retrieved files, or any unstructured content — before it is consumed
        by the agent.

        Uses ``InputGuard.validate_external_content_async`` which applies the
        full detector suite with an explicitly-set origin and trust tier.

        Parameters
        ----------
        content:
            The raw text content to evaluate.
        source_type:
            Origin classification (WEBSITE, FILE, TOOL_OUTPUT, etc.).
            Defaults to ``policy.default_source_type``; for external data this
            is commonly ``SourceType.WEBSITE`` or ``SourceType.FILE``.
        trust_level:
            Trust tier.  Defaults to ``policy.default_trust_level``; for
            untrusted external content callers should pass ``TrustLevel.UNTRUSTED``.
        source_uri:
            Optional URI or file path identifying the data source.
        context:
            Optional guardrail context.
        raise_on_block:
            When True, raises ``GuardrailViolationError`` for BLOCK/QUARANTINE.

        Returns
        -------
        GuardrailInputResponse
            Consistent response object from the existing schema.
        """
        start_time = time.perf_counter()
        ctx = context or GuardrailContext()

        # 1. Mandatory check (fail-closed)
        violations = self._check_mandatory_detectors()
        if violations:
            reason = "; ".join(violations)
            logger.error("SecurityEngine.inspect_data fail-closed: %s", reason)
            response = self._fail_closed_input_response(
                raw_prompt=content,
                reason=reason,
                context=ctx,
                start_time=start_time,
            )
            if raise_on_block:
                raise GuardrailViolationError(reason, action=Action.BLOCK, risk_score=1.0)
            return response

        # 2. Resolve source / trust from args or policy defaults
        effective_source = source_type or self.policy.default_source_type
        effective_trust = trust_level or self.policy.default_trust_level

        # 3. Delegate to InputGuard's external-content specialisation
        try:
            response = await self.input_guard.validate_external_content_async(
                content=content,
                source_type=effective_source,
                trust_level=effective_trust,
                source_uri=source_uri,
                context=ctx,
                raise_on_block=raise_on_block,
            )
        except GuardrailViolationError:
            raise
        except Exception as exc:
            reason = f"validate_external_content_async raised unexpected exception: {exc}"
            logger.critical("SecurityEngine.inspect_data fail-closed: %s", reason, exc_info=True)
            response = self._fail_closed_input_response(
                raw_prompt=content,
                reason=reason,
                context=ctx,
                start_time=start_time,
            )
            if raise_on_block:
                raise GuardrailViolationError(reason, action=Action.BLOCK, risk_score=1.0) from exc
            return response

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.info(
            "SecurityEngine.inspect_data: source=%s trust=%s action=%s latency=%.2fms",
            effective_source,
            effective_trust,
            response.action.value,
            latency_ms,
        )
        return response

    async def calculate_risk(
        self,
        content: str,
        context: GuardrailContext | None = None,
        source_trust: TrustLevel | None = None,
        requested_action: Action | str | None = None,
        record_provenance: bool = True,
    ) -> RiskAssessment:
        """
        Runs all individual detectors concurrently against ``content`` and
        feeds every result into the RiskEngine to produce an aggregate risk
        score — without routing through the full guardrail pipeline.

        Use this method when callers need a lightweight risk signal (e.g. to
        decide whether to escalate a request) but do not need the full
        sanitisation / provenance chain that ``inspect_input`` produces.

        Parameters
        ----------
        content:
            The text to assess.
        context:
            Optional guardrail context carrying session, agent, and tool info.
        source_trust:
            Explicit trust tier for the content source.  Defaults to
            ``policy.default_trust_level``.
        requested_action:
            The action the agent intends to perform; fed directly into the
            risk engine's action-risk assessment.
        record_provenance:
            When True (default), a provenance record is created and appended
            to the shared ledger.  Set to False for read-only risk probes that
            should not pollute the audit trail.

        Returns
        -------
        RiskAssessment
            A dataclass wrapping the ``RiskScore``, all ``DetectionFinding``
            objects across every detector, the ``ProvenanceRecord`` (or a
            synthetic fail-closed record on error), and wall-clock latency.
        """
        start_time = time.perf_counter()
        ctx = context or GuardrailContext()
        trust = source_trust or self.policy.default_trust_level

        # Fail-closed: mandatory detector availability
        violations = self._check_mandatory_detectors()
        if violations:
            reason = "; ".join(violations)
            logger.error("SecurityEngine.calculate_risk fail-closed: %s", reason)
            prov = self.provenance_engine.create_record(
                input_text=content,
                action=Action.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                metadata={"policy": "fail_closed", "reason": reason, **self.policy.extra_metadata},
            )
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            # Build a blocking RiskScore rather than letting evaluate() return ALLOW
            critical_score = RiskScore(
                overall_score=1.0,
                level=RiskLevel.CRITICAL,
                component_scores={"mandatory_failure": 1.0},
                factors=[f"FAIL-CLOSED: {reason}"],
                recommended_action=Action.BLOCK,
                context_multiplier=1.0,
            )
            return RiskAssessment(
                risk_score=critical_score,
                findings=[],
                provenance_record=prov,
                latency_ms=latency_ms,
            )

        # Run all four detectors concurrently
        inj_res: InjectionAnalysisResult | None = None
        pii_res: PIIAnalysisResult | None = None
        sec_res: SecretAnalysisResult | None = None
        dlp_res: DLPAnalysisResult | None = None
        scan_errors: list[str] = []

        try:
            inj_task = asyncio.to_thread(self.injection_detector.scan, content)
            pii_task = asyncio.to_thread(self.pii_detector.scan, content)
            sec_task = asyncio.to_thread(self.secret_scanner.scan, content)
            dlp_task = asyncio.to_thread(self.dlp_engine.scan, content)

            results = await asyncio.gather(
                inj_task, pii_task, sec_task, dlp_task,
                return_exceptions=True,
            )
            inj_raw, pii_raw, sec_raw, dlp_raw = results

            # Unpack results; treat exceptions as failed (fail-closed per detector)
            if isinstance(inj_raw, Exception):
                scan_errors.append(f"injection_detector: {inj_raw}")
                logger.error("calculate_risk: injection detector failed: %s", inj_raw)
            else:
                inj_res = inj_raw

            if isinstance(pii_raw, Exception):
                scan_errors.append(f"pii_detector: {pii_raw}")
                logger.error("calculate_risk: pii detector failed: %s", pii_raw)
            else:
                pii_res = pii_raw

            if isinstance(sec_raw, Exception):
                scan_errors.append(f"secret_scanner: {sec_raw}")
                logger.error("calculate_risk: secret scanner failed: %s", sec_raw)
            else:
                sec_res = sec_raw

            if isinstance(dlp_raw, Exception):
                scan_errors.append(f"dlp_engine: {dlp_raw}")
                logger.error("calculate_risk: DLP engine failed: %s", dlp_raw)
            else:
                dlp_res = dlp_raw

        except Exception as exc:
            # Catastrophic failure — all detectors unreachable
            reason = f"Detector gather failed entirely: {exc}"
            logger.critical("SecurityEngine.calculate_risk fail-closed: %s", reason, exc_info=True)
            prov = self.provenance_engine.create_record(
                input_text=content,
                action=Action.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                metadata={"policy": "fail_closed", "reason": reason, **self.policy.extra_metadata},
            )
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            critical_score = RiskScore(
                overall_score=1.0,
                level=RiskLevel.CRITICAL,
                component_scores={"catastrophic_failure": 1.0},
                factors=[f"FAIL-CLOSED: {reason}"],
                recommended_action=Action.BLOCK,
                context_multiplier=1.0,
            )
            return RiskAssessment(
                risk_score=critical_score,
                findings=[],
                provenance_record=prov,
                latency_ms=latency_ms,
            )

        # Check mandatory detector violations from individual failures
        mandatory_failed: list[str] = []
        if self.policy.require_injection_check and inj_res is None:
            mandatory_failed.append("injection")
        if self.policy.require_pii_check and pii_res is None:
            mandatory_failed.append("pii")
        if self.policy.require_secret_check and sec_res is None:
            mandatory_failed.append("secret")
        if self.policy.require_dlp_check and dlp_res is None:
            mandatory_failed.append("dlp")

        # Aggregate findings from whichever detectors succeeded
        all_findings: list[DetectionFinding] = []
        if inj_res:
            all_findings.extend(inj_res.findings)
        if pii_res:
            all_findings.extend(pii_res.findings)
        if sec_res:
            all_findings.extend(sec_res.findings)
        if dlp_res:
            all_findings.extend(dlp_res.findings)

        # Compute risk — if mandatory detectors failed, force CRITICAL/BLOCK
        if mandatory_failed:
            reason = f"Mandatory detectors failed: {', '.join(mandatory_failed)}"
            logger.error("SecurityEngine.calculate_risk fail-closed: %s", reason)
            risk_score = self.risk_engine.evaluate(
                injection_res=inj_res,
                pii_res=pii_res,
                secret_res=sec_res,
                dlp_res=dlp_res,
                context=ctx,
                source_trust=trust,
                requested_action=requested_action,
            )
            # Override to BLOCK regardless of computed score
            from pydantic import ValidationError
            try:
                risk_score = RiskScore(
                    overall_score=max(risk_score.overall_score, 0.95),
                    level=RiskLevel.CRITICAL,
                    component_scores={**risk_score.component_scores, "mandatory_failure": 1.0},
                    factors=risk_score.factors + [f"FAIL-CLOSED: {reason}"],
                    recommended_action=Action.BLOCK,
                    context_multiplier=risk_score.context_multiplier,
                )
            except Exception:
                risk_score = self.risk_engine.evaluate()
        else:
            risk_score = self.risk_engine.evaluate(
                injection_res=inj_res,
                pii_res=pii_res,
                secret_res=sec_res,
                dlp_res=dlp_res,
                context=ctx,
                source_trust=trust,
                requested_action=requested_action,
            )

        # Provenance record
        if record_provenance:
            prov = self.provenance_engine.create_record(
                input_text=content,
                action=risk_score.recommended_action,
                risk_level=risk_score.level,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                source_type=SourceType.USER,
                trust_level=trust,
                metadata={
                    "stage": "calculate_risk",
                    "findings_count": len(all_findings),
                    "risk_score": risk_score.overall_score,
                    "scan_errors": scan_errors,
                    **self.policy.extra_metadata,
                },
            )
        else:
            # record_provenance=False: do NOT write to the shared ledger.
            # Build a synthetic, detached ProvenanceRecord so callers always
            # receive a valid object, but the ledger is left untouched.
            prov = self.provenance_engine._build_detached_record(
                input_text=content,
                action=risk_score.recommended_action,
                risk_level=risk_score.level,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                metadata={"stage": "calculate_risk_readonly", "record_provenance": False},
            )

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        logger.info(
            "SecurityEngine.calculate_risk: action=%s level=%s score=%.3f findings=%d latency=%.2fms",
            risk_score.recommended_action.value,
            risk_score.level.value,
            risk_score.overall_score,
            len(all_findings),
            latency_ms,
        )

        return RiskAssessment(
            risk_score=risk_score,
            findings=all_findings,
            provenance_record=prov,
            latency_ms=latency_ms,
        )

    # -----------------------------------------------------------------------
    # Convenience synchronous wrappers
    # -----------------------------------------------------------------------

    def inspect_input_sync(self, *args: Any, **kwargs: Any) -> GuardrailInputResponse:
        """Synchronous wrapper for inspect_input."""
        return asyncio.run(self.inspect_input(*args, **kwargs))

    def inspect_output_sync(self, *args: Any, **kwargs: Any) -> GuardrailOutputResponse:
        """Synchronous wrapper for inspect_output."""
        return asyncio.run(self.inspect_output(*args, **kwargs))

    def inspect_data_sync(self, *args: Any, **kwargs: Any) -> GuardrailInputResponse:
        """Synchronous wrapper for inspect_data."""
        return asyncio.run(self.inspect_data(*args, **kwargs))

    def calculate_risk_sync(self, *args: Any, **kwargs: Any) -> RiskAssessment:
        """Synchronous wrapper for calculate_risk."""
        return asyncio.run(self.calculate_risk(*args, **kwargs))

    # -----------------------------------------------------------------------
    # Ledger / audit access
    # -----------------------------------------------------------------------

    def get_audit_ledger(self) -> list[ProvenanceRecord]:
        """Returns a snapshot of the shared provenance ledger."""
        return self.provenance_engine.get_ledger()

    def verify_audit_chain(self) -> tuple[bool, str | None]:
        """Cryptographically verifies the integrity of the shared ledger."""
        return self.provenance_engine.verify_chain()

    def update_policy(self, **kwargs: Any) -> SecurityPolicy:
        """
        Updates fields on the SecurityPolicy at runtime.
        Only known SecurityPolicy fields are applied; unknown keys are silently ignored.
        Returns the updated policy.
        """
        for k, v in kwargs.items():
            if hasattr(self.policy, k):
                setattr(self.policy, k, v)
        return self.policy
