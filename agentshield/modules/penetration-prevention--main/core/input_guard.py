"""
AgentShield Inbound Security Guardrail.
Orchestrates multi-engine verification for prompt inputs and external content entering AI agents.
Enforces injection defenses, credential sanitization, PII masking, DLP policy, source trust,
and cryptographic provenance tracking with ALLOW, WARN, MASK, BLOCK, and QUARANTINE decisions.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from core.config import AgentShieldConfig, setup_logger
from core.dlp_engine import DLPEngine
from core.injection_detector import PromptInjectionDetector
from core.pii_detector import PIIDetector
from core.provenance import ProvenanceEngine
from core.risk_engine import RiskEngine
from core.schemas import (
    Action,
    DetectionFinding,
    DLPViolationError,
    GuardrailContext,
    GuardrailInputRequest,
    GuardrailInputResponse,
    GuardrailViolationError,
    InjectionDetectedError,
    PIIViolationError,
    RiskLevel,
    SecretLeakError,
    SourceType,
    TrustLevel,
)
from core.secret_scanner import SecretScanner

logger = setup_logger("agentshield.input_guard")


def _normalize_trust_level(value: TrustLevel | str | None) -> TrustLevel | None:
    """
    BUG-2 fix: converts a string trust level (e.g. ``"untrusted"``) to the
    corresponding ``TrustLevel`` enum, returning ``None`` for unrecognised
    strings so callers can fall back gracefully.

    ``TrustLevel`` enum values are already passed through unchanged.
    ``None`` is returned as-is so that the provenance engine applies the
    source-type-based default rather than silently upgrading to MEDIUM.
    """
    if value is None or isinstance(value, TrustLevel):
        return value
    normalized = str(value).strip().lower()
    for tl in TrustLevel:
        if tl.value == normalized:
            return tl
    # Unrecognised string — return None so the caller uses the source-type default
    return None


def _run_coroutine_sync(coro: Any) -> Any:
    """Safely executes an async coroutine synchronously, even if an event loop is already active."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(coro)).result()
    return asyncio.run(coro)


class InputGuard:
    """
    Unified Inbound Security Guardrail for AI Agent Runtimes.
    Executes modular checks across injection detection, credential scanning,
    PII de-identification, DLP policies, and origin source trust.
    Supports ALLOW, WARN, MASK, BLOCK, and QUARANTINE decisions.
    """

    def __init__(
        self,
        config: AgentShieldConfig | None = None,
        injection_detector: PromptInjectionDetector | None = None,
        pii_detector: PIIDetector | None = None,
        secret_scanner: SecretScanner | None = None,
        dlp_engine: DLPEngine | None = None,
        risk_engine: RiskEngine | None = None,
        provenance_engine: ProvenanceEngine | None = None,
    ) -> None:
        self.config = config or AgentShieldConfig()
        self.injection_detector = injection_detector or PromptInjectionDetector(self.config)
        self.pii_detector = pii_detector or PIIDetector(self.config)
        self.secret_scanner = secret_scanner or SecretScanner(self.config)
        self.dlp_engine = dlp_engine or DLPEngine(self.config)
        self.risk_engine = risk_engine or RiskEngine(self.config)
        self.provenance_engine = provenance_engine or ProvenanceEngine(self.config)

    def _prepare_request(
        self, request: GuardrailInputRequest | str, context: GuardrailContext | None = None
    ) -> GuardrailInputRequest:
        """Normalizes raw string or request model into GuardrailInputRequest."""
        if isinstance(request, str):
            return GuardrailInputRequest(
                prompt=request,
                context=context or GuardrailContext(),
            )
        if context is not None:
            request.context = context
        return request

    def _merge_sanitized_text(
        self,
        original_prompt: str,
        pii_sanitized: str,
        secret_sanitized: str,
        dlp_sanitized: str,
    ) -> str:
        """
        Combines sanitized outputs from detectors so that all redacted fields
        are reflected cleanly in the resulting outbound prompt.
        """
        current = original_prompt
        if pii_sanitized != original_prompt:
            current = pii_sanitized
        # Apply secret sanitization
        if secret_sanitized != original_prompt:
            res = self.secret_scanner.scan(current)
            current = res.sanitized_text
        # Apply DLP sanitization
        if dlp_sanitized != original_prompt:
            res = self.dlp_engine.scan(current)
            current = res.sanitized_text
        return current

    def _raise_appropriate_violation(
        self,
        action: Action,
        risk_score: float,
        findings: list[DetectionFinding],
        message: str,
    ) -> None:
        """Raises specific subclasses of GuardrailViolationError based on root threat."""
        top_finding = max(findings, key=lambda f: f.risk_score, default=None)
        if top_finding:
            from core.schemas import DetectorType

            if top_finding.detector == DetectorType.INJECTION:
                raise InjectionDetectedError(message, action=action, risk_score=risk_score, findings=findings)
            if top_finding.detector == DetectorType.SECRET:
                raise SecretLeakError(message, action=action, risk_score=risk_score, findings=findings)
            if top_finding.detector == DetectorType.DLP:
                raise DLPViolationError(message, action=action, risk_score=risk_score, findings=findings)
            if top_finding.detector == DetectorType.PII:
                raise PIIViolationError(message, action=action, risk_score=risk_score, findings=findings)

        raise GuardrailViolationError(message, action=action, risk_score=risk_score, findings=findings)

    async def validate_async(
        self,
        request: GuardrailInputRequest | str,
        context: GuardrailContext | None = None,
        source_type: SourceType | str | None = None,
        trust_level: TrustLevel | str | None = None,
        source_uri: str | None = None,
        parent_id: str | None = None,
        requested_action: Action | str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailInputResponse:
        """
        Asynchronously validates and sanitizes incoming prompt or external content through the security gateway.
        Executes sub-engine scans concurrently, applies source trust and agent context,
        and returns decisive ALLOW, WARN, MASK, BLOCK, or QUARANTINE decisions.
        """
        start_time = time.perf_counter()
        req = self._prepare_request(request, context)
        raw_prompt = req.prompt
        ctx = req.context

        # Resolve source origin and trust metadata
        effective_source: SourceType | str = (
            source_type
            or ctx.metadata.get("source_type")
            or SourceType.USER
        )
        effective_trust: TrustLevel | str | None = (
            trust_level
            or ctx.metadata.get("source_trust")
            or ctx.metadata.get("trust_level")
        )
        # BUG-2 fix: normalize string trust values to TrustLevel enum so that
        # provenance records always carry the intended trust tier.
        effective_trust_enum: TrustLevel | None = _normalize_trust_level(effective_trust)
        effective_action: Action | str | None = (
            requested_action
            or ctx.metadata.get("requested_action")
        )

        logger.info(
            "InputGuard evaluating prompt for agent '%s' (session: %s, len: %d, source: %s)",
            ctx.agent_id,
            ctx.session_id[:8],
            len(raw_prompt),
            effective_source,
        )

        # Execute security sub-engines concurrently
        try:
            inj_task = asyncio.to_thread(self.injection_detector.scan, raw_prompt)
            pii_task = asyncio.to_thread(self.pii_detector.scan, raw_prompt)
            sec_task = asyncio.to_thread(self.secret_scanner.scan, raw_prompt)
            dlp_task = asyncio.to_thread(self.dlp_engine.scan, raw_prompt)

            inj_res, pii_res, sec_res, dlp_res = await asyncio.gather(
                inj_task, pii_task, sec_task, dlp_task
            )
        except Exception as exc:
            logger.critical("Security detector failure in InputGuard: %s. Enforcing fail-closed BLOCK.", exc)
            prov_record = self.provenance_engine.create_record(
                input_text=raw_prompt,
                action=Action.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                output_text=None,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                source_type=effective_source,
                trust_level=effective_trust_enum,
                source_uri=source_uri or ctx.metadata.get("source_uri"),
                parent_id=parent_id or ctx.metadata.get("parent_id"),
                metadata={"error": str(exc), "stage": "input", "policy": "fail_closed"},
            )
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            if raise_on_block:
                raise GuardrailViolationError(
                    f"Input guardrail detector failed unexpectedly; fail-closed policy enforced: {exc}",
                    action=Action.BLOCK,
                    risk_score=1.0,
                ) from exc
            return GuardrailInputResponse(
                allowed=False,
                action=Action.BLOCK,
                sanitized_prompt="[INPUT_BLOCKED_BY_GUARDRAIL: Security detector failure]",
                risk_assessment=self.risk_engine.evaluate(),
                findings=[],
                provenance_record=prov_record,
                latency_ms=round(latency_ms, 2),
            )

        # Aggregate findings across all detector vectors
        all_findings: list[DetectionFinding] = []
        all_findings.extend(inj_res.findings)
        all_findings.extend(sec_res.findings)
        all_findings.extend(pii_res.findings)
        all_findings.extend(dlp_res.findings)

        # Context-aware and source-trust-aware risk evaluation
        risk_score = self.risk_engine.evaluate(
            injection_res=inj_res,
            pii_res=pii_res,
            secret_res=sec_res,
            dlp_res=dlp_res,
            context=ctx,
            source_trust=effective_trust,
            requested_action=effective_action,
        )

        action = risk_score.recommended_action
        allowed = action not in (Action.BLOCK, Action.QUARANTINE)

        # Determine sanitized output text based on decisive action
        if action == Action.QUARANTINE:
            sanitized_prompt = "[INPUT_QUARANTINED_BY_GUARDRAIL: Isolated for security containment]"
        elif action == Action.BLOCK:
            sanitized_prompt = "[INPUT_BLOCKED_BY_GUARDRAIL]"
        elif action in (Action.MASK, Action.WARN, Action.ALLOW):
            sanitized_prompt = self._merge_sanitized_text(
                raw_prompt,
                pii_res.sanitized_text,
                sec_res.sanitized_text,
                dlp_res.sanitized_text,
            )
        else:
            sanitized_prompt = raw_prompt

        # Create cryptographic provenance record
        prov_record = self.provenance_engine.create_record(
            input_text=raw_prompt,
            action=action,
            risk_level=risk_score.level,
            output_text=None,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            source_type=effective_source,
            trust_level=effective_trust_enum,
            source_uri=source_uri or ctx.metadata.get("source_uri"),
            parent_id=parent_id or ctx.metadata.get("parent_id"),
            metadata={
                "stage": "input",
                "findings_count": len(all_findings),
                "risk_score": risk_score.overall_score,
                "normalized_score_100": getattr(risk_score, "score_100", round(risk_score.overall_score * 100.0, 2)),
            },
        )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        logger.info(
            "InputGuard decision: action=%s risk_level=%s latency=%.2fms",
            action.value,
            risk_score.level.value,
            latency_ms,
        )

        # Handle hard block or quarantine enforcement
        if not allowed and raise_on_block:
            self._raise_appropriate_violation(
                action=action,
                risk_score=risk_score.overall_score,
                findings=all_findings,
                message=f"Input prompt blocked by AgentShield guardrail: {'; '.join(risk_score.factors)}",
            )

        return GuardrailInputResponse(
            allowed=allowed,
            action=action,
            sanitized_prompt=sanitized_prompt,
            risk_assessment=risk_score,
            findings=all_findings,
            provenance_record=prov_record,
            latency_ms=round(latency_ms, 2),
        )

    def validate(
        self,
        request: GuardrailInputRequest | str,
        context: GuardrailContext | None = None,
        source_type: SourceType | str | None = None,
        trust_level: TrustLevel | str | None = None,
        source_uri: str | None = None,
        parent_id: str | None = None,
        requested_action: Action | str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailInputResponse:
        """Synchronous wrapper for validate_async."""
        return _run_coroutine_sync(
            self.validate_async(
                request,
                context=context,
                source_type=source_type,
                trust_level=trust_level,
                source_uri=source_uri,
                parent_id=parent_id,
                requested_action=requested_action,
                raise_on_block=raise_on_block,
            )
        )

    async def validate_external_content_async(
        self,
        content: str,
        source_type: SourceType | str = SourceType.WEBSITE,
        trust_level: TrustLevel | str = TrustLevel.UNTRUSTED,
        source_uri: str | None = None,
        context: GuardrailContext | None = None,
        raise_on_block: bool = False,
    ) -> GuardrailInputResponse:
        """
        Asynchronously inspects external content (documents, web scrapes, tool outputs)
        with explicit origin source type and trust tier.
        """
        return await self.validate_async(
            request=content,
            context=context,
            source_type=source_type,
            trust_level=trust_level,
            source_uri=source_uri,
            raise_on_block=raise_on_block,
        )

    def validate_external_content(
        self,
        content: str,
        source_type: SourceType | str = SourceType.WEBSITE,
        trust_level: TrustLevel | str = TrustLevel.UNTRUSTED,
        source_uri: str | None = None,
        context: GuardrailContext | None = None,
        raise_on_block: bool = False,
    ) -> GuardrailInputResponse:
        """Synchronous wrapper for validate_external_content_async."""
        return _run_coroutine_sync(
            self.validate_external_content_async(
                content,
                source_type=source_type,
                trust_level=trust_level,
                source_uri=source_uri,
                context=context,
                raise_on_block=raise_on_block,
            )
        )
