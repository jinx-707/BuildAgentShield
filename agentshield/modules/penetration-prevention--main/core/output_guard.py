"""
AgentShield Outbound Security Guardrail.
Orchestrates multi-engine verification for model-generated outputs, tool arguments,
and tool execution outputs before delivery to users, external tools, or downstream agents.
Prevents sensitive credential exfiltration, DLP violations, PII leakage, and indirect
payload reflection with decisive ALLOW, WARN, MASK, BLOCK, and QUARANTINE policies.
"""

from __future__ import annotations

import asyncio
import json
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
    GuardrailOutputRequest,
    GuardrailOutputResponse,
    GuardrailViolationError,
    InjectionDetectedError,
    PIIViolationError,
    RiskLevel,
    SecretLeakError,
    SourceType,
    TrustLevel,
)
from core.secret_scanner import SecretScanner

logger = setup_logger("agentshield.output_guard")


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


class OutputGuard:
    """
    Unified Outbound Security Guardrail for AI Agent Runtimes.
    Prevents exfiltration of credentials, confidential records, and user PII.
    Inspects agent responses, tool arguments, and tool outputs with decisive
    ALLOW, WARN, MASK, BLOCK, and QUARANTINE decisions.
    """

    def __init__(
        self,
        config: AgentShieldConfig | None = None,
        secret_scanner: SecretScanner | None = None,
        pii_detector: PIIDetector | None = None,
        dlp_engine: DLPEngine | None = None,
        risk_engine: RiskEngine | None = None,
        provenance_engine: ProvenanceEngine | None = None,
        injection_detector: PromptInjectionDetector | None = None,
    ) -> None:
        self.config = config or AgentShieldConfig()
        self.secret_scanner = secret_scanner or SecretScanner(self.config)
        self.pii_detector = pii_detector or PIIDetector(self.config)
        self.dlp_engine = dlp_engine or DLPEngine(self.config)
        self.risk_engine = risk_engine or RiskEngine(self.config)
        self.provenance_engine = provenance_engine or ProvenanceEngine(self.config)
        self.injection_detector = injection_detector or PromptInjectionDetector(self.config)

    def _prepare_request(
        self,
        request: GuardrailOutputRequest | str,
        context: GuardrailContext | None = None,
        source_input_hash: str | None = None,
    ) -> GuardrailOutputRequest:
        """Normalizes raw string or request model into GuardrailOutputRequest."""
        if isinstance(request, str):
            return GuardrailOutputRequest(
                raw_output=request,
                context=context or GuardrailContext(),
                source_input_hash=source_input_hash,
            )
        if context is not None:
            request.context = context
        if source_input_hash is not None:
            request.source_input_hash = source_input_hash
        return request

    def _merge_sanitized_text(
        self,
        original_output: str,
        pii_sanitized: str,
        secret_sanitized: str,
        dlp_sanitized: str,
    ) -> str:
        """Applies sanitizations in layered sequence."""
        current = original_output
        if pii_sanitized != original_output:
            current = pii_sanitized
        if secret_sanitized != original_output:
            res = self.secret_scanner.scan(current)
            current = res.sanitized_text
        if dlp_sanitized != original_output:
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

            if top_finding.detector == DetectorType.SECRET:
                raise SecretLeakError(message, action=action, risk_score=risk_score, findings=findings)
            if top_finding.detector == DetectorType.DLP:
                raise DLPViolationError(message, action=action, risk_score=risk_score, findings=findings)
            if top_finding.detector == DetectorType.PII:
                raise PIIViolationError(message, action=action, risk_score=risk_score, findings=findings)
            if top_finding.detector == DetectorType.INJECTION:
                raise InjectionDetectedError(message, action=action, risk_score=risk_score, findings=findings)

        raise GuardrailViolationError(message, action=action, risk_score=risk_score, findings=findings)

    async def validate_async(
        self,
        request: GuardrailOutputRequest | str,
        context: GuardrailContext | None = None,
        source_input_hash: str | None = None,
        source_type: SourceType | str = SourceType.AGENT,
        trust_level: TrustLevel | str | None = None,
        requested_action: Action | str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailOutputResponse:
        """
        Asynchronously validates and sanitizes outgoing model output or tool response.
        """
        start_time = time.perf_counter()
        req = self._prepare_request(request, context, source_input_hash)
        raw_output = req.raw_output
        ctx = req.context

        logger.info(
            "OutputGuard evaluating response for agent '%s' (session: %s, len: %d)",
            ctx.agent_id,
            ctx.session_id[:8],
            len(raw_output),
        )

        # Execute outbound detectors concurrently
        try:
            sec_task = asyncio.to_thread(self.secret_scanner.scan, raw_output)
            pii_task = asyncio.to_thread(self.pii_detector.scan, raw_output)
            dlp_task = asyncio.to_thread(self.dlp_engine.scan, raw_output)

            sec_res, pii_res, dlp_res = await asyncio.gather(sec_task, pii_task, dlp_task)
        except Exception as exc:
            logger.critical("Security detector failure in OutputGuard: %s. Enforcing fail-closed BLOCK.", exc)
            prov_record = self.provenance_engine.create_record(
                input_text=req.source_input_hash or "outbound-eval",
                action=Action.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                output_text=raw_output,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                source_type=source_type,
                trust_level=trust_level if isinstance(trust_level, TrustLevel) else None,
                metadata={"error": str(exc), "stage": "output", "policy": "fail_closed"},
            )
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            if raise_on_block:
                raise GuardrailViolationError(
                    f"Output guardrail detector failed unexpectedly; fail-closed policy enforced: {exc}",
                    action=Action.BLOCK,
                    risk_score=1.0,
                ) from exc
            return GuardrailOutputResponse(
                allowed=False,
                action=Action.BLOCK,
                sanitized_output="[RESPONSE_BLOCKED_BY_GUARDRAIL: Security detector failure]",
                risk_assessment=self.risk_engine.evaluate(),
                findings=[],
                provenance_record=prov_record,
                latency_ms=round(latency_ms, 2),
            )

        # Aggregate findings
        all_findings: list[DetectionFinding] = []
        all_findings.extend(sec_res.findings)
        all_findings.extend(pii_res.findings)
        all_findings.extend(dlp_res.findings)

        # Context-aware risk evaluation
        risk_score = self.risk_engine.evaluate(
            injection_res=None,  # Injection check is inbound primary, handled explicitly in tool outputs
            pii_res=pii_res,
            secret_res=sec_res,
            dlp_res=dlp_res,
            context=ctx,
            source_trust=trust_level,
            requested_action=requested_action,
        )

        action = risk_score.recommended_action
        allowed = action not in (Action.BLOCK, Action.QUARANTINE)

        # Determine sanitized output text
        if action == Action.QUARANTINE:
            sanitized_output = "[RESPONSE_QUARANTINED_BY_GUARDRAIL: Isolated for security containment]"
        elif action == Action.BLOCK:
            sanitized_output = "[RESPONSE_BLOCKED_BY_GUARDRAIL: Security policy violation detected]"
        elif action in (Action.MASK, Action.WARN, Action.ALLOW):
            sanitized_output = self._merge_sanitized_text(
                raw_output,
                pii_res.sanitized_text,
                sec_res.sanitized_text,
                dlp_res.sanitized_text,
            )
        else:
            sanitized_output = raw_output

        # Create cryptographic provenance record linked with parent input hash
        prov_record = self.provenance_engine.create_record(
            input_text=req.source_input_hash or "outbound-eval",
            action=action,
            risk_level=risk_score.level,
            output_text=raw_output,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            source_type=source_type,
            trust_level=trust_level if isinstance(trust_level, TrustLevel) else None,
            metadata={
                "stage": "output",
                "findings_count": len(all_findings),
                "risk_score": risk_score.overall_score,
                "normalized_score_100": getattr(risk_score, "score_100", round(risk_score.overall_score * 100.0, 2)),
                "source_input_hash": req.source_input_hash,
            },
        )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        logger.info(
            "OutputGuard decision: action=%s risk_level=%s latency=%.2fms",
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
                message=f"Agent response blocked by AgentShield guardrail: {'; '.join(risk_score.factors)}",
            )

        return GuardrailOutputResponse(
            allowed=allowed,
            action=action,
            sanitized_output=sanitized_output,
            risk_assessment=risk_score,
            findings=all_findings,
            provenance_record=prov_record,
            latency_ms=round(latency_ms, 2),
        )

    def validate(
        self,
        request: GuardrailOutputRequest | str,
        context: GuardrailContext | None = None,
        source_input_hash: str | None = None,
        source_type: SourceType | str = SourceType.AGENT,
        trust_level: TrustLevel | str | None = None,
        requested_action: Action | str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailOutputResponse:
        """Synchronous wrapper for validate_async."""
        return _run_coroutine_sync(
            self.validate_async(
                request,
                context=context,
                source_input_hash=source_input_hash,
                source_type=source_type,
                trust_level=trust_level,
                requested_action=requested_action,
                raise_on_block=raise_on_block,
            )
        )

    async def validate_agent_response_async(
        self,
        response_text: str,
        context: GuardrailContext | None = None,
        source_input_hash: str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailOutputResponse:
        """Convenience method to validate an outbound agent response."""
        return await self.validate_async(
            request=response_text,
            context=context,
            source_input_hash=source_input_hash,
            source_type=SourceType.AGENT,
            raise_on_block=raise_on_block,
        )

    def validate_agent_response(
        self,
        response_text: str,
        context: GuardrailContext | None = None,
        source_input_hash: str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailOutputResponse:
        """Synchronous wrapper for validate_agent_response_async."""
        return _run_coroutine_sync(
            self.validate_agent_response_async(
                response_text,
                context=context,
                source_input_hash=source_input_hash,
                raise_on_block=raise_on_block,
            )
        )

    async def validate_tool_call_async(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | str,
        context: GuardrailContext | None = None,
        source_input_hash: str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailOutputResponse:
        """
        Inspects arguments to be dispatched to an external tool.
        Detects credential leakage, PII, DLP violations, or injection payloads in tool arguments.
        """
        start_time = time.perf_counter()
        # BUG-3 fix: work on a copy of the caller's GuardrailContext so that
        # appending to tools_enabled and writing metadata keys do not mutate
        # the object the caller passed in.
        if context is not None:
            ctx = GuardrailContext(
                session_id=context.session_id,
                agent_id=context.agent_id,
                user_id=context.user_id,
                tools_enabled=list(context.tools_enabled),
                is_privileged_agent=context.is_privileged_agent,
                metadata=dict(context.metadata),
            )
        else:
            ctx = GuardrailContext()
        if tool_name not in ctx.tools_enabled:
            ctx.tools_enabled.append(tool_name)
        ctx.metadata["tool_name"] = tool_name
        ctx.metadata["stage"] = "tool_call"

        args_str = json.dumps(tool_args, sort_keys=True) if isinstance(tool_args, dict) else str(tool_args)

        logger.info(
            "OutputGuard inspecting tool arguments for tool '%s' (len: %d)",
            tool_name,
            len(args_str),
        )

        try:
            sec_task = asyncio.to_thread(self.secret_scanner.scan, args_str)
            pii_task = asyncio.to_thread(self.pii_detector.scan, args_str)
            dlp_task = asyncio.to_thread(self.dlp_engine.scan, args_str)
            inj_task = asyncio.to_thread(self.injection_detector.scan, args_str)

            sec_res, pii_res, dlp_res, inj_res = await asyncio.gather(
                sec_task, pii_task, dlp_task, inj_task
            )
        except Exception as exc:
            logger.critical("Detector failure during tool argument inspection for '%s': %s", tool_name, exc)
            if raise_on_block:
                raise GuardrailViolationError(
                    f"Tool argument guardrail inspection failed: {exc}",
                    action=Action.BLOCK,
                    risk_score=1.0,
                ) from exc
            prov_record = self.provenance_engine.create_record(
                input_text=source_input_hash or f"tool-call:{tool_name}",
                action=Action.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                output_text=args_str,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                source_type=SourceType.TOOL_OUTPUT,
                metadata={"error": str(exc), "stage": "tool_call", "tool_name": tool_name},
            )
            return GuardrailOutputResponse(
                allowed=False,
                action=Action.BLOCK,
                sanitized_output="[TOOL_CALL_BLOCKED_BY_GUARDRAIL: Detector failure]",
                risk_assessment=self.risk_engine.evaluate(),
                findings=[],
                provenance_record=prov_record,
                latency_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
            )

        all_findings: list[DetectionFinding] = []
        all_findings.extend(sec_res.findings)
        all_findings.extend(pii_res.findings)
        all_findings.extend(dlp_res.findings)
        all_findings.extend(inj_res.findings)

        risk_score = self.risk_engine.evaluate(
            injection_res=inj_res,
            pii_res=pii_res,
            secret_res=sec_res,
            dlp_res=dlp_res,
            context=ctx,
            requested_action=tool_name,
        )

        action = risk_score.recommended_action
        allowed = action not in (Action.BLOCK, Action.QUARANTINE)

        if action == Action.QUARANTINE:
            sanitized_args = "[TOOL_CALL_QUARANTINED_BY_GUARDRAIL]"
        elif action == Action.BLOCK:
            sanitized_args = "[TOOL_CALL_BLOCKED_BY_GUARDRAIL: Security violation]"
        elif action in (Action.MASK, Action.WARN, Action.ALLOW):
            sanitized_args = self._merge_sanitized_text(
                args_str,
                pii_res.sanitized_text,
                sec_res.sanitized_text,
                dlp_res.sanitized_text,
            )
        else:
            sanitized_args = args_str

        prov_record = self.provenance_engine.create_record(
            input_text=source_input_hash or f"tool-call:{tool_name}",
            action=action,
            risk_level=risk_score.level,
            output_text=args_str,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            source_type=SourceType.TOOL_OUTPUT,
            metadata={
                "stage": "tool_call",
                "tool_name": tool_name,
                "findings_count": len(all_findings),
                "risk_score": risk_score.overall_score,
            },
        )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        if not allowed and raise_on_block:
            self._raise_appropriate_violation(
                action=action,
                risk_score=risk_score.overall_score,
                findings=all_findings,
                message=f"Tool call '{tool_name}' blocked by guardrail: {'; '.join(risk_score.factors)}",
            )

        return GuardrailOutputResponse(
            allowed=allowed,
            action=action,
            sanitized_output=sanitized_args,
            risk_assessment=risk_score,
            findings=all_findings,
            provenance_record=prov_record,
            latency_ms=round(latency_ms, 2),
        )

    def validate_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | str,
        context: GuardrailContext | None = None,
        source_input_hash: str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailOutputResponse:
        """Synchronous wrapper for validate_tool_call_async."""
        return _run_coroutine_sync(
            self.validate_tool_call_async(
                tool_name=tool_name,
                tool_args=tool_args,
                context=context,
                source_input_hash=source_input_hash,
                raise_on_block=raise_on_block,
            )
        )

    async def validate_tool_output_async(
        self,
        tool_name: str,
        tool_output: str | dict[str, Any],
        context: GuardrailContext | None = None,
        source_uri: str | None = None,
        parent_id: str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailOutputResponse:
        """
        Inspects output returned from an external tool execution before forwarding to LLM or user.
        Detects credential exfiltration, PII leakage, DLP violations, and indirect prompt injection.
        """
        start_time = time.perf_counter()
        ctx = context or GuardrailContext()
        ctx.metadata["tool_name"] = tool_name
        ctx.metadata["stage"] = "tool_output"

        output_str = json.dumps(tool_output, sort_keys=True) if isinstance(tool_output, dict) else str(tool_output)

        logger.info(
            "OutputGuard inspecting output from tool '%s' (len: %d)",
            tool_name,
            len(output_str),
        )

        try:
            sec_task = asyncio.to_thread(self.secret_scanner.scan, output_str)
            pii_task = asyncio.to_thread(self.pii_detector.scan, output_str)
            dlp_task = asyncio.to_thread(self.dlp_engine.scan, output_str)
            inj_task = asyncio.to_thread(self.injection_detector.scan, output_str)

            sec_res, pii_res, dlp_res, inj_res = await asyncio.gather(
                sec_task, pii_task, dlp_task, inj_task
            )
        except Exception as exc:
            logger.critical("Detector failure during tool output inspection for '%s': %s", tool_name, exc)
            if raise_on_block:
                raise GuardrailViolationError(
                    f"Tool output guardrail inspection failed: {exc}",
                    action=Action.BLOCK,
                    risk_score=1.0,
                ) from exc
            prov_record = self.provenance_engine.create_record(
                input_text=f"tool-output:{tool_name}",
                action=Action.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                output_text=output_str,
                session_id=ctx.session_id,
                agent_id=ctx.agent_id,
                source_type=SourceType.TOOL_OUTPUT,
                trust_level=TrustLevel.LOW,
                source_uri=source_uri,
                parent_id=parent_id,
                metadata={"error": str(exc), "stage": "tool_output", "tool_name": tool_name},
            )
            return GuardrailOutputResponse(
                allowed=False,
                action=Action.BLOCK,
                sanitized_output="[TOOL_OUTPUT_BLOCKED_BY_GUARDRAIL: Detector failure]",
                risk_assessment=self.risk_engine.evaluate(),
                findings=[],
                provenance_record=prov_record,
                latency_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
            )

        all_findings: list[DetectionFinding] = []
        all_findings.extend(sec_res.findings)
        all_findings.extend(pii_res.findings)
        all_findings.extend(dlp_res.findings)
        all_findings.extend(inj_res.findings)

        # Evaluate risk with source trust set to LOW for tool outputs
        risk_score = self.risk_engine.evaluate(
            injection_res=inj_res,
            pii_res=pii_res,
            secret_res=sec_res,
            dlp_res=dlp_res,
            context=ctx,
            source_trust=TrustLevel.LOW,
            requested_action=tool_name,
        )

        action = risk_score.recommended_action
        allowed = action not in (Action.BLOCK, Action.QUARANTINE)

        if action == Action.QUARANTINE:
            sanitized_output = "[TOOL_OUTPUT_QUARANTINED_BY_GUARDRAIL: Isolated for security containment]"
        elif action == Action.BLOCK:
            sanitized_output = "[TOOL_OUTPUT_BLOCKED_BY_GUARDRAIL: Security violation detected]"
        elif action in (Action.MASK, Action.WARN, Action.ALLOW):
            sanitized_output = self._merge_sanitized_text(
                output_str,
                pii_res.sanitized_text,
                sec_res.sanitized_text,
                dlp_res.sanitized_text,
            )
        else:
            sanitized_output = output_str

        prov_record = self.provenance_engine.create_record(
            input_text=f"tool-output:{tool_name}",
            action=action,
            risk_level=risk_score.level,
            output_text=output_str,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            source_type=SourceType.TOOL_OUTPUT,
            trust_level=TrustLevel.LOW,
            source_uri=source_uri,
            parent_id=parent_id,
            metadata={
                "stage": "tool_output",
                "tool_name": tool_name,
                "findings_count": len(all_findings),
                "risk_score": risk_score.overall_score,
            },
        )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        if not allowed and raise_on_block:
            self._raise_appropriate_violation(
                action=action,
                risk_score=risk_score.overall_score,
                findings=all_findings,
                message=f"Tool output from '{tool_name}' blocked by guardrail: {'; '.join(risk_score.factors)}",
            )

        return GuardrailOutputResponse(
            allowed=allowed,
            action=action,
            sanitized_output=sanitized_output,
            risk_assessment=risk_score,
            findings=all_findings,
            provenance_record=prov_record,
            latency_ms=round(latency_ms, 2),
        )

    def validate_tool_output(
        self,
        tool_name: str,
        tool_output: str | dict[str, Any],
        context: GuardrailContext | None = None,
        source_uri: str | None = None,
        parent_id: str | None = None,
        raise_on_block: bool = True,
    ) -> GuardrailOutputResponse:
        """Synchronous wrapper for validate_tool_output_async."""
        return _run_coroutine_sync(
            self.validate_tool_output_async(
                tool_name=tool_name,
                tool_output=tool_output,
                context=context,
                source_uri=source_uri,
                parent_id=parent_id,
                raise_on_block=raise_on_block,
            )
        )
