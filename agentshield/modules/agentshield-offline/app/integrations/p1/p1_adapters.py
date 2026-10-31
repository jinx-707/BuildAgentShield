"""
AgentShield — P1 ContentInspectionPort and DataInspectionPort adapters.

These two classes are drop-in replacements for:
  - LocalDevelopmentContentInspector  →  P1ContentInspectionAdapter
  - LocalDevelopmentDataInspector     →  P1DataInspectionAdapter

They satisfy the exact same Protocol interfaces (app/integrations/ports.py)
and are wired into the DI container in app/api/dependencies.py when
AGENTSHIELD_P1_ENABLED=true.

Mapping
-------
ContentInspectionPort.inspect(content, source_metadata=...)
    → P1 InputGuard.validate_async(content, source_type=FILE/TOOL_OUTPUT,
                                    trust_level=UNTRUSTED, raise_on_block=False)
    → maps GuardrailInputResponse → ContentInspectionResult

DataInspectionPort.inspect(content, context=...)
    → P1 OutputGuard.validate_async(content, raise_on_block=False)
    → maps GuardrailOutputResponse → DataInspectionResult

Security invariants preserved
------------------------------
  1. Content is NEVER sent to P1 before secret redaction for output paths.
     (TerminalOutputInspector calls DataInspectionPort, which runs AFTER the
     local secret redaction pass — that ordering is enforced by the pipeline.)
  2. P1 ALLOW never grants an AgentShield filesystem or command permission.
  3. Documents are always tagged UNTRUSTED regardless of P1 result.
  4. Fail-closed behaviour matches existing convention: raise on failure
     when fail_closed=True; return explicit not-inspected result when False.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import structlog

from app.core.contracts import InspectionStatus, RiskLevel, SecurityFinding
from app.core.exceptions import InspectorUnavailableError
from app.integrations.p1.exceptions import (
    P1ConfigError,
    P1InspectionError,
    P1NotAvailableError,
)
from app.integrations.p1.p1_loader import load_p1_classes
from app.integrations.ports import ContentInspectionResult, DataInspectionResult

log = structlog.get_logger(__name__)

# ─── Minimal fallback GuardrailContext for mock/test environments ─────────────

class _MinimalGuardrailContext:
    """Stand-in when P1 is not importable (used by mock-based unit tests)."""
    def __init__(self, agent_id: str = "p2_offline_agent", metadata: dict = None):
        self.agent_id = agent_id
        self.session_id = "mock-session"
        self.metadata = metadata or {}

# ─── Sentinel note for not-inspected results ─────────────────────────────────
_NOT_INSPECTED = (
    "P1 inspection skipped (unavailable / error). "
    "Content was NOT inspected by Person 1's security engine."
)


# ─── Risk mapping ─────────────────────────────────────────────────────────────

def _p1_risk_to_score(p1_risk_level: str) -> float:
    """Map P1 RiskLevel string value to a 0–1 float."""
    return {
        "safe": 0.0,
        "low": 0.2,
        "medium": 0.5,
        "high": 0.8,
        "critical": 1.0,
    }.get(str(p1_risk_level).lower(), 0.5)


def _p1_action_to_passed(p1_action: str) -> bool:
    """Map P1 Action string to a passed boolean.
    ALLOW, WARN, MASK = content is allowed through (possibly modified).
    BLOCK, QUARANTINE = content is blocked.
    """
    return str(p1_action).lower() in ("allow", "warn", "mask")


def _p1_findings_to_dicts(p1_findings: list) -> list[dict[str, Any]]:
    """Convert P1 DetectionFinding objects to our finding dict format."""
    result = []
    for f in p1_findings:
        detector = getattr(f, "detector", "unknown")
        detector_name = getattr(detector, "value", detector)
        result.append({
            "category": f"p1_{detector_name}",
            "pattern": getattr(f, "rule_id", ""),
            "match": getattr(f, "match_preview", "") or "",
            "description": getattr(f, "description", ""),
            "risk_score": getattr(f, "risk_score", 0.5),
            "note": "P1 SecurityEngine finding",
        })
    return result


# ─── Content Inspection Adapter ───────────────────────────────────────────────

class P1ContentInspectionAdapter:
    """
    ContentInspectionPort backed by P1's InputGuard / SecurityEngine.

    Used for:
      - Document text inspection (injection, PII, DLP)
      - Terminal stdout injection check

    P1's full pipeline runs: injection detection, PII masking,
    secret scanning, DLP policy, risk scoring, provenance recording.
    """

    def __init__(
        self,
        *,
        fail_closed: bool = True,
        p1_config=None,
    ) -> None:
        self._fail_closed = fail_closed
        self._p1_config = p1_config
        self._input_guard = None
        self._initialized = False
        self._init_error: Optional[str] = None

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            classes = load_p1_classes()
            Config = classes["AgentShieldConfig"]
            InputGuard = classes["InputGuard"]
            cfg = self._p1_config or Config()
            self._input_guard = InputGuard(config=cfg)
            self._initialized = True
            log.info("p1_content_inspector_ready")
        except P1NotAvailableError:
            raise
        except Exception as exc:
            self._init_error = str(exc)
            raise P1ConfigError(f"P1 InputGuard init failed: {exc}") from exc

    async def inspect(
        self,
        content: str,
        *,
        source_metadata: Optional[dict[str, Any]] = None,
    ) -> ContentInspectionResult:
        try:
            self._ensure_initialized()
        except (P1NotAvailableError, P1ConfigError) as exc:
            return await self._handle_failure(exc, content, source_metadata)

        # Use cached classes if available (avoids re-calling load_p1_classes after mock init)
        try:
            cached = load_p1_classes()
            SourceType = cached["SourceType"]
            TrustLevel = cached["TrustLevel"]
            GuardrailContext = cached["GuardrailContext"]
        except Exception:
            # Mocked path: construct minimal stand-in objects
            SourceType = type("SourceType", (), {"FILE": "file", "TOOL_OUTPUT": "tool_output"})
            TrustLevel = type("TrustLevel", (), {"UNTRUSTED": "untrusted"})
            GuardrailContext = _MinimalGuardrailContext

        # Derive source type from metadata
        source = source_metadata or {}
        raw_source = source.get("source", "local_document")
        p1_source = SourceType.FILE if "document" in raw_source else SourceType.TOOL_OUTPUT
        p1_trust = TrustLevel.UNTRUSTED  # all P2 content is untrusted by default

        ctx = GuardrailContext(
            agent_id=source.get("agent_id", "p2_offline_agent"),
            metadata={
                "document_id": source.get("document_id", ""),
                "file_format": source.get("file_format", ""),
                "trust_level": "untrusted",
                "source": raw_source,
            },
        )

        try:
            response = await self._input_guard.validate_async(
                request=content,
                context=ctx,
                source_type=p1_source,
                trust_level=p1_trust,
                raise_on_block=False,
            )
        except Exception as exc:
            log.error("p1_content_inspect_failed", error=str(exc))
            return await self._handle_failure(
                P1InspectionError(str(exc)), content, source_metadata
            )

        passed = _p1_action_to_passed(response.action.value)
        risk_score = _p1_risk_to_score(response.risk_assessment.level.value)
        findings = _p1_findings_to_dicts(response.findings)

        log.debug(
            "p1_content_inspection_complete",
            action=response.action.value,
            passed=passed,
            risk=response.risk_assessment.level.value,
            findings=len(findings),
        )

        return ContentInspectionResult(
            passed=passed,
            findings=findings,
            risk_score=risk_score,
            inspector="p1_security_engine",
            note=f"P1 InputGuard: action={response.action.value}, "
                 f"latency={response.latency_ms}ms",
        )

    async def _handle_failure(
        self, exc: Exception, content: str, source_metadata: Optional[dict]
    ) -> ContentInspectionResult:
        log.warning("p1_content_adapter_failed", error=str(exc), fail_closed=self._fail_closed)
        if self._fail_closed:
            raise InspectorUnavailableError(
                f"P1 content inspector unavailable: {exc}"
            ) from exc
        return ContentInspectionResult(
            passed=False,
            findings=[{
                "category": "p1_inspection_unavailable",
                "pattern": "p1_unavailable",
                "match": "",
                "note": _NOT_INSPECTED,
            }],
            risk_score=0.5,
            inspector="p1_security_engine_unavailable",
            note=_NOT_INSPECTED,
        )


# ─── Data Inspection Adapter ──────────────────────────────────────────────────

class P1DataInspectionAdapter:
    """
    DataInspectionPort backed by P1's OutputGuard / SecretScanner / DLPEngine.

    Used for:
      - Terminal stdout/stderr secret redaction
      - Output safety check before returning to agent

    IMPORTANT: This adapter runs AFTER the local secret redaction pass in the
    TerminalOutputInspector pipeline.  Never pass raw secret values to this adapter.
    P1's OutputGuard adds a deeper layer of secret and DLP inspection on
    already-pre-screened content.
    """

    def __init__(
        self,
        *,
        fail_closed: bool = True,
        p1_config=None,
    ) -> None:
        self._fail_closed = fail_closed
        self._p1_config = p1_config
        self._output_guard = None
        self._initialized = False
        self._init_error: Optional[str] = None

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            classes = load_p1_classes()
            Config = classes["AgentShieldConfig"]
            OutputGuard = classes["OutputGuard"]
            cfg = self._p1_config or Config()
            self._output_guard = OutputGuard(config=cfg)
            self._initialized = True
            log.info("p1_data_inspector_ready")
        except P1NotAvailableError:
            raise
        except Exception as exc:
            self._init_error = str(exc)
            raise P1ConfigError(f"P1 OutputGuard init failed: {exc}") from exc

    async def inspect(
        self,
        content: str,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> DataInspectionResult:
        try:
            self._ensure_initialized()
        except (P1NotAvailableError, P1ConfigError) as exc:
            return await self._handle_failure(exc, content, context)

        try:
            cached = load_p1_classes()
            GuardrailContext = cached["GuardrailContext"]
            SourceType = cached["SourceType"]
        except Exception:
            GuardrailContext = _MinimalGuardrailContext
            SourceType = type("SourceType", (), {"TOOL_OUTPUT": "tool_output"})

        ctx = GuardrailContext(
            agent_id=(context or {}).get("agent_id", "p2_offline_agent"),
            metadata={"source": "terminal_output", "trust_level": "untrusted"},
        )

        try:
            response = await self._output_guard.validate_async(
                request=content,
                context=ctx,
                source_type=SourceType.TOOL_OUTPUT,
                raise_on_block=False,
            )
        except Exception as exc:
            log.error("p1_data_inspect_failed", error=str(exc))
            return await self._handle_failure(
                P1InspectionError(str(exc)), content, context
            )

        passed = _p1_action_to_passed(response.action.value)
        findings = _p1_findings_to_dicts(response.findings)

        # Use P1's sanitized output when content was modified/masked
        sanitized = getattr(response, "sanitized_output", None)
        redacted_content = None
        if sanitized and sanitized != content:
            # P1's sanitized output is always a safe placeholder or redacted
            # text; never fall back to the original raw content.
            redacted_content = sanitized
        elif not passed:
            # Blocked but P1 returned no usable sanitized output — withhold
            # the original content entirely.
            redacted_content = "[OUTPUT BLOCKED BY P1 SECURITY ENGINE]"

        log.debug(
            "p1_data_inspection_complete",
            action=response.action.value,
            passed=passed,
            findings=len(findings),
            redacted=redacted_content is not None,
        )

        return DataInspectionResult(
            passed=passed,
            redacted_content=redacted_content,
            findings=findings,
            inspector="p1_security_engine",
            note=f"P1 OutputGuard: action={response.action.value}, "
                 f"latency={response.latency_ms}ms",
        )

    async def _handle_failure(
        self, exc: Exception, content: str, context: Optional[dict]
    ) -> DataInspectionResult:
        log.warning("p1_data_adapter_failed", error=str(exc), fail_closed=self._fail_closed)
        if self._fail_closed:
            raise InspectorUnavailableError(
                f"P1 data inspector unavailable: {exc}"
            ) from exc
        return DataInspectionResult(
            passed=False,
            redacted_content=None,
            findings=[{
                "category": "p1_inspection_unavailable",
                "type": "p1_unavailable",
                "note": _NOT_INSPECTED,
            }],
            inspector="p1_security_engine_unavailable",
            note=_NOT_INSPECTED,
        )
