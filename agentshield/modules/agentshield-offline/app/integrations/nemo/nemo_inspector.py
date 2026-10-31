"""
AgentShield Offline — NeMo Content Inspector.

Implements ContentInspectionPort and DataInspectionPort using the NeMo engine.
Both classes are drop-in replacements for LocalDevelopmentContentInspector and
LocalDevelopmentDataInspector — they share the exact same interface.

Architecture:
  ┌────────────────────────────────────────────┐
  │  AgentShield Content Inspection Layer       │
  │                                             │
  │  NemoContentInspector (ContentInspectionPort)│
  │  NemoDataInspector    (DataInspectionPort)  │
  │         │                                   │
  │  NemoEngine (singleton via DI)              │
  │         │                                   │
  │  nemoguardrails.Guardrails (optional pkg)   │
  └────────────────────────────────────────────┘

Fail-closed behaviour
---------------------
When NeMo is unavailable (not installed, misconfigured, timed out):
  - If fail_closed=True  → raises InspectorUnavailableError
  - If fail_closed=False → logs a warning and returns a NOT_INSPECTED result

Secret protection
-----------------
Content MUST be pre-screened by the existing DataInspectionPort (secret redaction)
BEFORE being passed to NemoContentInspector to ensure no credential values
reach the NeMo engine (and potentially an external model provider).
This is enforced by the TerminalOutputInspector pipeline ordering.
"""

from __future__ import annotations

from typing import Any, Optional

import structlog

from app.core.configuration import get_settings
from app.core.exceptions import InspectorUnavailableError
from app.integrations.nemo.exceptions import (
    NemoEngineError,
    NemoNotInstalledError,
    NemoTimeoutError,
)
from app.integrations.nemo.nemo_engine import NemoEngine, _NemoCheckResult
from app.integrations.nemo.nemo_result_mapper import map_to_content_result, map_to_data_result
from app.integrations.ports import ContentInspectionResult, DataInspectionResult

log = structlog.get_logger(__name__)

_NOT_INSPECTED_NOTE = (
    "NeMo inspection skipped (unavailable / disabled). "
    "Content was NOT inspected by NeMo Guardrails."
)


class NemoContentInspector:
    """
    ContentInspectionPort implementation backed by NeMo Guardrails.

    Passes content through configured NeMo input rails.
    Falls back gracefully when NeMo is unavailable.

    Drop-in replacement for LocalDevelopmentContentInspector.
    """

    def __init__(
        self,
        engine: NemoEngine,
        *,
        fail_closed: bool = True,
        fallback_inspector=None,
    ) -> None:
        """
        Args:
            engine: The shared NemoEngine singleton.
            fail_closed: If True, raise on NeMo failure; if False, degrade.
            fallback_inspector: An optional ContentInspectionPort to use when
                NeMo is unavailable and fail_closed=False. If None, returns
                a NOT_INSPECTED pass-through result.
        """
        self._engine = engine
        self._fail_closed = fail_closed
        self._fallback = fallback_inspector
        self._settings = get_settings()
        log.info(
            "nemo_content_inspector_created",
            fail_closed=fail_closed,
            has_fallback=fallback_inspector is not None,
        )

    async def inspect(
        self,
        content: str,
        *,
        source_metadata: Optional[dict[str, Any]] = None,
    ) -> ContentInspectionResult:
        """Inspect content via NeMo input rails."""

        # Truncate to configured limit before sending to NeMo
        max_chars = self._settings.nemo_max_content_chars
        truncated = content[:max_chars] if len(content) > max_chars else content
        was_truncated = len(content) > max_chars

        if was_truncated:
            log.debug(
                "nemo_content_truncated",
                original_length=len(content),
                truncated_to=max_chars,
            )

        try:
            nemo_result = await self._engine.check_input(truncated)
            ci_result = map_to_content_result(
                nemo_result,
                original_content=truncated,
                source_metadata=source_metadata,
            )
            log.debug(
                "nemo_input_inspection_complete",
                status=nemo_result.status,
                passed=ci_result.passed,
                source=source_metadata.get("source") if source_metadata else None,
            )
            return ci_result

        except (NemoNotInstalledError, NemoEngineError, NemoTimeoutError) as exc:
            return await self._handle_failure(exc, content, source_metadata)

        except Exception as exc:  # noqa: BLE001
            log.error("nemo_content_inspect_unexpected_error", error=str(exc))
            return await self._handle_failure(exc, content, source_metadata)

    async def _handle_failure(
        self, exc: Exception, content: str, source_metadata: Optional[dict]
    ) -> ContentInspectionResult:
        log.warning(
            "nemo_content_inspector_failed",
            error=str(exc),
            fail_closed=self._fail_closed,
        )
        if self._fail_closed:
            raise InspectorUnavailableError(
                f"NeMo content inspector unavailable: {exc}"
            ) from exc

        # Fallback path
        if self._fallback is not None:
            log.info("nemo_falling_back_to_fallback_inspector")
            return await self._fallback.inspect(content, source_metadata=source_metadata)

        # Return an explicit not-inspected result (never silently pass)
        return ContentInspectionResult(
            passed=False,
            findings=[
                {
                    "category": "nemo_inspection_unavailable",
                    "pattern": "nemo_unavailable",
                    "match": "",
                    "note": _NOT_INSPECTED_NOTE,
                }
            ],
            risk_score=0.5,
            inspector="nemo_guardrails_unavailable",
            note=_NOT_INSPECTED_NOTE,
        )


class NemoDataInspector:
    """
    DataInspectionPort implementation backed by NeMo Guardrails output rails.

    Passes content through configured NeMo output rails for safety screening.
    Falls back gracefully when NeMo is unavailable.

    Drop-in replacement for LocalDevelopmentDataInspector.

    IMPORTANT: This inspector is NOT a substitute for the existing secret
    redaction pipeline. Always run the existing DataInspectionPort (secret
    scanner) BEFORE passing content to this inspector to ensure that
    credential values never reach a remote model provider.
    """

    def __init__(
        self,
        engine: NemoEngine,
        *,
        fail_closed: bool = True,
        fallback_inspector=None,
    ) -> None:
        self._engine = engine
        self._fail_closed = fail_closed
        self._fallback = fallback_inspector
        self._settings = get_settings()
        log.info(
            "nemo_data_inspector_created",
            fail_closed=fail_closed,
            has_fallback=fallback_inspector is not None,
        )

    async def inspect(
        self,
        content: str,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> DataInspectionResult:
        """Inspect content via NeMo output rails."""

        max_chars = self._settings.nemo_max_content_chars
        truncated = content[:max_chars] if len(content) > max_chars else content

        try:
            nemo_result = await self._engine.check_output(truncated)
            di_result = map_to_data_result(
                nemo_result,
                original_content=truncated,
            )
            log.debug(
                "nemo_output_inspection_complete",
                status=nemo_result.status,
                passed=di_result.passed,
            )
            return di_result

        except (NemoNotInstalledError, NemoEngineError, NemoTimeoutError) as exc:
            return await self._handle_failure(exc, content, context)

        except Exception as exc:  # noqa: BLE001
            log.error("nemo_data_inspect_unexpected_error", error=str(exc))
            return await self._handle_failure(exc, content, context)

    async def _handle_failure(
        self, exc: Exception, content: str, context: Optional[dict]
    ) -> DataInspectionResult:
        log.warning(
            "nemo_data_inspector_failed",
            error=str(exc),
            fail_closed=self._fail_closed,
        )
        if self._fail_closed:
            raise InspectorUnavailableError(
                f"NeMo data inspector unavailable: {exc}"
            ) from exc

        if self._fallback is not None:
            log.info("nemo_data_falling_back_to_fallback_inspector")
            return await self._fallback.inspect(content, context=context)

        return DataInspectionResult(
            passed=False,
            redacted_content=None,
            findings=[
                {
                    "category": "nemo_inspection_unavailable",
                    "type": "nemo_unavailable",
                    "note": _NOT_INSPECTED_NOTE,
                }
            ],
            inspector="nemo_guardrails_unavailable",
            note=_NOT_INSPECTED_NOTE,
        )


class ChainedContentInspector:
    """
    Runs multiple ContentInspectionPort implementations in sequence.
    The first BLOCKED result terminates the chain.

    Architecture:
        LocalDevelopmentContentInspector → NemoContentInspector → (Person 1's engine)

    Used when both local regex inspection AND NeMo should run.
    """

    def __init__(self, *inspectors) -> None:
        self._inspectors = list(inspectors)

    async def inspect(
        self,
        content: str,
        *,
        source_metadata: Optional[dict[str, Any]] = None,
    ) -> ContentInspectionResult:
        all_findings: list[dict] = []
        max_risk = 0.0
        active_inspectors: list[str] = []

        for inspector in self._inspectors:
            result = await inspector.inspect(content, source_metadata=source_metadata)
            active_inspectors.append(result.inspector)
            all_findings.extend(result.findings)
            max_risk = max(max_risk, result.risk_score)

            if not result.passed:
                # Short-circuit on first block
                return ContentInspectionResult(
                    passed=False,
                    findings=all_findings,
                    risk_score=max_risk,
                    inspector="+".join(active_inspectors),
                    note=f"Blocked by: {result.inspector}",
                )

        return ContentInspectionResult(
            passed=True,
            findings=all_findings,
            risk_score=max_risk,
            inspector="+".join(active_inspectors),
            note="All inspectors passed",
        )
