"""
AgentShield Offline — Output Redaction.

Wraps the DataInspectionPort to redact secrets and sensitive data from
command outputs, log messages and API responses before they are returned
to the agent.

This module is an adapter — in production, wire in Person 1's DLP engine.
"""

from __future__ import annotations

from typing import Optional

import structlog

from app.integrations.ports import DataInspectionPort, DataInspectionResult

log = structlog.get_logger(__name__)


class OutputRedactor:
    """
    Runs data inspection on a string and returns the redacted version.
    If the inspector is unavailable, behaviour depends on fail_closed setting.
    """

    def __init__(
        self,
        inspector: DataInspectionPort,
        *,
        fail_closed: bool = True,
    ) -> None:
        self._inspector = inspector
        self._fail_closed = fail_closed

    async def redact(self, content: str, context: Optional[dict] = None) -> str:
        """
        Returns the redacted version of content.
        If inspector raises and fail_closed=True, raises InspectorUnavailableError.
        """
        try:
            result: DataInspectionResult = await self._inspector.inspect(
                content, context=context
            )
            if not result.passed and result.redacted_content is not None:
                log.warning(
                    "output_redacted",
                    finding_count=len(result.findings),
                    inspector=result.inspector,
                )
                return result.redacted_content
            return content
        except Exception as exc:  # noqa: BLE001
            log.error("output_redaction_failed", error=str(exc))
            if self._fail_closed:
                from app.core.exceptions import InspectorUnavailableError
                raise InspectorUnavailableError(
                    "Output inspector unavailable and fail_closed=True"
                ) from exc
            return content
