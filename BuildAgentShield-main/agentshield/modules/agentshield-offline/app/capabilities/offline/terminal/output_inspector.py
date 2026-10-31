"""
AgentShield Offline — Terminal Output Inspector.

Runs content and data inspection on command output before returning it
to the agent.  Wires into the ContentInspectionPort and DataInspectionPort.
"""

from __future__ import annotations

from typing import Optional

import structlog

from app.integrations.ports import ContentInspectionPort, DataInspectionPort

log = structlog.get_logger(__name__)


class TerminalOutputInspector:
    """
    Inspects and optionally redacts terminal stdout/stderr before delivery.
    """

    def __init__(
        self,
        content_inspector: ContentInspectionPort,
        data_inspector: DataInspectionPort,
        *,
        fail_closed: bool = True,
    ) -> None:
        self._content = content_inspector
        self._data = data_inspector
        self._fail_closed = fail_closed

    async def inspect_and_redact(
        self,
        stdout: str,
        stderr: str,
        *,
        agent_id: str = "",
        execution_id: str = "",
    ) -> tuple[str, str, list[dict]]:
        """
        Returns (inspected_stdout, inspected_stderr, findings).
        May redact secret values from both streams.
        """
        findings: list[dict] = []

        try:
            # Inspect stdout for prompt injection
            ci_result = await self._content.inspect(
                stdout,
                source_metadata={
                    "source": "terminal_stdout",
                    "trust_level": "untrusted",
                    "execution_id": execution_id,
                    "agent_id": agent_id,
                },
            )
            if not ci_result.passed:
                findings.extend(ci_result.findings)
                log.warning(
                    "terminal_output_flagged",
                    execution_id=execution_id,
                    finding_count=len(ci_result.findings),
                )

            # Redact secrets from stdout
            di_result = await self._data.inspect(stdout)
            clean_stdout = di_result.redacted_content if (not di_result.passed and di_result.redacted_content) else stdout

            # Redact secrets from stderr
            di_stderr = await self._data.inspect(stderr)
            clean_stderr = di_stderr.redacted_content if (not di_stderr.passed and di_stderr.redacted_content) else stderr

            return clean_stdout, clean_stderr, findings

        except Exception as exc:  # noqa: BLE001
            log.error("terminal_output_inspection_failed", error=str(exc))
            if self._fail_closed:
                from app.core.exceptions import InspectorUnavailableError
                raise InspectorUnavailableError(
                    "Terminal output inspector unavailable"
                ) from exc
            return stdout, stderr, findings
