"""
AgentShield Offline — Document Content Inspector.

Wraps the ContentInspectionPort to inspect extracted document text.
Extracted document content is always treated as UNTRUSTED.
"""

from __future__ import annotations

from typing import Any, Optional

import structlog

from app.core.contracts import InspectionStatus, SecurityFinding, RiskLevel
from app.integrations.ports import ContentInspectionPort, ContentInspectionResult

log = structlog.get_logger(__name__)


class DocumentInspector:
    """
    Invokes the configured content inspector on extracted document text.
    Document content is always tagged with trust_level=UNTRUSTED.
    """

    def __init__(
        self,
        inspector: ContentInspectionPort,
        *,
        fail_closed: bool = True,
    ) -> None:
        self._inspector = inspector
        self._fail_closed = fail_closed

    async def inspect(
        self,
        text: str,
        *,
        document_id: str,
        file_format: str,
    ) -> tuple[InspectionStatus, list[SecurityFinding]]:
        """
        Returns (inspection_status, findings).
        """
        source_metadata = {
            "source": "local_document",
            "trust_level": "untrusted",
            "document_id": document_id,
            "file_format": file_format,
        }
        try:
            result: ContentInspectionResult = await self._inspector.inspect(
                text, source_metadata=source_metadata
            )
            findings = []
            for raw in result.findings:
                findings.append(
                    SecurityFinding(
                        severity=RiskLevel.HIGH if result.risk_score > 0.5 else RiskLevel.MEDIUM,
                        category=raw.get("category", "unknown"),
                        description=raw.get("pattern", ""),
                        evidence=raw.get("match", "")[:200],
                        recommendation="Review document content before use",
                    )
                )
            status = InspectionStatus.PASSED if result.passed else InspectionStatus.FLAGGED
            return status, findings

        except Exception as exc:
            log.error("document_inspection_failed", error=str(exc))
            if self._fail_closed:
                return InspectionStatus.INSPECTOR_UNAVAILABLE, []
            return InspectionStatus.ERROR, []
