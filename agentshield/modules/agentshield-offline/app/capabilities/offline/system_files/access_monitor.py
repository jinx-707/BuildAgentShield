"""
AgentShield Offline — System file access monitor.

Records every access attempt (allowed or denied) for audit purposes.
IMPORTANT: File contents are NEVER logged.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import structlog

from app.core.contracts import FileOperation, RiskLevel, SecurityDecision

log = structlog.get_logger(__name__)


class SystemFileAccessMonitor:
    """
    Logs system file access events.
    In production this would forward events to Person 4's SIEM via AuditPort.
    """

    def record(
        self,
        *,
        agent_id: str,
        resource: str,
        access_type: FileOperation,
        decision: SecurityDecision,
        denial_reason: Optional[str] = None,
        request_id: str = "",
    ) -> None:
        level = (
            "warning"
            if decision == SecurityDecision.DENY
            else "info"
        )
        # Never include file contents, only path metadata
        getattr(log, level)(
            "system_file_access",
            agent_id=agent_id,
            resource=resource,
            access_type=access_type.value,
            decision=decision.value,
            denial_reason=denial_reason,
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
