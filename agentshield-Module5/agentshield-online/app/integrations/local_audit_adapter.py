"""
LOCAL DEVELOPMENT ONLY — Audit Adapter.

Writes structured JSON audit events to a logger.
In production, replace with Person 4's centralized audit infrastructure.

This adapter must never raise — audit failures are logged internally.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from app.integrations.ports import AuditPort, AuditEvent

logger = logging.getLogger("agentshield.audit")


class LocalAuditAdapter(AuditPort):
    """
    Development audit adapter.
    Records events as structured JSON log lines.
    Also keeps an in-memory log for test assertions.
    """

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    async def record(self, event: AuditEvent) -> None:
        try:
            record = {
                "audit": True,
                "event_type": event.event_type,
                "agent_id": event.agent_id,
                "tenant_id": event.tenant_id,
                "capability": event.capability,
                "operation": event.operation,
                "decision": event.decision,
                "status": event.status,
                "request_id": event.request_id,
                "resource": event.resource,
                "reason": event.reason,
                "metadata": event.metadata,
                "timestamp": event.timestamp.isoformat(),
            }
            self._events.append(record)
            logger.info("[AUDIT] %s", json.dumps(record))
        except Exception as e:
            # Must never propagate
            logger.error("[AUDIT] Failed to record event: %s", e)

    def get_events(
        self,
        capability: str | None = None,
        agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Test helper: retrieve recorded audit events."""
        events = self._events
        if capability:
            events = [e for e in events if e.get("capability") == capability]
        if agent_id:
            events = [e for e in events if e.get("agent_id") == agent_id]
        return events

    def clear(self) -> None:
        """Test helper: clear recorded events."""
        self._events.clear()
