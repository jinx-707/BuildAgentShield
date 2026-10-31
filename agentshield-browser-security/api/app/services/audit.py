"""In-memory audit event store for the AgentShield security API.

Events are appended in process memory and can be queried through the
audit events API. This is a development/operational store; durable
persistence is introduced in Prompt 2 (PostgreSQL + migrations).
"""

from threading import Lock
from typing import Literal
import asyncio

from app.schemas.audit import AuditEvent, AuditEventList
from app.services.event_broadcaster import broadcaster

AuditEventType = Literal[
    "session.create",
    "session.read",
    "session.close",
    "navigation.allow",
    "navigation.deny",
    "navigation.blocked_redirect",
    "action.execute",
    "action.refuse",
    "extract.read",
    "screenshot.capture",
    "security.violation",
    "auth.failure",
    "admin.change",
]


class AuditStore:
    """Thread-safe in-memory audit event store with bounded retention."""

    def __init__(self, max_events: int = 10000) -> None:
        self._max_events = max_events
        self._events: list[AuditEvent] = []
        self._lock = Lock()

    def add(
        self,
        *,
        type: AuditEventType,
        actor: str | None = None,
        session_id: str | None = None,
        target: str | None = None,
        decision: str | None = None,
        reason: str | None = None,
        request_id: str | None = None,
        metadata: dict | None = None,
        organization_id: str | None = None,
        agent_id: str | None = None,
        event_category: str | None = None,
        ip_address: str | None = None,
        severity: str = "info",
    ) -> AuditEvent:
        event = AuditEvent(
            type=type,
            actor=actor,
            session_id=session_id,
            target=target,
            decision=decision,
            reason=reason,
            request_id=request_id,
            metadata=metadata or {},
        )
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events :]
        try:
            asyncio.create_task(
                broadcaster.publish(
                    {
                        "id": event.event_id,
                        "organization_id": None,
                        "event_type": event.type,
                        "actor": event.actor,
                        "session_id": event.session_id,
                        "target": event.target,
                        "decision": event.decision,
                        "reason": event.reason,
                        "request_id": event.request_id,
                        "timestamp": event.timestamp.isoformat(),
                        "metadata": event.metadata,
                    }
                )
            )
        except RuntimeError:
            pass
        return event

    def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        event_type: AuditEventType | None = None,
        actor: str | None = None,
        session_id: str | None = None,
    ) -> AuditEventList:
        with self._lock:
            filtered = list(self._events)

        if event_type is not None:
            filtered = [e for e in filtered if e.type == event_type]
        if actor is not None:
            filtered = [e for e in filtered if e.actor == actor]
        if session_id is not None:
            filtered = [e for e in filtered if e.session_id == session_id]

        total = len(filtered)
        page = filtered[offset : offset + limit]
        return AuditEventList(events=page, total=total, limit=limit, offset=offset)
