"""Audit event schemas for the AgentShield security API.

Audit events record security-relevant actions: session lifecycle,
navigation decisions, policy denials, and administrative operations.
Events are held in memory for the current process lifetime; durable
persistence is introduced in the enterprise control plane (Prompt 2).
"""

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

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


class AuditEvent(BaseModel):
    """A single immutable audit event."""

    event_id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    type: AuditEventType
    actor: str | None = None
    session_id: str | None = None
    target: str | None = None
    decision: str | None = None
    reason: str | None = None
    request_id: str | None = None
    metadata: dict = Field(default_factory=dict)


class AuditEventList(BaseModel):
    """A paginated list of audit events."""

    events: list[AuditEvent]
    total: int
    limit: int
    offset: int
