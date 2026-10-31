"""
AgentShield Offline — Local Audit Adapter.

⚠️  DEVELOPMENT COMPONENT ⚠️

Writes structured audit events to a local JSONL file.
Exposes the AuditPort interface so Person 4's central audit service
can replace this adapter without changing calling code.

IMPORTANT: This adapter NEVER logs credential values, secret contents,
or file payloads — only metadata and identifiers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import structlog

from app.core.contracts import AuditEvent
from app.integrations.ports import AuditPort

log = structlog.get_logger(__name__)

_ADAPTER_NOTE = (
    "LOCAL_AUDIT_ADAPTER — writes to local JSONL file. "
    "Replace with Person 4's central audit service in production."
)


class LocalAuditAdapter:
    """
    Local filesystem audit sink.
    Appends newline-delimited JSON records to a configurable log file.
    Sensitive values are never recorded.
    """

    def __init__(self, log_path: str) -> None:
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        log.info(
            "local_audit_adapter_initialized",
            path=str(self._log_path),
            note=_ADAPTER_NOTE,
        )

    async def record(self, event: AuditEvent) -> None:
        record = {
            "event_id": event.event_id,
            "request_id": event.request_id,
            "agent_id": event.agent_id,
            "tenant_id": event.tenant_id,
            "module": event.module.value,
            "tool": event.tool,
            "operation": event.operation,
            "resource": event.resource,
            "decision": event.decision.value,
            "risk_level": event.risk_level.value,
            "reason": event.reason,
            "timestamp": event.timestamp.isoformat(),
            # metadata must not contain secret values — enforced by callers
            "metadata": event.metadata,
        }
        try:
            with self._log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as exc:
            log.error("audit_write_failed", error=str(exc), path=str(self._log_path))
            raise

        log.debug(
            "audit_recorded",
            event_id=event.event_id,
            decision=event.decision.value,
            module=event.module.value,
        )


class NullAuditAdapter:
    """
    No-op audit adapter for testing. Events are silently discarded.
    """

    async def record(self, event: AuditEvent) -> None:
        pass


class InMemoryAuditAdapter:
    """
    In-memory audit adapter for unit tests.
    Stores events in a list that tests can inspect.
    """

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def record(self, event: AuditEvent) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()

    def last_event(self) -> Optional[AuditEvent]:
        return self.events[-1] if self.events else None
