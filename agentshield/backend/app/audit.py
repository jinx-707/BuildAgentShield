from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import AuditEvent, AuditHead, utcnow
from .security import hash_event, sanitize_dict


def iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


class AuditService:
    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def append(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_type: str,
        actor_id: str,
        action: str,
        decision: str,
        risk_score: int = 0,
        risk_level: str = "none",
        tool_name: str = "",
        request_id: str = "",
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        async with self._locks[tenant_id]:
            head = await session.get(AuditHead, tenant_id, with_for_update=True)
            if head is None:
                head = AuditHead(tenant_id=tenant_id, sequence=0, last_hash="0" * 64)
                session.add(head)
                await session.flush()
            sequence = head.sequence + 1
            safe_details = sanitize_dict(details or {})
            created_at = utcnow()
            payload = {
                "tenant_id": tenant_id,
                "sequence": sequence,
                "actor_type": actor_type,
                "actor_id": actor_id,
                "action": action,
                "decision": decision,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "tool_name": tool_name,
                "request_id": request_id,
                "details": safe_details,
                "created_at": iso_utc(created_at),
            }
            previous = head.last_hash
            event_hash = hash_event(previous, payload)
            event = AuditEvent(
                tenant_id=tenant_id,
                sequence=sequence,
                actor_type=actor_type,
                actor_id=actor_id,
                action=action,
                tool_name=tool_name,
                request_id=request_id,
                decision=decision,
                risk_score=risk_score,
                risk_level=risk_level,
                details=safe_details,
                prev_hash=previous,
                event_hash=event_hash,
                created_at=created_at,
            )
            head.sequence = sequence
            head.last_hash = event_hash
            head.updated_at = created_at
            session.add(event)
            await session.flush()
            return event

    async def verify(self, session: AsyncSession, tenant_id: str) -> dict[str, Any]:
        result = await session.execute(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.sequence.asc())
        )
        events = result.scalars().all()
        previous = "0" * 64
        for event in events:
            payload = {
                "tenant_id": event.tenant_id,
                "sequence": event.sequence,
                "actor_type": event.actor_type,
                "actor_id": event.actor_id,
                "action": event.action,
                "decision": event.decision,
                "risk_score": event.risk_score,
                "risk_level": event.risk_level,
                "tool_name": event.tool_name,
                "request_id": event.request_id,
                "details": event.details,
                "created_at": iso_utc(event.created_at),
            }
            expected = hash_event(previous, payload)
            if event.prev_hash != previous or event.event_hash != expected:
                return {
                    "valid": False,
                    "events": len(events),
                    "broken_sequence": event.sequence,
                    "checked_at": utcnow().isoformat(),
                }
            previous = event.event_hash
        return {
            "valid": True,
            "events": len(events),
            "head": previous,
            "broken_sequence": None,
            "checked_at": utcnow().isoformat(),
        }


def event_summary(event: AuditEvent) -> dict[str, Any]:
    details = event.details or {}
    description = details.get("summary") or details.get("description") or event.action
    created_at: datetime = event.created_at
    return {
        "id": event.id,
        "sequence": event.sequence,
        "agent": details.get("agent_name", event.actor_id),
        "tool": event.tool_name,
        "description": description,
        "decision": decision_label(event.decision),
        "risk": event.risk_score,
        "risk_level": event.risk_level,
        "time": created_at.isoformat(),
        "request_id": event.request_id,
        "details": details,
        "event_hash": event.event_hash,
        "prev_hash": event.prev_hash,
    }


def decision_label(decision: str) -> str:
    return {
        "ALLOW": "Allowed",
        "DENY": "Blocked",
        "REQUIRE_APPROVAL": "Approval",
        "QUARANTINE": "Quarantined",
        "REDACT": "Redacted",
    }.get(decision, decision.title())

