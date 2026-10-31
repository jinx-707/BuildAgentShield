"""Persistent PostgreSQL-backed audit event store for AgentShield.

Replaces the in-memory AuditStore with durable persistence. Preserves the
existing AuditEvent semantics and API compatibility: every event field from the
in-memory store is mapped to a database column, and the same add()/list()
interface is exposed.

Organization-scoped: every audit event is bound to an organization so tenant
isolation is enforced at the query layer. Cross-tenant audit access is not
possible because all queries filter by organization_id.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4
import asyncio

from sqlalchemy.orm import Session

from app.db.base import get_db_session, get_engine
from app.db.models import (
    Agent,
    AuditEvent as AuditEventModel,
    Organization,
)
from app.schemas.audit import AuditEvent, AuditEventList, AuditEventType
from app.services.event_broadcaster import broadcaster

logger = logging.getLogger(__name__)


class PersistentAuditStore:
    """PostgreSQL-backed audit event store with pagination and filtering."""

    def __init__(self, organization_id: str | None = None) -> None:
        self._organization_id = organization_id
        engine = get_engine()
        if engine is None:
            raise RuntimeError("Database not initialized. Call init_db() first.")

    def _session(self) -> Session:
        return get_db_session()

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
        event_category: str | None = None,
        agent_id: str | None = None,
        ip_address: str | None = None,
        severity: str = "info",
    ) -> AuditEvent:
        org_id = organization_id or self._organization_id
        if not org_id and agent_id:
            # Resolve the organization from the agent so browser audit events
            # are tenant-scoped even when the caller does not supply an org.
            db = self._session()
            try:
                agent = (
                    db.query(Agent)
                    .filter(Agent.agent_id == agent_id)
                    .first()
                )
                if agent:
                    org_id = str(agent.organization_id)
            finally:
                db.close()
        if not org_id:
            raise ValueError("organization_id is required for persistent audit events")
        event = AuditEventModel(
            id=str(uuid4()),
            organization_id=org_id,
            actor=actor,
            actor_type=None,
            event_type=type,
            event_category=event_category,
            session_id=session_id,
            agent_id=agent_id,
            target=target,
            decision=decision,
            reason=reason,
            severity=severity,
            request_id=request_id,
            event_metadata=metadata or {},
            ip_address=ip_address,
        )
        db = self._session()
        try:
            db.add(event)
            db.commit()
            db.refresh(event)
        except Exception:
            db.rollback()
            logger.exception("audit_event_persist_failed")
            raise
        finally:
            db.close()
        audit_event = AuditEvent(
            event_id=event.id,
            timestamp=event.created_at,
            type=event.event_type,
            actor=event.actor,
            session_id=event.session_id,
            target=event.target,
            decision=event.decision,
            reason=event.reason,
            request_id=event.request_id,
            metadata=event.event_metadata or {},
        )
        try:
            asyncio.create_task(self.publish(audit_event, org_id))
        except RuntimeError:
            # No running event loop (e.g. sync callers); publication is best-effort.
            pass
        return audit_event

    async def publish(self, event: AuditEvent, organization_id: str | None) -> None:
        """Publish a persisted audit event to SSE subscribers."""
        try:
            await broadcaster.publish(
                {
                    "id": event.event_id,
                    "organization_id": organization_id,
                    "event_type": event.type,
                    "actor": event.actor,
                    "session_id": event.session_id,
                    "target": event.target,
                    "decision": event.decision,
                    "reason": event.reason,
                    "request_id": event.request_id,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "metadata": event.metadata,
                }
            )
        except Exception:
            logger.exception("audit_event_publish_failed")

    def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        event_type: AuditEventType | None = None,
        actor: str | None = None,
        session_id: str | None = None,
        organization_id: str | None = None,
        agent_id: str | None = None,
        decision: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> AuditEventList:
        org_id = organization_id or self._organization_id
        db = self._session()
        try:
            query = db.query(AuditEventModel)
            if org_id:
                query = query.filter(AuditEventModel.organization_id == org_id)
            if event_type is not None:
                query = query.filter(AuditEventModel.event_type == event_type)
            if actor is not None:
                query = query.filter(AuditEventModel.actor == actor)
            if session_id is not None:
                query = query.filter(AuditEventModel.session_id == session_id)
            if agent_id is not None:
                query = query.filter(AuditEventModel.agent_id == agent_id)
            if decision is not None:
                query = query.filter(AuditEventModel.decision == decision)
            if start_time is not None:
                query = query.filter(AuditEventModel.created_at >= start_time)
            if end_time is not None:
                query = query.filter(AuditEventModel.created_at <= end_time)

            query = query.order_by(AuditEventModel.created_at.desc())
            total = query.count()
            rows = query.offset(offset).limit(limit).all()
        finally:
            db.close()

        events = [
            AuditEvent(
                event_id=row.id,
                timestamp=row.created_at,
                type=row.event_type,
                actor=row.actor,
                session_id=row.session_id,
                target=row.target,
                decision=row.decision,
                reason=row.reason,
                request_id=row.request_id,
                metadata=row.event_metadata or {},
            )
            for row in rows
        ]
        return AuditEventList(events=events, total=total, limit=limit, offset=offset)

    def count(self, *, organization_id: str | None = None) -> int:
        org_id = organization_id or self._organization_id
        db = self._session()
        try:
            query = db.query(AuditEventModel)
            if org_id:
                query = query.filter(AuditEventModel.organization_id == org_id)
            return query.count()
        finally:
            db.close()
