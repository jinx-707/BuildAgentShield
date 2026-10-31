"""Audit events API routes.

Endpoints:
- GET /v1/audit/events — list audit events with optional filtering
- GET /v1/audit/events/{event_id} — read a single audit event
"""

import logging

from fastapi import APIRouter, HTTPException, Query, Request

from app.services.audit import AuditStore, AuditEventType

router = APIRouter(prefix="/v1/audit", tags=["audit"])
logger = logging.getLogger(__name__)

# Shared audit store is attached to app state during create_app().


def _get_store(request: Request) -> AuditStore:
    store = getattr(request.app.state, "audit_store", None)
    if store is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "AUDIT_STORE_UNAVAILABLE", "message": "audit store is not initialized"},
        )
    return store


@router.get("/events", response_model=None)
async def list_events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    event_type: AuditEventType | None = Query(default=None),
    actor: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
):
    store = _get_store(request)
    return store.list(
        limit=limit,
        offset=offset,
        event_type=event_type,
        actor=actor,
        session_id=session_id,
    )


@router.get("/events/{event_id}")
async def get_event(request: Request, event_id: str):
    store = _get_store(request)
    result = store.list(limit=1, offset=0)
    for event in result.events:
        if event.event_id == event_id:
            return event
    raise HTTPException(
        status_code=404,
        detail={"code": "AUDIT_EVENT_NOT_FOUND", "message": "audit event not found"},
    )
