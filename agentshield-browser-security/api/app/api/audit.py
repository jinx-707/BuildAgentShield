"""Audit events API routes.

Endpoints:
- GET /v1/audit/events — list audit events with optional filtering
- GET /v1/audit/events/{event_id} — read a single audit event
"""

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.enterprise.deps import get_current_principal, get_db
from app.services.audit import AuditStore, AuditEventType
from app.services.event_broadcaster import broadcaster

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


@router.get("/stream")
async def stream_events(
    request: Request,
    token: str | None = Query(default=None),
    principal=Depends(get_current_principal),
):
    """Server-Sent Events stream of audit events for the principal's org.

    Emits ``data: <json>\n\n`` messages for new audit events. Clients can keep
    the connection open to receive real-time security monitoring updates.

    Authentication: the ``Authorization: Bearer`` header is preferred.
    Because ``EventSource`` cannot set custom headers, a ``token`` query
    parameter is also accepted as a fallback.
    """
    # Resolve principal from the query token when no bearer header is present.
    if principal is None and token is not None:
        from app.enterprise.auth import decode_access_token, verify_api_key
        from app.enterprise.rbac import Principal, get_role_permissions
        from app.db.base import get_db_session

        db = None
        try:
            db = get_db_session()
        except RuntimeError:
            db = None
        try:
            payload = decode_access_token(token)
            if payload:
                sub = payload.get("sub")
                org_id = payload.get("org")
                roles = payload.get("roles", [])
                permissions = set()
                for role in roles:
                    permissions.update(get_role_permissions(role))
                principal = Principal(
                    user_id=sub if not sub.startswith("agent-") else None,
                    agent_id=sub if sub.startswith("agent-") else None,
                    organization_id=org_id,
                    role=roles[0] if roles else "viewer",
                    permissions=permissions,
                )
            elif db is not None:
                api_key = verify_api_key(db, token)
                if api_key:
                    principal = Principal(
                        user_id=api_key.user_id,
                        organization_id=api_key.organization_id,
                        role="viewer",
                        permissions={"session:read", "audit:read", "org:read"},
                    )
        finally:
            if db is not None:
                db.close()

    if principal is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "AUTHENTICATION_REQUIRED", "message": "no credentials provided"},
        )

    async def event_generator():
        queue = await broadcaster.subscribe()
        try:
            # Send an initial heartbeat so the connection is established.
            yield json.dumps({"type": "heartbeat"}) + "\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    yield ":heartbeat\n\n"
                    continue
                # Only forward events belonging to the subscriber's organization.
                try:
                    event = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                if (
                    principal is None
                    or event.get("organization_id") == principal.organization_id
                ):
                    yield f"data: {payload}\n\n"
        finally:
            await broadcaster.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
