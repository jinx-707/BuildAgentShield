from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy import select, update

from .api_common import agent_dict, approval_dict, policy_dict, quarantine_dict
from .approvals import ApprovalError, approve, reject
from .audit import decision_label, event_summary
from .auth import require_dashboard
from .contracts import (
    AgentCreate,
    AgentKeyResponse,
    AgentUpdate,
    ApprovalDecision,
    AuthContext,
    PolicyCreate,
    PolicyUpdate,
    QuarantineRelease,
    WorkspaceUpdate,
)
from .db import (
    Agent,
    AgentKey,
    Approval,
    AuditEvent,
    Policy,
    QuarantineItem,
    Tenant,
    utcnow,
)
from .registry import DEFAULT_AGENT_PERMISSIONS, REGISTRY
from .runtime import Runtime
from .security import generate_agent_key

router = APIRouter(tags=["dashboard"])

KNOWN_PERMISSIONS = {spec.permission for spec in REGISTRY.values()} | {"mcp.call"}
ROLE_LABELS = {"admin", "approver", "viewer", "auditor"}


async def _dashboard_event(
    runtime: Runtime,
    session,
    auth: AuthContext,
    *,
    action: str,
    decision: str,
    summary: str,
    risk: int = 0,
    risk_level: str = "low",
    tool_name: str = "",
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    payload = {"summary": summary, "actor": auth.principal_id}
    payload.update(details or {})
    return await runtime.audit.append(
        session,
        tenant_id=auth.tenant_id,
        actor_type="user",
        actor_id=auth.principal_id,
        action=action,
        decision=decision,
        risk_score=risk,
        risk_level=risk_level,
        tool_name=tool_name,
        details=payload,
    )


@router.get("/agents")
async def list_agents(
    auth: AuthContext = Depends(require_dashboard("agents.read")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        agents = (
            await session.scalars(
                select(Agent)
                .where(Agent.tenant_id == auth.tenant_id)
                .order_by(Agent.created_at)
            )
        ).all()
    return {"items": [agent_dict(agent, index) for index, agent in enumerate(agents)]}


@router.post("/agents", status_code=201)
async def create_agent(
    payload: AgentCreate,
    auth: AuthContext = Depends(require_dashboard("agents.manage")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    permissions = payload.permissions or list(DEFAULT_AGENT_PERMISSIONS)
    unknown = sorted(set(permissions) - KNOWN_PERMISSIONS)
    if unknown:
        raise HTTPException(400, f"Unknown permission: {unknown[0]}")
    validate_scopes(payload.scopes)
    async with runtime.database.session() as session:
        duplicate = await session.scalar(
            select(Agent).where(
                Agent.tenant_id == auth.tenant_id, Agent.name == payload.name
            )
        )
        if duplicate is not None:
            raise HTTPException(409, "An agent with this name already exists")
        agent = Agent(
            tenant_id=auth.tenant_id,
            name=payload.name,
            role=payload.role,
            status="Active",
            permissions=permissions,
            scopes=payload.scopes,
        )
        session.add(agent)
        await session.flush()
        full_key, prefix, key_hash = generate_agent_key(runtime.settings)
        session.add(
            AgentKey(
                tenant_id=auth.tenant_id,
                agent_id=agent.id,
                key_prefix=prefix,
                key_hash=key_hash,
            )
        )
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="agent.created",
            decision="ALLOW",
            summary=f"Created agent {agent.name}",
            details={"agent_id": agent.id, "agent_name": agent.name},
        )
        await session.commit()
        item = agent_dict(agent, 0)
    return {
        "agent": item,
        "api_key": full_key,
        "key_prefix": prefix,
        "message": "Store this key once. It cannot be retrieved again.",
    }


@router.get("/agents/{agent_id}")
async def get_agent(
    agent_id: str,
    auth: AuthContext = Depends(require_dashboard("agents.read")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None or agent.tenant_id != auth.tenant_id:
            raise HTTPException(404, "Agent not found")
        return agent_dict(agent, 0)


@router.patch("/agents/{agent_id}")
async def update_agent(
    agent_id: str,
    payload: AgentUpdate,
    auth: AuthContext = Depends(require_dashboard("agents.manage")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    if payload.permissions is not None:
        unknown = sorted(set(payload.permissions) - KNOWN_PERMISSIONS)
        if unknown:
            raise HTTPException(400, f"Unknown permission: {unknown[0]}")
    if payload.scopes is not None:
        validate_scopes(payload.scopes)
    async with runtime.database.session() as session:
        agent = await session.get(Agent, agent_id, with_for_update=True)
        if agent is None or agent.tenant_id != auth.tenant_id:
            raise HTTPException(404, "Agent not found")
        if payload.name is not None and payload.name != agent.name:
            duplicate = await session.scalar(
                select(Agent).where(
                    Agent.tenant_id == auth.tenant_id,
                    Agent.name == payload.name,
                    Agent.id != agent.id,
                )
            )
            if duplicate is not None:
                raise HTTPException(409, "An agent with this name already exists")
            agent.name = payload.name
        if payload.role is not None:
            agent.role = payload.role
        if payload.status is not None:
            agent.status = payload.status
        if payload.permissions is not None:
            agent.permissions = payload.permissions
        if payload.scopes is not None:
            agent.scopes = payload.scopes
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="agent.updated",
            decision="ALLOW",
            summary=f"Updated agent {agent.name}",
            details={"agent_id": agent.id, "agent_name": agent.name},
        )
        await session.commit()
        return agent_dict(agent, 0)


@router.post("/agents/{agent_id}/rotate-key", response_model=AgentKeyResponse)
async def rotate_agent_key(
    agent_id: str,
    auth: AuthContext = Depends(require_dashboard("agents.manage")),
    request: Request = None,
) -> AgentKeyResponse:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        agent = await session.get(Agent, agent_id, with_for_update=True)
        if agent is None or agent.tenant_id != auth.tenant_id:
            raise HTTPException(404, "Agent not found")
        await session.execute(
            update(AgentKey)
            .where(AgentKey.agent_id == agent.id, AgentKey.active.is_(True))
            .values(active=False, revoked_at=utcnow())
        )
        full_key, prefix, key_hash = generate_agent_key(runtime.settings)
        session.add(
            AgentKey(
                tenant_id=auth.tenant_id,
                agent_id=agent.id,
                key_prefix=prefix,
                key_hash=key_hash,
            )
        )
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="agent.key_rotated",
            decision="ALLOW",
            summary=f"Rotated API key for {agent.name}",
            details={"agent_id": agent.id, "agent_name": agent.name},
        )
        await session.commit()
    return AgentKeyResponse(agent_id=agent_id, api_key=full_key, key_prefix=prefix)


@router.get("/approvals")
async def list_approvals(
    approval_status: str | None = Query(default=None, alias="status"),
    auth: AuthContext = Depends(require_dashboard("approvals.read")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        query = (
            select(Approval, Agent.name)
            .join(Agent, Agent.id == Approval.agent_id)
            .where(Approval.tenant_id == auth.tenant_id)
            .order_by(Approval.created_at.desc())
        )
        if approval_status:
            query = query.where(Approval.status == approval_status)
        rows = (await session.execute(query)).all()
    return {
        "items": [approval_dict(approval, name) for approval, name in rows],
        "pending": sum(1 for approval, _ in rows if approval.status == "Pending"),
    }


@router.get("/approvals/{approval_id}")
async def get_approval(
    approval_id: str,
    auth: AuthContext = Depends(require_dashboard("approvals.read")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        row = (
            await session.execute(
                select(Approval, Agent.name)
                .join(Agent, Agent.id == Approval.agent_id)
                .where(
                    Approval.id == approval_id,
                    Approval.tenant_id == auth.tenant_id,
                )
            )
        ).first()
        if row is None:
            raise HTTPException(404, "Approval not found")
        return approval_dict(row[0], row[1])


@router.post("/approvals/{approval_id}/approve")
async def approve_request(
    approval_id: str,
    payload: ApprovalDecision,
    auth: AuthContext = Depends(require_dashboard("approvals.approve")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        try:
            approval, token = await approve(
                session,
                runtime.settings,
                tenant_id=auth.tenant_id,
                approval_id=approval_id,
                reviewer=auth.principal_id,
                comment=payload.comment,
            )
        except ApprovalError as exc:
            raise HTTPException(exc.status_code, str(exc))
        agent = await session.get(Agent, approval.agent_id)
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="approval.approved",
            decision="ALLOW",
            summary=f"Approved {approval.tool_name} for {agent.name if agent else approval.agent_id}",
            risk=approval.risk_score,
            risk_level="high" if approval.risk_score >= 60 else "medium",
            tool_name=approval.tool_name,
            details={
                "approval_id": approval.id,
                "agent_name": agent.name if agent else approval.agent_id,
                "comment": payload.comment,
            },
        )
        await session.commit()
        item = approval_dict(approval, agent.name if agent else approval.agent_id)
    item["token"] = token
    item["message"] = "This signed token is valid once and bound to the exact action hash."
    return item


@router.post("/approvals/{approval_id}/reject")
async def reject_request(
    approval_id: str,
    payload: ApprovalDecision,
    auth: AuthContext = Depends(require_dashboard("approvals.reject")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        try:
            approval = await reject(
                session,
                tenant_id=auth.tenant_id,
                approval_id=approval_id,
                reviewer=auth.principal_id,
                comment=payload.comment,
            )
        except ApprovalError as exc:
            raise HTTPException(exc.status_code, str(exc))
        agent = await session.get(Agent, approval.agent_id)
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="approval.rejected",
            decision="DENY",
            summary=f"Rejected {approval.tool_name} for {agent.name if agent else approval.agent_id}",
            risk=approval.risk_score,
            risk_level="high" if approval.risk_score >= 60 else "medium",
            tool_name=approval.tool_name,
            details={
                "approval_id": approval.id,
                "agent_name": agent.name if agent else approval.agent_id,
                "comment": payload.comment,
            },
        )
        await session.commit()
        return approval_dict(approval, agent.name if agent else approval.agent_id)


@router.get("/audit")
async def list_audit(
    decision: str | None = None,
    query: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(require_dashboard("audit.read")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    canonical = _canonical_decision(decision)
    async with runtime.database.session() as session:
        events = (
            await session.scalars(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == auth.tenant_id)
                .order_by(AuditEvent.created_at.desc(), AuditEvent.sequence.desc())
            )
        ).all()
    items = [event_summary(event) for event in events]
    if canonical:
        items = [item for item in items if item["decision"] == decision_label(canonical)]
    if query:
        needle = query.lower()
        items = [
            item
            for item in items
            if needle
            in f"{item['agent']} {item['tool']} {item['id']} {item['description']} {item['request_id']}".lower()
        ]
    total = len(items)
    start = (page - 1) * page_size
    return {
        "items": items[start : start + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/audit/verify")
async def verify_audit(
    auth: AuthContext = Depends(require_dashboard("audit.verify")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        result = await runtime.audit.verify(session, auth.tenant_id)
    return result


@router.get("/audit/export")
async def export_audit(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    auth: AuthContext = Depends(require_dashboard("audit.export")),
    request: Request = None,
) -> Response:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        events = (
            await session.scalars(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == auth.tenant_id)
                .order_by(AuditEvent.sequence.asc())
            )
        ).all()
        items = [event_summary(event) for event in events]
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="audit.exported",
            decision="ALLOW",
            summary=f"Exported {len(items)} sanitized audit events",
            details={"format": format, "count": len(items)},
        )
        await session.commit()
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=["id", "sequence", "agent", "tool", "description", "decision", "risk", "time", "request_id"],
        )
        writer.writeheader()
        for item in items:
            writer.writerow({key: item.get(key, "") for key in writer.fieldnames})
        return Response(
            output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=agentshield-audit.csv"},
        )
    import json

    return Response(
        json.dumps(items, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=agentshield-audit.json"},
    )


@router.get("/audit/{event_id}")
async def get_audit_event(
    event_id: str,
    auth: AuthContext = Depends(require_dashboard("audit.read")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        event = await session.get(AuditEvent, event_id)
        if event is None or event.tenant_id != auth.tenant_id:
            raise HTTPException(404, "Event not found")
        return event_summary(event)


@router.get("/quarantine")
async def list_quarantine(
    auth: AuthContext = Depends(require_dashboard("quarantine.read")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        items = (
            await session.scalars(
                select(QuarantineItem)
                .where(
                    QuarantineItem.tenant_id == auth.tenant_id,
                    QuarantineItem.status == "Quarantined",
                )
                .order_by(QuarantineItem.created_at.desc())
            )
        ).all()
    return {"items": [quarantine_dict(item) for item in items]}


@router.post("/quarantine/{item_id}/release")
async def release_quarantine(
    item_id: str,
    payload: QuarantineRelease,
    auth: AuthContext = Depends(require_dashboard("quarantine.manage")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        item = await session.get(QuarantineItem, item_id, with_for_update=True)
        if item is None or item.tenant_id != auth.tenant_id:
            raise HTTPException(404, "Quarantine item not found")
        if item.status != "Quarantined":
            raise HTTPException(409, "Item has already been released")
        item.status = "Released"
        item.released_at = utcnow()
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="quarantine.released",
            decision="ALLOW",
            summary=f"Released quarantine item for {item.tool_name}; no tool was executed",
            details={"quarantine_id": item.id, "comment": payload.comment},
        )
        await session.commit()
        return quarantine_dict(item)


@router.get("/policies")
async def list_policies(
    auth: AuthContext = Depends(require_dashboard("policies.read")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        policies = (
            await session.scalars(
                select(Policy)
                .where(Policy.tenant_id == auth.tenant_id)
                .order_by(Policy.key)
            )
        ).all()
    return {"items": [policy_dict(policy) for policy in policies]}


@router.post("/policies", status_code=201)
async def create_policy(
    payload: PolicyCreate,
    auth: AuthContext = Depends(require_dashboard("policies.manage")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        policy = Policy(
            tenant_id=auth.tenant_id,
            key=f"pol_{uuid.uuid4().hex[:8]}",
            name=payload.name,
            description=payload.description,
            category=payload.category,
            rule=payload.rule,
            version=1,
            active=False,
            immutable=False,
        )
        session.add(policy)
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="policy.created",
            decision="ALLOW",
            summary=f"Created policy draft {policy.name}",
            details={"policy_id": policy.key, "executable": False},
        )
        await session.commit()
    result = policy_dict(policy)
    result["executable"] = False
    result["message"] = "Draft stored. Custom Rego execution is not enabled."
    return result


@router.patch("/policies/{policy_key}")
async def update_policy(
    policy_key: str,
    payload: PolicyUpdate,
    auth: AuthContext = Depends(require_dashboard("policies.manage")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        policy = await session.scalar(
            select(Policy).where(
                Policy.tenant_id == auth.tenant_id, Policy.key == policy_key
            )
        )
        if policy is None:
            raise HTTPException(404, "Policy not found")
        if policy.immutable:
            raise HTTPException(409, "Baseline security policies cannot be disabled")
        policy.active = payload.active
        policy.version += 1
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="policy.updated",
            decision="ALLOW",
            summary=f"{'Activated' if payload.active else 'Deactivated'} draft policy {policy.name}",
            details={"policy_id": policy.key},
        )
        await session.commit()
        return policy_dict(policy)


@router.get("/workspace")
async def get_workspace(
    auth: AuthContext = Depends(require_dashboard("stats.read")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        tenant = await session.get(Tenant, auth.tenant_id)
    if tenant is None:
        raise HTTPException(404, "Workspace not found")
    return {"id": tenant.id, "slug": tenant.slug, "name": tenant.name}


@router.patch("/workspace")
async def update_workspace(
    payload: WorkspaceUpdate,
    auth: AuthContext = Depends(require_dashboard("workspace.manage")),
    request: Request = None,
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        tenant = await session.get(Tenant, auth.tenant_id)
        if tenant is None:
            raise HTTPException(404, "Workspace not found")
        tenant.name = payload.name
        await _dashboard_event(
            runtime,
            session,
            auth,
            action="workspace.updated",
            decision="ALLOW",
            summary=f"Renamed workspace to {payload.name}",
            details={"workspace_id": tenant.id},
        )
        await session.commit()
    return {"id": tenant.id, "slug": tenant.slug, "name": tenant.name}


def _canonical_decision(value: str | None) -> str | None:
    if not value or value.lower() in {"all", "all decisions"}:
        return None
    mapping = {
        "allowed": "ALLOW",
        "blocked": "DENY",
        "approval": "REQUIRE_APPROVAL",
        "quarantined": "QUARANTINE",
        "redacted": "REDACT",
    }
    upper = value.upper()
    if upper in mapping.values():
        return upper
    return mapping.get(value.lower())


def validate_scopes(scopes: dict[str, Any]) -> None:
    list_fields = {
        "allowed_paths",
        "allowed_domains",
        "allowed_merchants",
        "allowed_env",
        "allowed_system_paths",
        "allowed_servers",
    }
    for key in list_fields:
        if key in scopes and (
            not isinstance(scopes[key], list)
            or not all(isinstance(item, str) for item in scopes[key])
        ):
            raise HTTPException(422, f"{key} must be an array of strings")
    if "payment_budget" in scopes:
        try:
            budget = float(scopes["payment_budget"])
        except (TypeError, ValueError):
            raise HTTPException(422, "payment_budget must be numeric")
        if budget < 0 or budget > 1_000_000:
            raise HTTPException(422, "payment_budget is out of range")
