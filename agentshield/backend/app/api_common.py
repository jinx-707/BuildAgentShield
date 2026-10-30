from __future__ import annotations

from datetime import timezone
from typing import Any

from .approvals import ensure_aware
from .db import Agent, Approval, Policy, QuarantineItem, utcnow


COLORS = ["violet", "blue", "green", "amber", "pink", "blue", "violet"]


def agent_dict(agent: Agent, index: int = 0) -> dict[str, Any]:
    parts = agent.name.replace("_", "-").split("-")
    initials = "".join(part[:1] for part in parts[:2]).upper() or agent.name[:2].upper()
    return {
        "id": agent.id,
        "name": agent.name,
        "role": agent.role,
        "status": agent.status,
        "requests": agent.request_count,
        "initials": initials,
        "color": COLORS[index % len(COLORS)],
        "permissions": list(agent.permissions),
        "scopes": dict(agent.scopes),
        "created_at": ensure_aware(agent.created_at).isoformat(),
    }


def expiry_label(approval: Approval) -> str:
    remaining = (ensure_aware(approval.expires_at) - utcnow()).total_seconds()
    if approval.status != "Pending" or remaining <= 0:
        return approval.status if approval.status != "Pending" else "Expired"
    minutes = max(1, int(remaining // 60))
    return f"{minutes} minutes"


def approval_dict(approval: Approval, agent_name: str) -> dict[str, Any]:
    return {
        "id": approval.id,
        "agent": agent_name,
        "agent_id": approval.agent_id,
        "tool": approval.tool_name,
        "summary": approval.action_summary,
        "args": approval.arguments_snapshot,
        "risk": approval.risk_score,
        "expires": expiry_label(approval),
        "status": approval.status,
        "action_hash": approval.action_hash,
        "reason": approval.reason,
        "reviewed_by": approval.reviewed_by,
        "review_comment": approval.review_comment,
        "created_at": ensure_aware(approval.created_at).isoformat(),
        "expires_at": ensure_aware(approval.expires_at).isoformat(),
        "consumed": approval.consumed_at is not None,
    }


def policy_dict(policy: Policy) -> dict[str, Any]:
    return {
        "id": policy.key,
        "name": policy.name,
        "description": policy.description,
        "category": policy.category,
        "version": policy.version,
        "active": policy.active,
        "rule": policy.rule,
        "immutable": policy.immutable,
        "updated_at": ensure_aware(policy.updated_at).isoformat(),
    }


def quarantine_dict(item: QuarantineItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "agent_id": item.agent_id,
        "tool": item.tool_name,
        "reason": item.reason,
        "preview": item.content_preview,
        "status": item.status,
        "created_at": ensure_aware(item.created_at).isoformat(),
        "released_at": ensure_aware(item.released_at).isoformat()
        if item.released_at
        else None,
    }


def utc_iso(value) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()
