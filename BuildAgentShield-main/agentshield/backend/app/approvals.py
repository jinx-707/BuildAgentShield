from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .contracts import ToolRequest, action_hash
from .db import Approval, utcnow
from .security import preview, sanitize_dict, sign_approval_token


class ApprovalError(ValueError):
    def __init__(self, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.status_code = status_code


def ensure_aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def approval_expired(approval: Approval) -> bool:
    return ensure_aware(approval.expires_at) <= utcnow()


def approval_summary(tool_name: str, arguments: dict[str, Any]) -> str:
    safe = sanitize_dict(arguments)
    return f"{tool_name} {preview(safe, 420)}"[:500]


async def find_or_create_approval(
    session: AsyncSession,
    settings: Settings,
    *,
    tenant_id: str,
    agent_id: str,
    request: ToolRequest,
    risk_score: int,
    reason: str,
) -> Approval:
    digest = action_hash(request.tool_name, request.arguments)
    result = await session.execute(
        select(Approval)
        .where(
            Approval.tenant_id == tenant_id,
            Approval.agent_id == agent_id,
            Approval.tool_name == request.tool_name,
            Approval.action_hash == digest,
            Approval.status == "Pending",
        )
        .order_by(Approval.created_at.desc())
    )
    existing = result.scalars().first()
    if existing is not None and not approval_expired(existing):
        return existing
    approval = Approval(
        tenant_id=tenant_id,
        agent_id=agent_id,
        tool_name=request.tool_name,
        arguments_snapshot=sanitize_dict(request.arguments),
        action_hash=digest,
        action_summary=approval_summary(request.tool_name, request.arguments),
        risk_score=risk_score,
        status="Pending",
        reason=reason,
        requested_by=request.request_id,
        expires_at=utcnow() + timedelta(minutes=settings.approval_ttl_minutes),
    )
    session.add(approval)
    await session.flush()
    return approval


async def approve(
    session: AsyncSession,
    settings: Settings,
    *,
    tenant_id: str,
    approval_id: str,
    reviewer: str,
    comment: str,
) -> tuple[Approval, str]:
    approval = await session.get(Approval, approval_id, with_for_update=True)
    if approval is None or approval.tenant_id != tenant_id:
        raise ApprovalError("Approval not found", 404)
    if approval.status != "Pending":
        raise ApprovalError("Only pending approvals can be approved")
    if approval_expired(approval):
        raise ApprovalError("Approval has expired")
    nonce = secrets.token_urlsafe(18)
    token = sign_approval_token(
        settings,
        approval_id=approval.id,
        action_hash=approval.action_hash,
        nonce=nonce,
        expires_at=ensure_aware(approval.expires_at),
    )
    approval.status = "Approved"
    approval.reviewed_by = reviewer
    approval.review_comment = comment
    approval.reviewed_at = utcnow()
    approval.nonce = nonce
    approval.token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    await session.flush()
    return approval, token


async def reject(
    session: AsyncSession,
    *,
    tenant_id: str,
    approval_id: str,
    reviewer: str,
    comment: str,
) -> Approval:
    approval = await session.get(Approval, approval_id, with_for_update=True)
    if approval is None or approval.tenant_id != tenant_id:
        raise ApprovalError("Approval not found", 404)
    if approval.status != "Pending":
        raise ApprovalError("Only pending approvals can be rejected")
    approval.status = "Rejected"
    approval.reviewed_by = reviewer
    approval.review_comment = comment
    approval.reviewed_at = utcnow()
    await session.flush()
    return approval
