"""Development mock implementation of ApprovalClient.

WARNING:
This mock is for local development and test suites ONLY.
It DOES NOT provide production human approval workflows and must NEVER be used in production.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4
from app.integrations.approval_client import BaseApprovalClient
from app.schemas.approval import ApprovalResponse, ApprovalStatus

logger = logging.getLogger("agentshield.mocks.approval")


class MockApprovalClient(BaseApprovalClient):
    """Development mock approval client with in-memory storage."""

    IS_DEVELOPMENT_MOCK: bool = True

    def __init__(self, auto_approve: bool = False):
        logger.warning(
            "*** SECURITY WARNING: MockApprovalClient ACTIVE. THIS IS A TEST MOCK ONLY. ***"
        )
        self.auto_approve = auto_approve
        self.approvals: Dict[UUID, Dict[str, Any]] = {}

    async def request_approval(
        self,
        tenant_id: str,
        agent_id: str,
        account_id: UUID,
        action_type: str,
        target_resource: str,
        subject: str,
        recipients: List[str],
        content_hash: str,
        attachment_hashes: List[str],
        reason: str,
        payload_summary: Dict[str, Any],
        ttl_hours: int = 24,
    ) -> ApprovalResponse:
        approval_id = uuid4()
        status = ApprovalStatus.APPROVED if self.auto_approve else ApprovalStatus.PENDING
        record = {
            "approval_id": approval_id,
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "account_id": account_id,
            "action_type": action_type,
            "target_resource": target_resource,
            "subject": subject,
            "recipients": [r.lower() for r in recipients],
            "content_hash": content_hash,
            "attachment_hashes": attachment_hashes,
            "status": status,
            "reason": reason,
            "payload_summary": payload_summary,
            "approved_by": "mock-admin" if self.auto_approve else None,
            "used": False,
        }
        self.approvals[approval_id] = record
        return ApprovalResponse(
            approval_id=approval_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            account_id=account_id,
            action_type=action_type,
            status=status,
            subject=subject,
            recipients=recipients,
            content_hash_sha256=content_hash,
            attachment_hashes_sha256=attachment_hashes,
            reason=reason,
            approved_by=record["approved_by"],
            created_at=record.get("created_at") or None,
            expires_at=None,
            used=False,
        )

    async def get_approval(
        self, approval_id: UUID, tenant_id: str, agent_id: str
    ) -> Optional[ApprovalResponse]:
        record = self.approvals.get(approval_id)
        if not record:
            return None
        if record["tenant_id"] != tenant_id or record["agent_id"] != agent_id:
            return None
        return ApprovalResponse(
            approval_id=record["approval_id"],
            tenant_id=record["tenant_id"],
            agent_id=record["agent_id"],
            account_id=record.get("account_id"),
            action_type=record["action_type"],
            status=record["status"],
            subject=record.get("subject"),
            recipients=record.get("recipients", []),
            content_hash_sha256=record.get("content_hash"),
            attachment_hashes_sha256=record.get("attachment_hashes", []),
            reason=record["reason"],
            approved_by=record.get("approved_by"),
            created_at=record.get("created_at") or None,
            expires_at=None,
            used=record.get("used", False),
        )

    async def verify_and_consume(
        self,
        approval_id: UUID,
        tenant_id: str,
        agent_id: str,
        account_id: UUID,
        action_type: str,
        content_hash: str,
        attachment_hashes: List[str],
        recipients: List[str],
    ) -> Tuple[bool, str]:
        record = self.approvals.get(approval_id)
        if not record:
            return False, "Approval not found"
        if record["tenant_id"] != tenant_id or record["agent_id"] != agent_id:
            return False, "Approval does not belong to caller context"
        if record.get("used"):
            return False, "Approval has already been consumed (replay attempt)"
        if record["status"] != ApprovalStatus.APPROVED:
            return False, f"Approval is not approved (status: {record['status']})"
        if record.get("content_hash") and record["content_hash"] != content_hash:
            return False, "Content modified after approval"
        if set(r.lower() for r in recipients) != set(record.get("recipients", [])):
            return False, "Recipients modified after approval"

        record["used"] = True
        record["status"] = ApprovalStatus.USED
        return True, "Approval consumed"

