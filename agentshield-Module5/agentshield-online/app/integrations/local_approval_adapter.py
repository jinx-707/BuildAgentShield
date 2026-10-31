"""
LOCAL DEVELOPMENT ONLY — Approval Adapter.

IMPORTANT: This adapter requires an EXPLICIT test approval token.
It does NOT auto-approve dangerous actions.

To approve an action in tests, call:
    LocalApprovalAdapter.grant_test_approval(approval_request_id)

This simulates a human approver without building a full approval UI.
Replace with Person 4's approval workflow in production.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

from app.integrations.ports import (
    ApprovalPort,
    ApprovalRequest,
    ApprovalTicket,
    ApprovalVerification,
)

logger = logging.getLogger(__name__)


class LocalApprovalAdapter(ApprovalPort):
    """
    Development approval adapter.

    - Pending approvals stored in-memory (do NOT use in production).
    - Requires explicit grant via grant_test_approval().
    - Each approval is single-use.
    - Approvals expire after `expires_seconds`.
    """

    def __init__(self) -> None:
        # approval_id -> {"request": ApprovalRequest, "status": str, "expires_at": datetime, "consumed": bool}
        self._store: dict[str, dict[str, Any]] = {}

    async def request_approval(self, action: ApprovalRequest) -> ApprovalTicket:
        approval_id = f"appr_{uuid.uuid4().hex[:16]}"
        expires_at = datetime.utcnow() + timedelta(seconds=action.expires_seconds)

        self._store[approval_id] = {
            "request": action,
            "status": "pending",
            "expires_at": expires_at,
            "consumed": False,
        }

        logger.info(
            "[LOCAL APPROVAL] Pending approval created: id=%s action=%s agent=%s",
            approval_id,
            action.action_type,
            action.agent_id,
        )
        logger.info(
            "[LOCAL APPROVAL] To approve in tests call: "
            "adapter.grant_test_approval('%s')",
            approval_id,
        )

        return ApprovalTicket(
            approval_request_id=approval_id,
            status="pending",
            expires_at=expires_at,
        )

    async def verify_approval(
        self,
        approval_id: str,
        action_hash: str,
    ) -> ApprovalVerification:
        record = self._store.get(approval_id)

        if not record:
            return ApprovalVerification(
                valid=False,
                consumed=False,
                reason="Approval ID not found",
            )

        if record["consumed"]:
            return ApprovalVerification(
                valid=False,
                consumed=True,
                reason="Approval already consumed (single-use)",
            )

        if datetime.utcnow() > record["expires_at"]:
            record["status"] = "expired"
            return ApprovalVerification(
                valid=False,
                consumed=False,
                reason="Approval expired",
            )

        if record["status"] != "approved":
            return ApprovalVerification(
                valid=False,
                consumed=False,
                reason=f"Approval status is '{record['status']}', not 'approved'",
            )

        # Verify the action hash matches what was approved
        stored_hash = record["request"].action_hash
        if not hmac.compare_digest(stored_hash.encode(), action_hash.encode()):
            logger.warning(
                "[LOCAL APPROVAL] Hash mismatch! stored=%s provided=%s",
                stored_hash[:16],
                action_hash[:16],
            )
            return ApprovalVerification(
                valid=False,
                consumed=False,
                reason="Action hash mismatch — transaction details changed after approval",
            )

        # Consume the approval (single-use)
        record["consumed"] = True
        record["status"] = "consumed"

        return ApprovalVerification(
            valid=True,
            consumed=True,
            reason="Approval valid and consumed",
        )

    def grant_test_approval(self, approval_id: str) -> bool:
        """
        Test helper: simulate a human approving the action.
        Only for use in tests and local development.
        """
        record = self._store.get(approval_id)
        if not record:
            logger.error("[LOCAL APPROVAL] grant_test_approval: unknown id=%s", approval_id)
            return False
        if datetime.utcnow() > record["expires_at"]:
            logger.error("[LOCAL APPROVAL] grant_test_approval: expired id=%s", approval_id)
            return False
        record["status"] = "approved"
        logger.info("[LOCAL APPROVAL] Test approval granted: id=%s", approval_id)
        return True

    def deny_test_approval(self, approval_id: str) -> bool:
        """Test helper: simulate a human denying the action."""
        record = self._store.get(approval_id)
        if not record:
            return False
        record["status"] = "denied"
        return True

    def get_pending_approvals(self) -> list[dict[str, Any]]:
        """Test helper: list all pending approvals."""
        return [
            {
                "approval_id": aid,
                "action_type": rec["request"].action_type,
                "agent_id": rec["request"].agent_id,
                "status": rec["status"],
                "expires_at": rec["expires_at"].isoformat(),
            }
            for aid, rec in self._store.items()
            if rec["status"] == "pending"
        ]
