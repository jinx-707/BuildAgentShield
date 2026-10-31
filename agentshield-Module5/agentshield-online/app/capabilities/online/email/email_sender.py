"""
Email sender — handles the full 12-step outgoing email security pipeline:
1. Agent permission check
2. Recipient validation
3. Sender account validation
4. Attachment validation
5. Sensitive data inspection
6. Content inspection
7. Domain policy verification
8. Human approval
9. Exact-action binding
10. Send operation
11. Result verification
12. Audit recording
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from app.capabilities.online.email.email_policy import EmailPolicy
from app.capabilities.online.email.recipient_validator import (
    validate_recipients,
    validate_sender,
)
from app.core.exceptions import (
    ApprovalInvalidError,
    EmailDLPViolationError,
    EmailSendDeniedError,
    UnauthorizedRecipientError,
)
from app.core.result_models import EmailSendResult
from app.integrations.ports import (
    ApprovalPort,
    ApprovalRequest,
    AuditEvent,
    AuditPort,
    ContentInspectionPort,
    DataInspectionPort,
)

logger = logging.getLogger(__name__)


def compute_email_hash(
    sender: str,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    body: str,
    attachment_hashes: list[str],
) -> str:
    """
    Canonical SHA-256 fingerprint of an email.
    Used for exact-action approval binding.
    If ANY field changes, the hash changes and approval is invalidated.
    """
    canonical = json.dumps(
        {
            "sender": sender.lower().strip(),
            "to": sorted([r.lower().strip() for r in to]),
            "cc": sorted([r.lower().strip() for r in cc]),
            "bcc": sorted([r.lower().strip() for r in bcc]),
            "subject": subject.strip(),
            "body": body.strip(),
            "attachment_hashes": sorted(attachment_hashes),
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class EmailSender:
    """Implements the full outgoing email security pipeline."""

    def __init__(
        self,
        policy: EmailPolicy,
        data_inspector: DataInspectionPort,
        content_inspector: ContentInspectionPort,
        approval: ApprovalPort,
        audit: AuditPort,
    ) -> None:
        self._policy = policy
        self._data_inspector = data_inspector
        self._content_inspector = content_inspector
        self._approval = approval
        self._audit = audit

    async def validate_and_request_approval(
        self,
        agent_id: str,
        tenant_id: str,
        sender: str,
        to: list[str],
        subject: str,
        body: str,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachment_hashes: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Run steps 1–9: validate, inspect, and request approval.
        Returns {"approval_request_id": ..., "action_hash": ...}
        """
        cc = cc or []
        bcc = bcc or []
        attachment_hashes = attachment_hashes or []

        # Step 1: Validate sender
        if not validate_sender(sender, self._policy):
            raise EmailSendDeniedError(
                f"Sender '{sender}' is not in the allowed sender list."
            )

        # Step 2: Validate recipients
        validate_recipients(to, cc, bcc, self._policy)

        # Step 3: Sensitive data inspection (DLP)
        if self._policy.dlp_enabled:
            full_content = f"To: {to}\nSubject: {subject}\n\n{body}"
            dlp_result = await self._data_inspector.inspect(
                content=full_content,
                metadata={"sender": sender, "recipients": to},
            )
            if not dlp_result.safe_to_use:
                raise EmailDLPViolationError(
                    f"Email blocked by DLP: {dlp_result.summary}"
                )

        # Step 4: Content inspection
        content_result = await self._content_inspector.inspect(
            content=body,
            source="email_outgoing",
            metadata={"sender": sender, "subject": subject},
        )
        if not content_result.safe_to_use:
            raise EmailSendDeniedError(
                f"Email body blocked by content inspection: {content_result.summary}"
            )

        # Step 5: Compute exact-action hash
        action_hash = compute_email_hash(
            sender=sender,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            attachment_hashes=attachment_hashes,
        )

        # Step 6: Request approval
        ticket = await self._approval.request_approval(
            ApprovalRequest(
                action_type="email_send",
                agent_id=agent_id,
                tenant_id=tenant_id,
                action_hash=action_hash,
                action_summary=f"Send email to {to} — subject: {subject[:50]}",
                action_details={
                    "sender": sender,
                    "to": to,
                    "cc": cc,
                    "bcc": bcc,
                    "subject": subject,
                    "body_preview": body[:200],
                },
                expires_seconds=self._policy.approval_expires_seconds,
            )
        )

        return {
            "approval_request_id": ticket.approval_request_id,
            "action_hash": action_hash,
        }

    async def execute_send(
        self,
        approval_id: str,
        action_hash: str,
        send_fn: Any,  # async callable that actually sends
        agent_id: str,
        tenant_id: str,
        request_id: str,
    ) -> EmailSendResult:
        """
        Step 9–12: Verify approval, send, audit.
        send_fn must be the actual send callable (GmailClient.send_message etc.)
        """
        # Verify approval is still valid and matches exact hash
        verification = await self._approval.verify_approval(
            approval_id=approval_id,
            action_hash=action_hash,
        )
        if not verification.valid:
            await self._audit.record(AuditEvent(
                event_type="EMAIL_SEND_APPROVAL_INVALID",
                agent_id=agent_id,
                tenant_id=tenant_id,
                capability="email",
                operation="send",
                decision="DENY",
                status="BLOCKED",
                request_id=request_id,
                reason=verification.reason,
            ))
            raise ApprovalInvalidError(
                f"Email send approval invalid: {verification.reason}"
            )

        # Execute the send
        result: EmailSendResult = await send_fn()

        # Audit record
        await self._audit.record(AuditEvent(
            event_type="EMAIL_SENT",
            agent_id=agent_id,
            tenant_id=tenant_id,
            capability="email",
            operation="send",
            decision="ALLOW",
            status="EXECUTED",
            request_id=request_id,
            metadata={"message_id": result.message_id},
        ))

        return result
