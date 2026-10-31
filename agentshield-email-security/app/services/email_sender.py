"""Email sender service: Strict egress security, human approval binding, and delivery."""

import base64
from datetime import datetime, timezone
import hashlib
import logging
from uuid import UUID
from app.database.repository import OAuthAccountRepository
from app.integrations.approval_client import (
    BaseApprovalClient,
    calculate_attachment_hashes,
    calculate_canonical_content_hash,
)
from app.providers.base import BaseEmailProvider
from app.providers.gmail.client import GmailClient
from app.providers.gmail.message_parser import GmailMessageParser
from app.schemas.email import EmailAddress, EmailSendRequest, EmailSendResponse
from app.schemas.security import SecurityContext
from app.security.message_policy import (
    HumanApprovalRequiredError,
    MessagePolicyCoordinator,
    SecurityPolicyEnforcementError,
)

logger = logging.getLogger("agentshield.services.sender")


class EmailSenderService:
    """Orchestrates outbound email transmission through comprehensive egress controls."""

    def __init__(
        self,
        account_repo: OAuthAccountRepository,
        policy_coordinator: MessagePolicyCoordinator,
        approval_client: BaseApprovalClient = None,
    ):
        self.account_repo = account_repo
        self.policy_coordinator = policy_coordinator
        self.approval_client = approval_client or policy_coordinator.approval_client

    async def _resolve_provider(
        self, context: SecurityContext, account_id: UUID
    ) -> BaseEmailProvider:
        account = await self.account_repo.get_account(
            account_id, context.tenant_id, context.agent_id
        )
        if not account or account.status != "active":
            raise ValueError(f"Account {account_id} not found or inactive for caller")

        # Scope enforcement
        allowed_send_scopes = [
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://mail.google.com/",
        ]
        self.policy_coordinator.enforce_scope(account.granted_scopes, allowed_send_scopes, "send")

        access_token, refresh_token = self.account_repo.get_decrypted_tokens(account)
        if account.provider == "google":
            return GmailClient(access_token=access_token, refresh_token=refresh_token)
        else:
            from app.providers.microsoft.client import MicrosoftGraphClient
            return MicrosoftGraphClient(access_token=access_token, refresh_token=refresh_token)

    async def send_email(
        self, context: SecurityContext, send_req: EmailSendRequest
    ) -> EmailSendResponse:
        """Validate, authorize, and transmit outbound email (new message or draft)."""
        provider = await self._resolve_provider(context, send_req.account_id)

        # 1. If sending an existing draft, fetch draft content to perform egress checks
        is_sending_draft = bool(send_req.draft_id)
        if is_sending_draft:
            raw_draft = await provider.get_draft(send_req.draft_id)
            msg_payload = raw_draft.get("message", {})
            parsed_draft = GmailMessageParser.to_email_message(msg_payload)

            # Reconcile send request with draft content
            send_req.subject = send_req.subject or parsed_draft.subject
            send_req.to = send_req.to or parsed_draft.to
            send_req.cc = send_req.cc or parsed_draft.cc
            send_req.bcc = send_req.bcc or parsed_draft.bcc
            send_req.body_text = send_req.body_text or parsed_draft.body_text or ""
            send_req.body_html = send_req.body_html or parsed_draft.body_html

        # Ensure mandatory fields are present
        if not send_req.to:
            raise SecurityPolicyEnforcementError("Recipient list cannot be empty", policy_id="INVALID_RECIPIENT")
        if not send_req.subject and not send_req.body_text:
            raise SecurityPolicyEnforcementError("Subject and body cannot both be empty", policy_id="EMPTY_PAYLOAD")

        # 2. Multi-layered validation and policy authorization
        decision = await self.policy_coordinator.validate_and_authorize_send(
            context=context, account_id=send_req.account_id, send_request=send_req
        )

        # 3. Handle human approval requirement if policy indicates human sign-off needed
        if decision.requires_human_approval and not send_req.approval_id:
            content_hash = calculate_canonical_content_hash(send_req.subject or "", send_req.body_text or "")
            att_hashes = calculate_attachment_hashes(send_req.attachments)
            recip_emails = [r.email for r in (send_req.to or []) + send_req.cc + send_req.bcc]

            approval_record = await self.approval_client.request_approval(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                account_id=send_req.account_id,
                action_type="send",
                target_resource=f"account:{send_req.account_id}",
                subject=send_req.subject or "",
                recipients=recip_emails,
                content_hash=content_hash,
                attachment_hashes=att_hashes,
                reason=decision.reason or "High risk outbound action requires human approval",
                payload_summary={
                    "to": recip_emails,
                    "subject": send_req.subject,
                    "attachment_count": len(send_req.attachments),
                },
            )

            await self.policy_coordinator.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_APPROVAL_REQUIRED",
                status="FLAGGED",
                metadata={"approval_id": str(approval_record.approval_id), "reason": decision.reason},
                account_id=send_req.account_id,
                policy_decision_id=decision.policy_id,
            )

            raise HumanApprovalRequiredError(
                "Action held for human authorization", approval_id=str(approval_record.approval_id)
            )

        # 4. Execute outbound transmission via provider
        if is_sending_draft:
            raw_result = await provider.send_draft(send_req.draft_id)
            sent_msg_id = raw_result.get("id", "draft-sent")
            thread_id = raw_result.get("threadId")
        else:
            raw_result = await provider.send_email(
                to=[r.email for r in send_req.to],
                cc=[r.email for r in send_req.cc],
                bcc=[r.email for r in send_req.bcc],
                subject=send_req.subject or "",
                body_text=send_req.body_text or "",
                body_html=send_req.body_html,
                thread_id=send_req.thread_id,
                attachments=[att.model_dump() for att in send_req.attachments],
            )
            sent_msg_id = raw_result.get("id", "sent-message")
            thread_id = raw_result.get("threadId")

        # 5. Record immutable audit entry
        await self.policy_coordinator.audit_client.record_event(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            event_type="EMAIL_SENT",
            status="ALLOWED",
            metadata={
                "message_id": sent_msg_id,
                "recipients_count": len(send_req.to),
                "attachments_count": len(send_req.attachments),
                "draft_id": send_req.draft_id,
            },
            account_id=send_req.account_id,
            policy_decision_id=decision.policy_id,
        )

        return EmailSendResponse(
            message_id=sent_msg_id,
            thread_id=thread_id,
            account_id=send_req.account_id,
            sent_at=datetime.now(timezone.utc),
            status="sent",
        )
