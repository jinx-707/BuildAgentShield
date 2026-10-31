"""Email forwarder service: Egress verification, deep content inspection, and secure forwarding."""

from datetime import datetime, timezone
import logging
from uuid import UUID
from app.database.repository import OAuthAccountRepository
from app.integrations.approval_client import (
    BaseApprovalClient,
    calculate_canonical_content_hash,
)
from app.providers.base import BaseEmailProvider
from app.providers.gmail.client import GmailClient
from app.providers.gmail.message_parser import GmailMessageParser
from app.schemas.email import EmailForwardRequest, EmailForwardResponse
from app.schemas.security import SecurityContext
from app.security.message_policy import (
    HumanApprovalRequiredError,
    MessagePolicyCoordinator,
    SecurityPolicyEnforcementError,
)

logger = logging.getLogger("agentshield.services.forwarder")


class EmailForwarderService:
    """Manages email forwarding with recipient validation, original email inspection, and approval binding."""

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

        allowed_send_scopes = [
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://mail.google.com/",
        ]
        self.policy_coordinator.enforce_scope(account.granted_scopes, allowed_send_scopes, "forward")

        access_token, refresh_token = self.account_repo.get_decrypted_tokens(account)
        if account.provider == "google":
            return GmailClient(access_token=access_token, refresh_token=refresh_token)
        else:
            from app.providers.microsoft.client import MicrosoftGraphClient
            return MicrosoftGraphClient(access_token=access_token, refresh_token=refresh_token)

    async def forward_email(
        self, context: SecurityContext, forward_req: EmailForwardRequest
    ) -> EmailForwardResponse:
        """Validate destination, inspect both original and forwarded content, evaluate policy, and forward email."""
        provider = await self._resolve_provider(context, forward_req.account_id)

        # 1. Fetch original email to inspect content before forwarding
        orig_raw = await provider.get_message(forward_req.original_message_id)
        parsed_orig = GmailMessageParser.to_email_message(orig_raw)

        # 2. Recipient validation on new forwarding destinations
        all_recipients = forward_req.to + forward_req.cc
        recip_result = self.policy_coordinator.recipient_validator.validate_recipients(all_recipients)
        if not recip_result.is_valid:
            await self.policy_coordinator.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_FORWARD_ATTEMPTED",
                status="BLOCKED",
                metadata={"reason": "Invalid recipients", "invalid": recip_result.invalid_recipients},
                account_id=forward_req.account_id,
            )
            raise SecurityPolicyEnforcementError(
                f"Forward recipient validation failed: {'; '.join(recip_result.reasons)}",
                policy_id="INVALID_RECIPIENT",
            )

        # 3. Deep DLP scan on both original content and forwarding comment
        combined_forward_body = (
            f"{forward_req.additional_comment or ''}\n"
            f"--- Forwarded message ---\n"
            f"Subject: {parsed_orig.subject}\n"
            f"{parsed_orig.body_text or parsed_orig.snippet}"
        )
        forward_subject = f"Fwd: {parsed_orig.subject}"

        local_dlp = self.policy_coordinator.content_classifier.classify_outgoing_content(
            subject=forward_subject,
            body_text=combined_forward_body,
        )
        if not local_dlp.safe:
            await self.policy_coordinator.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_FORWARD_ATTEMPTED",
                status="BLOCKED",
                metadata={"flags": local_dlp.flags, "pii": local_dlp.pii_detected},
                account_id=forward_req.account_id,
            )
            raise SecurityPolicyEnforcementError(
                f"Forwarded content contains confidential data: {', '.join(local_dlp.flags)}",
                policy_id="DLP_DATA_LEAKAGE",
            )

        # 4. Human approval verification if pre-granted
        content_hash = calculate_canonical_content_hash(forward_subject, combined_forward_body)
        recip_emails = [r.email for r in forward_req.to + forward_req.cc]

        if forward_req.approval_id and self.approval_client:
            valid, msg = await self.approval_client.verify_and_consume(
                approval_id=forward_req.approval_id,
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                account_id=forward_req.account_id,
                action_type="forward",
                content_hash=content_hash,
                attachment_hashes=[],
                recipients=recip_emails,
            )
            if not valid:
                raise SecurityPolicyEnforcementError(
                    f"Approval verification failed for forward: {msg}", policy_id="INVALID_APPROVAL"
                )

        # 5. Policy authorization
        decision = await self.policy_coordinator.policy_client.authorize_forward(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            account_id=forward_req.account_id,
            forward_request=forward_req,
        )

        if decision.requires_human_approval and not forward_req.approval_id:
            approval_record = await self.approval_client.request_approval(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                account_id=forward_req.account_id,
                action_type="forward",
                target_resource=f"message:{forward_req.original_message_id}",
                subject=forward_subject,
                recipients=recip_emails,
                content_hash=content_hash,
                attachment_hashes=[],
                reason=decision.reason or "Forwarding sensitive email requires human approval",
                payload_summary={"recipients": recip_emails, "original_message_id": forward_req.original_message_id},
            )
            await self.policy_coordinator.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_APPROVAL_REQUIRED",
                status="FLAGGED",
                metadata={"approval_id": str(approval_record.approval_id), "reason": decision.reason},
                account_id=forward_req.account_id,
                policy_decision_id=decision.policy_id,
            )
            raise HumanApprovalRequiredError(
                "Forwarding held for human authorization", approval_id=str(approval_record.approval_id)
            )

        if not decision.allowed:
            await self.policy_coordinator.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_FORWARD_ATTEMPTED",
                status="BLOCKED",
                metadata={"reason": decision.reason},
                account_id=forward_req.account_id,
                policy_decision_id=decision.policy_id,
            )
            raise SecurityPolicyEnforcementError(
                decision.reason or "Forward action unauthorized by policy",
                policy_id=decision.policy_id or "FORWARD_DISALLOWED",
            )

        # 6. Provider execution
        raw_result = await provider.forward_email(
            original_message_id=forward_req.original_message_id,
            to=[r.email for r in forward_req.to],
            cc=[r.email for r in forward_req.cc],
            additional_comment=forward_req.additional_comment,
            forward_attachments=forward_req.forward_attachments,
        )

        sent_id = raw_result.get("id", "forwarded-message")

        await self.policy_coordinator.audit_client.record_event(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            event_type="EMAIL_FORWARD_ATTEMPTED",
            status="ALLOWED",
            metadata={
                "original_message_id": forward_req.original_message_id,
                "forwarded_to": recip_emails,
            },
            account_id=forward_req.account_id,
            policy_decision_id=decision.policy_id,
        )

        return EmailForwardResponse(
            message_id=sent_id,
            account_id=forward_req.account_id,
            forwarded_to=recip_emails,
            status="forwarded",
            sent_at=datetime.now(timezone.utc),
        )
