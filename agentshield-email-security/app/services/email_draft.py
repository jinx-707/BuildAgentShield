"""Email draft service: Pre-send validation, DLP inspection, and draft lifecycle management."""

from datetime import datetime, timezone
import logging
from uuid import UUID
from app.database.repository import OAuthAccountRepository
from app.providers.base import BaseEmailProvider
from app.providers.gmail.client import GmailClient
from app.providers.gmail.message_parser import GmailMessageParser
from app.schemas.email import (
    EmailAddress,
    EmailDraftRequest,
    EmailDraftResponse,
    EmailDraftUpdateRequest,
)
from app.schemas.security import SecurityContext
from app.security.message_policy import MessagePolicyCoordinator, SecurityPolicyEnforcementError

logger = logging.getLogger("agentshield.services.draft")


class EmailDraftService:
    """Manages email draft creation, updating, and retrieval with outbound DLP analysis."""

    def __init__(
        self,
        account_repo: OAuthAccountRepository,
        policy_coordinator: MessagePolicyCoordinator,
    ):
        self.account_repo = account_repo
        self.policy_coordinator = policy_coordinator

    async def _resolve_provider(
        self, context: SecurityContext, account_id: UUID
    ) -> BaseEmailProvider:
        account = await self.account_repo.get_account(
            account_id, context.tenant_id, context.agent_id
        )
        if not account or account.status != "active":
            raise ValueError(f"Account {account_id} not found or inactive for caller")

        # Check required OAuth compose/modify scope
        allowed_compose_scopes = [
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://mail.google.com/",
        ]
        self.policy_coordinator.enforce_scope(
            account.granted_scopes, allowed_compose_scopes, "draft"
        )

        access_token, refresh_token = self.account_repo.get_decrypted_tokens(account)
        if account.provider == "google":
            return GmailClient(access_token=access_token, refresh_token=refresh_token)
        else:
            from app.providers.microsoft.client import MicrosoftGraphClient
            return MicrosoftGraphClient(access_token=access_token, refresh_token=refresh_token)

    async def create_draft(
        self, context: SecurityContext, draft_req: EmailDraftRequest
    ) -> EmailDraftResponse:
        """Create draft after validating recipients, content DLP, and policy authorization."""
        # Policy & DLP verification
        decision = await self.policy_coordinator.validate_and_authorize_draft(
            context=context, account_id=draft_req.account_id, draft_request=draft_req
        )

        provider = await self._resolve_provider(context, draft_req.account_id)
        raw_draft = await provider.create_draft(
            to=[r.email for r in draft_req.to],
            cc=[r.email for r in draft_req.cc],
            bcc=[r.email for r in draft_req.bcc],
            subject=draft_req.subject,
            body_text=draft_req.body_text,
            body_html=draft_req.body_html,
            thread_id=draft_req.thread_id,
        )

        draft_id = raw_draft.get("id", "draft-created")
        message_info = raw_draft.get("message", {})
        message_id = message_info.get("id")

        await self.policy_coordinator.audit_client.record_event(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            event_type="EMAIL_DRAFT_CREATED",
            status="ALLOWED",
            metadata={
                "draft_id": draft_id,
                "recipients_count": len(draft_req.to),
                "subject": draft_req.subject,
            },
            account_id=draft_req.account_id,
            policy_decision_id=decision.policy_id,
        )

        return EmailDraftResponse(
            draft_id=draft_id,
            message_id=message_id,
            account_id=draft_req.account_id,
            subject=draft_req.subject,
            to=draft_req.to,
            cc=draft_req.cc,
            bcc=draft_req.bcc,
            body_text=draft_req.body_text,
            body_html=draft_req.body_html,
            status="drafted",
            created_at=datetime.now(timezone.utc),
        )

    async def get_draft(
        self, context: SecurityContext, account_id: UUID, draft_id: str
    ) -> EmailDraftResponse:
        """Retrieve existing draft details by ID."""
        provider = await self._resolve_provider(context, account_id)
        raw_draft = await provider.get_draft(draft_id)

        msg_payload = raw_draft.get("message", {})
        parsed_msg = GmailMessageParser.to_email_message(msg_payload)

        return EmailDraftResponse(
            draft_id=raw_draft.get("id", draft_id),
            message_id=msg_payload.get("id"),
            account_id=account_id,
            subject=parsed_msg.subject,
            to=parsed_msg.to,
            cc=parsed_msg.cc,
            bcc=parsed_msg.bcc,
            body_text=parsed_msg.body_text,
            body_html=parsed_msg.body_html,
            status="drafted",
            created_at=parsed_msg.received_at or datetime.now(timezone.utc),
        )

    async def update_draft(
        self, context: SecurityContext, draft_id: str, update_req: EmailDraftUpdateRequest
    ) -> EmailDraftResponse:
        """Update existing draft after verifying recipient hygiene and DLP rules."""
        # 1. Recipient check if recipients provided
        if update_req.to or update_req.cc or update_req.bcc:
            recips = (update_req.to or []) + (update_req.cc or []) + (update_req.bcc or [])
            recip_result = self.policy_coordinator.recipient_validator.validate_recipients(recips)
            if not recip_result.is_valid:
                raise SecurityPolicyEnforcementError(
                    f"Updated draft recipient validation failed: {'; '.join(recip_result.reasons)}",
                    policy_id="INVALID_RECIPIENT",
                )

        # 2. DLP scan on updated content
        if update_req.subject or update_req.body_text or update_req.body_html:
            local_dlp = self.policy_coordinator.content_classifier.classify_outgoing_content(
                subject=update_req.subject or "",
                body_text=update_req.body_text or "",
                body_html=update_req.body_html,
            )
            if not local_dlp.safe:
                raise SecurityPolicyEnforcementError(
                    f"Updated draft contains confidential data: {', '.join(local_dlp.flags)}",
                    policy_id="DLP_DATA_LEAKAGE",
                )

        # 3. Policy authorization
        decision = await self.policy_coordinator.policy_client.authorize_draft_update(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            account_id=update_req.account_id,
            draft_id=draft_id,
            update_request=update_req,
        )
        if not decision.allowed:
            raise SecurityPolicyEnforcementError(
                decision.reason or "Draft update rejected by policy",
                policy_id=decision.policy_id or "DRAFT_UPDATE_REJECTED",
            )

        provider = await self._resolve_provider(context, update_req.account_id)
        raw_updated = await provider.update_draft(
            draft_id=draft_id,
            to=[r.email for r in (update_req.to or [])],
            cc=[r.email for r in (update_req.cc or [])],
            bcc=[r.email for r in (update_req.bcc or [])],
            subject=update_req.subject or "",
            body_text=update_req.body_text or "",
            body_html=update_req.body_html,
            thread_id=update_req.thread_id,
        )

        await self.policy_coordinator.audit_client.record_event(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            event_type="EMAIL_DRAFT_UPDATED",
            status="ALLOWED",
            metadata={"draft_id": draft_id},
            account_id=update_req.account_id,
            policy_decision_id=decision.policy_id,
        )

        return EmailDraftResponse(
            draft_id=draft_id,
            message_id=raw_updated.get("message", {}).get("id"),
            account_id=update_req.account_id,
            subject=update_req.subject or "",
            to=update_req.to or [],
            cc=update_req.cc or [],
            bcc=update_req.bcc or [],
            body_text=update_req.body_text,
            body_html=update_req.body_html,
            status="updated",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
