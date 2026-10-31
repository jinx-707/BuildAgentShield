"""Email reading service handling single and batch message retrieval with security inspection."""

import base64
import hashlib
import logging
from typing import List, Optional, Tuple
from uuid import UUID
from app.database.repository import AttachmentQuarantineRepository, OAuthAccountRepository
from app.providers.base import BaseEmailProvider
from app.providers.gmail.client import GmailClient
from app.providers.gmail.message_parser import GmailMessageParser
from app.schemas.email import AttachmentMetadataResponse, EmailMessage
from app.schemas.security import SecurityContext
from app.security.message_policy import MessagePolicyCoordinator, SecurityPolicyEnforcementError

logger = logging.getLogger("agentshield.services.reader")


class EmailReaderService:
    """Orchestrates secure email reading, attachment metadata inspection, and inbound threat scanning."""

    def __init__(
        self,
        account_repo: OAuthAccountRepository,
        policy_coordinator: MessagePolicyCoordinator,
        quarantine_repo: Optional[AttachmentQuarantineRepository] = None,
    ):
        self.account_repo = account_repo
        self.policy_coordinator = policy_coordinator
        self.quarantine_repo = quarantine_repo

    async def _resolve_provider(
        self, context: SecurityContext, account_id: UUID
    ) -> BaseEmailProvider:
        account = await self.account_repo.get_account(account_id, context.tenant_id, context.agent_id)
        if not account or account.status != "active":
            raise ValueError(f"Account {account_id} not found or inactive for caller")

        # Check required read scope
        allowed_read_scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://mail.google.com/",
        ]
        self.policy_coordinator.enforce_scope(account.granted_scopes, allowed_read_scopes, "read")

        access_token, refresh_token = self.account_repo.get_decrypted_tokens(account)
        if account.provider == "google":
            return GmailClient(access_token=access_token, refresh_token=refresh_token)
        else:
            from app.providers.microsoft.client import MicrosoftGraphClient
            return MicrosoftGraphClient(access_token=access_token, refresh_token=refresh_token)

    async def list_messages(
        self,
        context: SecurityContext,
        account_id: UUID,
        query: Optional[str] = None,
        max_results: int = 10,
        page_token: Optional[str] = None,
    ) -> Tuple[List[EmailMessage], Optional[str]]:
        """List messages and apply inbound inspection on retrieved previews."""
        provider = await self._resolve_provider(context, account_id)

        raw_messages, next_page = await provider.list_messages(
            query=query, max_results=max_results, page_token=page_token
        )

        messages: List[EmailMessage] = []
        for raw in raw_messages:
            parsed = GmailMessageParser.to_email_message(raw)
            # Inbound prompt injection and threat scan
            inspected = await self.policy_coordinator.inspect_inbound_message(
                context=context, email=parsed, account_id=account_id
            )
            messages.append(inspected)

        await self.policy_coordinator.audit_client.record_event(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            event_type="EMAIL_READ",
            status="ALLOWED",
            metadata={"account_id": str(account_id), "count": len(messages)},
            account_id=account_id,
        )

        return messages, next_page

    async def get_message(
        self,
        context: SecurityContext,
        account_id: UUID,
        message_id: str,
    ) -> EmailMessage:
        """Retrieve single message, verifying read authorization and content security."""
        # 1. Verify policy authorization
        await self.policy_coordinator.validate_and_authorize_read(
            context=context, account_id=account_id, message_id=message_id
        )

        provider = await self._resolve_provider(context, account_id)
        raw_msg = await provider.get_message(message_id)
        parsed = GmailMessageParser.to_email_message(raw_msg)

        # 2. Inspect inbound message (HTML script sanitization & prompt injection check)
        inspected = await self.policy_coordinator.inspect_inbound_message(
            context=context, email=parsed, account_id=account_id
        )

        await self.policy_coordinator.audit_client.record_event(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            event_type="EMAIL_READ",
            status="ALLOWED",
            metadata={"message_id": message_id},
            account_id=account_id,
        )

        return inspected

    async def get_attachment_metadata(
        self,
        context: SecurityContext,
        account_id: UUID,
        message_id: str,
        attachment_id: str,
    ) -> AttachmentMetadataResponse:
        """Fetch attachment data from provider and compute cryptographic SHA-256 and quarantine status."""
        # Authorize attachment read via policy
        decision = await self.policy_coordinator.policy_client.authorize_attachment_read(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            account_id=account_id,
            message_id=message_id,
            attachment_id=attachment_id,
        )
        if not decision.allowed:
            raise SecurityPolicyEnforcementError(
                decision.reason or "Attachment read rejected by policy",
                policy_id=decision.policy_id or "ATTACHMENT_READ_BLOCKED",
            )

        provider = await self._resolve_provider(context, account_id)
        raw_att = await provider.get_attachment(message_id, attachment_id)

        att_data_str = raw_att.get("data", "")
        # Decode base64url data
        padded = att_data_str + "=" * (-len(att_data_str) % 4)
        raw_bytes = base64.urlsafe_b64decode(padded.encode("ascii")) if padded else b""
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        size = raw_att.get("size", len(raw_bytes))

        # Scan attachment bytes
        filename = raw_att.get("filename", f"attachment_{attachment_id[:8]}")
        content_type = raw_att.get("mimeType", "application/octet-stream")
        scan_res = await self.policy_coordinator.attachment_scanner.scan(filename, content_type, raw_bytes)

        if scan_res.quarantined and self.quarantine_repo:
            await self.quarantine_repo.record_quarantine(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                account_id=account_id,
                message_id=message_id,
                attachment_id=attachment_id,
                filename=filename,
                content_type=content_type,
                size_bytes=size,
                sha256_hash=sha256,
                quarantine_reason="; ".join(scan_res.reasons),
            )
            await self.policy_coordinator.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_ATTACHMENT_QUARANTINED",
                status="BLOCKED",
                metadata={"message_id": message_id, "attachment_id": attachment_id, "reasons": scan_res.reasons},
                account_id=account_id,
            )

        return AttachmentMetadataResponse(
            attachment_id=attachment_id,
            message_id=message_id,
            filename=scan_res.sanitized_filename,
            content_type=content_type,
            size_bytes=size,
            sha256_hash=sha256,
            quarantined=scan_res.quarantined,
            quarantine_reason="; ".join(scan_res.reasons) if scan_res.reasons else None,
            is_safe=scan_res.is_safe,
        )
