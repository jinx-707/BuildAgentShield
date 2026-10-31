"""Message security policy orchestrator coordinating zero-trust validation controls."""

import base64
import logging
from typing import List, Optional
from uuid import UUID
from app.integrations.approval_client import (
    BaseApprovalClient,
    calculate_attachment_hashes,
    calculate_canonical_content_hash,
)
from app.integrations.audit_client import BaseAuditClient
from app.integrations.inspection_client import BaseInspectionClient
from app.integrations.policy_client import BasePolicyClient
from app.schemas.email import (
    EmailDraftRequest,
    EmailDraftUpdateRequest,
    EmailForwardRequest,
    EmailMessage,
    EmailSendRequest,
)
from app.schemas.security import PolicyDecision, SecurityContext
from app.security.attachment_scanner import BaseAttachmentScanner, LocalAttachmentScanner
from app.security.attachment_validator import AttachmentValidator
from app.security.content_classifier import ContentClassifier
from app.security.recipient_validator import RecipientValidator

logger = logging.getLogger("agentshield.security.message_policy")


class SecurityPolicyEnforcementError(Exception):
    """Raised when an operation violates security policy or fails authorization."""

    def __init__(self, message: str, policy_id: str = "POLICY_VIOLATION", details: dict = None):
        super().__init__(message)
        self.message = message
        self.policy_id = policy_id
        self.details = details or {}


class HumanApprovalRequiredError(SecurityPolicyEnforcementError):
    """Raised when an outbound email requires out-of-band human sign-off."""

    def __init__(self, message: str, approval_id: str):
        super().__init__(message, policy_id="APPROVAL_PENDING", details={"approval_id": approval_id})
        self.approval_id = approval_id


class MessagePolicyCoordinator:
    """Coordinates local validators, attachment scanner, remote policy engine, and DLP inspection services."""

    def __init__(
        self,
        policy_client: BasePolicyClient,
        inspection_client: BaseInspectionClient,
        audit_client: BaseAuditClient,
        approval_client: Optional[BaseApprovalClient] = None,
        recipient_validator: Optional[RecipientValidator] = None,
        attachment_validator: Optional[AttachmentValidator] = None,
        attachment_scanner: Optional[BaseAttachmentScanner] = None,
        content_classifier: Optional[ContentClassifier] = None,
    ):
        self.policy_client = policy_client
        self.inspection_client = inspection_client
        self.audit_client = audit_client
        self.approval_client = approval_client
        self.recipient_validator = recipient_validator or RecipientValidator()
        self.attachment_validator = attachment_validator or AttachmentValidator()
        self.attachment_scanner = attachment_scanner or LocalAttachmentScanner()
        self.content_classifier = content_classifier or ContentClassifier()

    def enforce_scope(self, granted_scopes: List[str], required_scopes: List[str], action_name: str) -> None:
        """Enforce that account holds at least one of the OAuth scopes required for the action."""
        if not any(s in granted_scopes for s in required_scopes):
            err = (
                f"Account lacks required OAuth scope for action '{action_name}'. "
                f"Required one of: {required_scopes}. Granted: {granted_scopes}"
            )
            logger.warning(err)
            raise SecurityPolicyEnforcementError(err, policy_id="OAUTH_SCOPE_INSUFFICIENT")

    async def validate_and_authorize_read(
        self, context: SecurityContext, account_id: UUID, message_id: str
    ) -> PolicyDecision:
        """Enforce policy on reading a message."""
        decision = await self.policy_client.authorize_read(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            account_id=account_id,
            message_id=message_id,
        )
        if not decision.allowed:
            await self.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_READ_BLOCKED",
                status="BLOCKED",
                metadata={"message_id": message_id, "reason": decision.reason},
                account_id=account_id,
                policy_decision_id=decision.policy_id,
            )
            raise SecurityPolicyEnforcementError(
                decision.reason or "Read action unauthorized by policy",
                policy_id=decision.policy_id or "READ_DISALLOWED",
            )
        return decision

    async def inspect_inbound_message(
        self, context: SecurityContext, email: EmailMessage, account_id: UUID
    ) -> EmailMessage:
        """Inspect received message content and attachments for prompt injection or malicious payloads."""
        # 1. Local heuristic & HTML sanitization
        local_result = self.content_classifier.classify_incoming_content(
            subject=email.subject,
            snippet=email.snippet,
            body_text=email.body_text,
            body_html=email.body_html,
        )

        if local_result.sanitized_text:
            email.body_html = local_result.sanitized_text

        # 2. Central inspection engine check
        remote_result = await self.inspection_client.inspect_incoming_email(email)

        # Inbound content is always marked untrusted
        email.is_untrusted = True

        if not local_result.safe or not remote_result.safe:
            flags = list(set(local_result.flags + remote_result.flags))
            logger.warning(f"Inbound message {email.id} flagged for security violations: {flags}")
            await self.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="INCOMING_EMAIL_FLAGGED",
                status="FLAGGED",
                metadata={"message_id": email.id, "flags": flags},
                account_id=account_id,
            )
            notice = f"[AGENTSHIELD NOTICE: Inbound content flagged by security inspection: {', '.join(flags)}]"
            email.security_notice = notice
            if email.body_text:
                email.body_text = f"{notice}\n\n{email.body_text}"

        return email

    async def validate_and_authorize_draft(
        self, context: SecurityContext, account_id: UUID, draft_request: EmailDraftRequest
    ) -> PolicyDecision:
        """Validate recipients, scan draft body for DLP, and authorize via policy."""
        recip_result = self.recipient_validator.validate_recipients(
            draft_request.to + draft_request.cc + draft_request.bcc
        )
        if not recip_result.is_valid:
            err = f"Draft recipient validation failed: {'; '.join(recip_result.reasons)}"
            raise SecurityPolicyEnforcementError(err, policy_id="INVALID_RECIPIENT")

        local_dlp = self.content_classifier.classify_outgoing_content(
            subject=draft_request.subject,
            body_text=draft_request.body_text,
            body_html=draft_request.body_html,
        )
        if not local_dlp.safe:
            err = f"Draft contains confidential data leakage: {', '.join(local_dlp.flags)}"
            await self.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_DRAFT_BLOCKED",
                status="BLOCKED",
                metadata={"flags": local_dlp.flags},
                account_id=account_id,
            )
            raise SecurityPolicyEnforcementError(err, policy_id="DLP_DATA_LEAKAGE")

        decision = await self.policy_client.authorize_draft(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            account_id=account_id,
            draft_request=draft_request,
        )
        if not decision.allowed:
            raise SecurityPolicyEnforcementError(
                decision.reason or "Draft rejected by policy",
                policy_id=decision.policy_id or "DRAFT_DISALLOWED",
            )
        return decision

    async def validate_and_authorize_send(
        self, context: SecurityContext, account_id: UUID, send_request: EmailSendRequest
    ) -> PolicyDecision:
        """Enforce multi-layered validation and policy authorization on outbound emails."""
        # 1. Recipient validation
        all_recipients = (send_request.to or []) + send_request.cc + send_request.bcc
        recip_result = self.recipient_validator.validate_recipients(all_recipients)
        if not recip_result.is_valid:
            err = f"Recipient validation failed: {'; '.join(recip_result.reasons)}"
            await self.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_SEND_BLOCKED",
                status="BLOCKED",
                metadata={"reasons": recip_result.reasons, "invalid": recip_result.invalid_recipients},
                account_id=account_id,
            )
            raise SecurityPolicyEnforcementError(err, policy_id="INVALID_RECIPIENT")

        # 2. Attachment validation & deep file signature scan
        attachment_hashes = []
        if send_request.attachments:
            att_result = self.attachment_validator.validate_attachments(send_request.attachments)
            if not att_result.is_valid:
                err = f"Attachment validation failed: {'; '.join(att_result.reasons)}"
                await self.audit_client.record_event(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    event_type="EMAIL_SEND_BLOCKED",
                    status="BLOCKED",
                    metadata={"reasons": att_result.reasons, "rejected": att_result.rejected_attachments},
                    account_id=account_id,
                )
                raise SecurityPolicyEnforcementError(err, policy_id="ATTACHMENT_DISALLOWED")

            for att in send_request.attachments:
                raw_bytes = base64.b64decode(att.content_base64)
                scan_res = await self.attachment_scanner.scan(att.filename, att.content_type, raw_bytes)
                if not scan_res.is_safe:
                    err = f"Attachment security scan failed for '{att.filename}': {'; '.join(scan_res.reasons)}"
                    event_type = "EMAIL_ATTACHMENT_QUARANTINED" if scan_res.quarantined else "EMAIL_SEND_BLOCKED"
                    await self.audit_client.record_event(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        event_type=event_type,
                        status="BLOCKED",
                        metadata={"filename": att.filename, "sha256": scan_res.sha256_hash, "reasons": scan_res.reasons},
                        account_id=account_id,
                    )
                    raise SecurityPolicyEnforcementError(err, policy_id="ATTACHMENT_MALWARE_DETECTED")
                attachment_hashes.append(scan_res.sha256_hash)

        # 3. Content classification (DLP)
        local_dlp = self.content_classifier.classify_outgoing_content(
            subject=send_request.subject or "",
            body_text=send_request.body_text or "",
            body_html=send_request.body_html,
        )
        if not local_dlp.safe:
            err = f"Outbound DLP policy violation: confidential data detected ({', '.join(local_dlp.flags)})"
            await self.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="DLP_LEAKAGE_BLOCKED",
                status="BLOCKED",
                metadata={"flags": local_dlp.flags, "pii": local_dlp.pii_detected},
                account_id=account_id,
            )
            raise SecurityPolicyEnforcementError(err, policy_id="DLP_DATA_LEAKAGE")

        # 4. Central inspection engine
        remote_dlp = await self.inspection_client.inspect_outgoing_email(send_request)
        if not remote_dlp.safe:
            err = f"Central DLP inspection blocked outbound message: {', '.join(remote_dlp.flags)}"
            await self.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="DLP_LEAKAGE_BLOCKED",
                status="BLOCKED",
                metadata={"flags": remote_dlp.flags},
                account_id=account_id,
            )
            raise SecurityPolicyEnforcementError(err, policy_id="CENTRAL_DLP_BLOCKED")

        # 5. Check pre-granted human approval if supplied
        content_hash = calculate_canonical_content_hash(send_request.subject or "", send_request.body_text or "")
        target_recips = [r.email for r in (send_request.to or []) + send_request.cc + send_request.bcc]

        if send_request.approval_id and self.approval_client:
            valid, msg = await self.approval_client.verify_and_consume(
                approval_id=send_request.approval_id,
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                account_id=account_id,
                action_type="send",
                content_hash=content_hash,
                attachment_hashes=attachment_hashes,
                recipients=target_recips,
            )
            if not valid:
                err = f"Approval verification failed: {msg}"
                await self.audit_client.record_event(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    event_type="EMAIL_SEND_BLOCKED",
                    status="BLOCKED",
                    metadata={"approval_id": str(send_request.approval_id), "issue": msg},
                    account_id=account_id,
                )
                raise SecurityPolicyEnforcementError(err, policy_id="INVALID_APPROVAL")

        # 6. Policy authorization
        decision = await self.policy_client.authorize_send(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            account_id=account_id,
            send_request=send_request,
        )
        if not decision.allowed and not decision.requires_human_approval:
            await self.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_SEND_BLOCKED",
                status="BLOCKED",
                metadata={"reason": decision.reason},
                account_id=account_id,
                policy_decision_id=decision.policy_id,
            )
            raise SecurityPolicyEnforcementError(
                decision.reason or "Send action unauthorized by policy",
                policy_id=decision.policy_id or "SEND_DISALLOWED",
            )

        return decision
