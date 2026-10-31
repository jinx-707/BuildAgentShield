"""Database repository providing isolated data access patterns for OAuth, audit, approvals, and quarantine."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.models import (
    ApprovalReference,
    AttachmentQuarantineRecord,
    EmailAuditRecord,
    OAuthAccount,
    OAuthState,
)
from app.security.token_crypto import TokenCrypto, get_token_crypto


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class OAuthAccountRepository:
    """Manages persistent credentials with transparent field-level encryption."""

    def __init__(self, session: AsyncSession, crypto: Optional[TokenCrypto] = None):
        self.session = session
        self.crypto = crypto or get_token_crypto()

    async def create_or_update_account(
        self,
        tenant_id: str,
        agent_id: str,
        provider: str,
        account_email: str,
        access_token: str,
        refresh_token: Optional[str],
        token_expiry: Optional[datetime],
        granted_scopes: List[str],
    ) -> OAuthAccount:
        """Store or update account with encrypted tokens."""
        encrypted_access = self.crypto.encrypt(access_token)
        encrypted_refresh = self.crypto.encrypt(refresh_token) if refresh_token else None

        stmt = select(OAuthAccount).where(
            and_(
                OAuthAccount.tenant_id == tenant_id,
                OAuthAccount.agent_id == agent_id,
                OAuthAccount.account_email == account_email,
                OAuthAccount.provider == provider,
            )
        )
        result = await self.session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.encrypted_access_token = encrypted_access
            if encrypted_refresh:
                existing.encrypted_refresh_token = encrypted_refresh
            existing.token_expiry = token_expiry
            existing.granted_scopes = granted_scopes
            existing.status = "active"
            existing.updated_at = utcnow()
            await self.session.flush()
            return existing

        account = OAuthAccount(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            agent_id=agent_id,
            provider=provider,
            account_email=account_email,
            encrypted_access_token=encrypted_access,
            encrypted_refresh_token=encrypted_refresh,
            token_expiry=token_expiry,
            granted_scopes=granted_scopes,
            status="active",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        self.session.add(account)
        await self.session.flush()
        return account

    async def get_account(
        self, account_id: uuid.UUID, tenant_id: str, agent_id: str
    ) -> Optional[OAuthAccount]:
        """Fetch account ensuring tenant and agent boundary isolation."""
        stmt = select(OAuthAccount).where(
            and_(
                OAuthAccount.id == account_id,
                OAuthAccount.tenant_id == tenant_id,
                OAuthAccount.agent_id == agent_id,
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_accounts(self, tenant_id: str, agent_id: str) -> List[OAuthAccount]:
        """List active email accounts for caller context."""
        stmt = (
            select(OAuthAccount)
            .where(
                and_(
                    OAuthAccount.tenant_id == tenant_id,
                    OAuthAccount.agent_id == agent_id,
                )
            )
            .order_by(OAuthAccount.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    def get_decrypted_tokens(self, account: OAuthAccount) -> Tuple[str, Optional[str]]:
        """Decrypt and return (access_token, refresh_token). Never expose via API."""
        access_token = self.crypto.decrypt(account.encrypted_access_token)
        refresh_token = (
            self.crypto.decrypt(account.encrypted_refresh_token)
            if account.encrypted_refresh_token
            else None
        )
        return access_token, refresh_token

    async def update_access_token(
        self, account_id: uuid.UUID, new_access_token: str, new_expiry: Optional[datetime]
    ) -> None:
        """Update refreshed access token."""
        encrypted_access = self.crypto.encrypt(new_access_token)
        stmt = (
            update(OAuthAccount)
            .where(OAuthAccount.id == account_id)
            .values(
                encrypted_access_token=encrypted_access,
                token_expiry=new_expiry,
                updated_at=utcnow(),
            )
        )
        await self.session.execute(stmt)
        await self.session.flush()

    async def revoke_account(
        self, account_id: uuid.UUID, tenant_id: str, agent_id: str
    ) -> bool:
        """Mark account as revoked."""
        account = await self.get_account(account_id, tenant_id, agent_id)
        if not account:
            return False
        account.status = "revoked"
        account.updated_at = utcnow()
        await self.session.flush()
        return True


class OAuthStateRepository:
    """Manages ephemeral OAuth state records for CSRF protection."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_state(
        self,
        state_token: str,
        tenant_id: str,
        agent_id: str,
        provider: str,
        requested_scopes: List[str],
        redirect_uri: str,
        expires_at: datetime,
    ) -> OAuthState:
        """Store new CSRF state token."""
        state = OAuthState(
            state_token=state_token,
            tenant_id=tenant_id,
            agent_id=agent_id,
            provider=provider,
            requested_scopes=requested_scopes,
            redirect_uri=redirect_uri,
            expires_at=expires_at,
            used=False,
            created_at=utcnow(),
        )
        self.session.add(state)
        await self.session.flush()
        return state

    async def validate_and_consume_state(self, state_token: str) -> Optional[OAuthState]:
        """Validate state token, ensure not expired or reused, and mark as consumed."""
        stmt = select(OAuthState).where(OAuthState.state_token == state_token)
        result = await self.session.execute(stmt)
        state = result.scalar_one_or_none()

        if not state:
            return None

        now = utcnow()
        exp = state.expires_at if state.expires_at.tzinfo else state.expires_at.replace(tzinfo=timezone.utc)
        if state.used or exp < now:
            return None

        state.used = True
        await self.session.flush()
        return state


class AuditRepository:
    """Persists immutable audit log records."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def record_audit_event(
        self,
        tenant_id: str,
        agent_id: str,
        event_type: str,
        status: str,
        metadata_json: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        account_id: Optional[uuid.UUID] = None,
        policy_decision_id: Optional[str] = None,
        inspection_reference_id: Optional[str] = None,
    ) -> EmailAuditRecord:
        """Record a security audit log event."""
        meta = metadata_json if metadata_json is not None else (metadata or {})
        record = EmailAuditRecord(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            agent_id=agent_id,
            account_id=account_id,
            event_type=event_type,
            status=status,
            policy_decision_id=policy_decision_id,
            inspection_reference_id=inspection_reference_id,
            metadata_json=meta,
            timestamp=utcnow(),
        )
        self.session.add(record)
        await self.session.flush()
        return record


class ApprovalRepository:
    """Manages human approval requests with cryptographic action binding and atomic consumption."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_approval(
        self,
        tenant_id: str,
        agent_id: str,
        action_type: str,
        target_resource: str,
        reason: str,
        payload_summary: Dict[str, Any],
        expires_at: datetime,
        account_id: Optional[uuid.UUID] = None,
        subject: Optional[str] = None,
        recipients: Optional[List[str]] = None,
        content_hash: Optional[str] = None,
        attachment_hashes: Optional[List[str]] = None,
        initial_status: str = "PENDING",
    ) -> ApprovalReference:
        """Create new pending approval bound to exact canonical content and recipient hashes."""
        approval = ApprovalReference(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            agent_id=agent_id,
            account_id=account_id,
            action_type=action_type,
            target_resource=target_resource,
            subject=subject,
            recipients=[r.lower() for r in (recipients or [])],
            content_hash=content_hash,
            attachment_hashes=attachment_hashes or [],
            status=initial_status,
            reason=reason,
            payload_summary=payload_summary,
            used=False,
            created_at=utcnow(),
            expires_at=expires_at,
        )
        self.session.add(approval)
        await self.session.flush()
        return approval

    async def get_approval(
        self, approval_id: uuid.UUID, tenant_id: str, agent_id: str
    ) -> Optional[ApprovalReference]:
        """Fetch approval within security boundary."""
        stmt = select(ApprovalReference).where(
            and_(
                ApprovalReference.id == approval_id,
                ApprovalReference.tenant_id == tenant_id,
                ApprovalReference.agent_id == agent_id,
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def approve_approval(
        self, approval_id: uuid.UUID, tenant_id: str, agent_id: str, approved_by: str = "security-admin"
    ) -> Optional[ApprovalReference]:
        """Mark approval as APPROVED by authorized human."""
        approval = await self.get_approval(approval_id, tenant_id, agent_id)
        if not approval or approval.status != "PENDING":
            return None
        approval.status = "APPROVED"
        approval.approved_by = approved_by
        await self.session.flush()
        return approval

    async def consume_approval_atomically(
        self,
        approval_id: uuid.UUID,
        tenant_id: str,
        agent_id: str,
        account_id: uuid.UUID,
        action_type: str,
        content_hash: str,
        attachment_hashes: List[str],
        recipients: List[str],
    ) -> Tuple[bool, str]:
        """Atomically verify and consume human approval.

        Enforces:
        - Exists and belongs to caller tenant/agent
        - Status is APPROVED
        - Not used (anti-replay)
        - Not expired
        - Exact match on content hash
        - Exact match on recipient list
        - Exact match on attachment hashes
        """
        approval = await self.get_approval(approval_id, tenant_id, agent_id)
        if not approval:
            return False, "Approval reference ID not found or inaccessible for caller"

        if approval.used:
            return False, "Approval has already been consumed (replay attempt detected)"

        now = utcnow()
        exp = approval.expires_at if approval.expires_at.tzinfo else approval.expires_at.replace(tzinfo=timezone.utc)
        if exp < now or approval.status == "EXPIRED":
            approval.status = "EXPIRED"
            await self.session.flush()
            return False, "Approval has expired"

        if approval.status != "APPROVED":
            return False, f"Approval is not in APPROVED state (current state: {approval.status})"

        if approval.account_id and approval.account_id != account_id:
            return False, "Approval is bound to a different email account"

        if approval.action_type != action_type:
            return False, f"Approval is bound to action '{approval.action_type}', not '{action_type}'"

        # Content integrity check
        if approval.content_hash and approval.content_hash != content_hash:
            return False, "Message content modified after approval was granted (hash mismatch)"

        # Recipients integrity check
        target_recips = set(r.lower() for r in recipients)
        approved_recips = set(r.lower() for r in approval.recipients)
        if target_recips != approved_recips:
            return False, "Recipient list modified after approval was granted"

        # Attachment hashes integrity check
        if sorted(approval.attachment_hashes or []) != sorted(attachment_hashes or []):
            return False, "Attachments modified after approval was granted"

        # Atomically consume
        approval.used = True
        approval.status = "USED"
        await self.session.flush()
        return True, "Approval validated and consumed"


class AttachmentQuarantineRepository:
    """Manages records of quarantined attachments."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def record_quarantine(
        self,
        tenant_id: str,
        agent_id: str,
        account_id: uuid.UUID,
        message_id: str,
        attachment_id: str,
        filename: str,
        content_type: str,
        size_bytes: int,
        sha256_hash: str,
        quarantine_reason: str,
    ) -> AttachmentQuarantineRecord:
        record = AttachmentQuarantineRecord(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            agent_id=agent_id,
            account_id=account_id,
            message_id=message_id,
            attachment_id=attachment_id,
            filename=filename,
            content_type=content_type,
            size_bytes=size_bytes,
            sha256_hash=sha256_hash,
            quarantine_reason=quarantine_reason,
            created_at=utcnow(),
        )
        self.session.add(record)
        await self.session.flush()
        return record

    async def get_quarantined_record(
        self, attachment_id: str, tenant_id: str, agent_id: str
    ) -> Optional[AttachmentQuarantineRecord]:
        stmt = select(AttachmentQuarantineRecord).where(
            and_(
                AttachmentQuarantineRecord.attachment_id == attachment_id,
                AttachmentQuarantineRecord.tenant_id == tenant_id,
                AttachmentQuarantineRecord.agent_id == agent_id,
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
