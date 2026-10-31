"""SQLAlchemy 2 declarative models for AgentShield Email Security."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import Boolean, DateTime, String, Text, Uuid, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base model class."""
    pass


class OAuthAccount(Base):
    """Secure metadata and encrypted OAuth tokens for an integrated mailbox."""

    __tablename__ = "oauth_accounts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="google")
    account_email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)

    # Secure tokens: Encrypted at rest using TOKEN_ENCRYPTION_KEY
    encrypted_access_token: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_refresh_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_expiry: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    granted_scopes: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)  # active, revoked, expired

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class OAuthState(Base):
    """Ephemeral CSRF state tokens used during the OAuth authorization handshake."""

    __tablename__ = "oauth_states"

    state_token: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), default="google", nullable=False)
    requested_scopes: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    redirect_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class EmailAuditRecord(Base):
    """Audit log records for security-relevant email events."""

    __tablename__ = "email_audit_records"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    account_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # ALLOWED, BLOCKED, FLAGGED, ERROR
    policy_decision_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    inspection_reference_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )


class ApprovalReference(Base):
    """Tracks human authorization requests for sensitive or high-risk email actions."""

    __tablename__ = "approval_references"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    account_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid, nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_resource: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[Optional[str]] = mapped_column(String(998), nullable=True)
    recipients: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    content_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    attachment_hashes: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)  # PENDING, APPROVED, REJECTED, EXPIRED, USED
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    payload_summary: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttachmentQuarantineRecord(Base):
    """Stores metadata and cryptographic hashes for attachments flagged or quarantined by security inspection."""

    __tablename__ = "attachment_quarantine_records"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    message_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    attachment_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    quarantine_reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
