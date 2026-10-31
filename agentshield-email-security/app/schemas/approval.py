"""Schemas for human approval workflows with cryptographic action binding."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class ApprovalStatus(str, Enum):
    """Lifecycle status of a human approval request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    USED = "USED"


class ApprovalRequestCreate(BaseModel):
    """Payload to register an action requiring human approval."""

    model_config = ConfigDict(extra="ignore")

    tenant_id: str = Field(..., description="Tenant ID")
    agent_id: str = Field(..., description="Requesting agent ID")
    account_id: UUID = Field(..., description="Bound email account UUID")
    action_type: str = Field(..., description="Action: send, forward, confidential_leakage")
    target_resource: str = Field(..., description="Resource identifier or target description")
    subject: str = Field(..., description="Bound email subject")
    recipients: List[str] = Field(..., description="Bound recipient email list")
    content_hash_sha256: str = Field(..., description="SHA-256 hash of canonical subject + body")
    attachment_hashes_sha256: List[str] = Field(default_factory=list, description="SHA-256 hashes of attachments")
    reason: str = Field(..., description="Why human authorization is required")
    payload_summary: Dict[str, Any] = Field(default_factory=dict, description="Sanitized summary of action")


class ApprovalResponse(BaseModel):
    """Response representing an approval record."""

    model_config = ConfigDict(extra="ignore", from_attributes=True)

    approval_id: UUID = Field(..., description="Unique approval ID")
    tenant_id: str = Field(..., description="Tenant ID")
    agent_id: str = Field(..., description="Agent ID")
    account_id: Optional[UUID] = Field(default=None, description="Bound account UUID")
    action_type: str = Field(..., description="Action type")
    status: ApprovalStatus = Field(..., description="Current approval status")
    subject: Optional[str] = Field(default=None, description="Bound email subject")
    recipients: List[str] = Field(default_factory=list, description="Bound recipients")
    content_hash_sha256: Optional[str] = Field(default=None, description="Canonical content hash")
    attachment_hashes_sha256: List[str] = Field(default_factory=list, description="Attachment hashes")
    reason: str = Field(..., description="Reason approval was triggered")
    approved_by: Optional[str] = Field(default=None, description="Identity of approver if resolved")
    created_at: datetime = Field(..., description="Timestamp created")
    expires_at: datetime = Field(..., description="Expiration timestamp")
    used: bool = Field(default=False, description="True if already consumed")
