"""Pydantic models for email representations, requests, and responses."""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EmailAddress(BaseModel):
    """Normalized email address with optional display name."""

    model_config = ConfigDict(extra="ignore")

    email: EmailStr = Field(..., description="Email address RFC 5322 format")
    name: Optional[str] = Field(default=None, description="Display name if available")


class EmailAttachmentMetadata(BaseModel):
    """Metadata describing an attachment without transferring raw bytes."""

    model_config = ConfigDict(extra="ignore")

    attachment_id: Optional[str] = Field(default=None, description="Provider attachment ID")
    filename: str = Field(..., description="Attachment filename")
    content_type: str = Field(..., description="MIME content type")
    size_bytes: int = Field(default=0, description="Size in bytes")
    sha256_hash: Optional[str] = Field(default=None, description="SHA-256 digest of attachment content")
    quarantined: bool = Field(default=False, description="True if quarantined due to security threats")
    quarantine_reason: Optional[str] = Field(default=None, description="Reason for quarantine if applicable")


class EmailAttachmentInput(BaseModel):
    """Inbound attachment payload for outbound draft or send requests."""

    model_config = ConfigDict(extra="ignore")

    filename: str = Field(..., description="Attachment filename")
    content_type: str = Field(..., description="Attachment MIME type")
    content_base64: str = Field(..., description="Base64 encoded attachment content")


class EmailMessage(BaseModel):
    """Normalized email message representation across providers."""

    model_config = ConfigDict(extra="ignore", from_attributes=True)

    id: str = Field(..., description="Provider message ID")
    thread_id: Optional[str] = Field(default=None, description="Provider thread ID")
    subject: str = Field(default="", description="Email subject")
    sender: EmailAddress = Field(..., description="From sender address")
    to: List[EmailAddress] = Field(default_factory=list, description="Primary recipients")
    cc: List[EmailAddress] = Field(default_factory=list, description="Carbon copy recipients")
    bcc: List[EmailAddress] = Field(default_factory=list, description="Blind carbon copy recipients")
    received_at: Optional[datetime] = Field(default=None, description="Timestamp message was received")
    snippet: str = Field(default="", description="Short snippet of email text")
    body_text: Optional[str] = Field(default=None, description="Plain text body content")
    body_html: Optional[str] = Field(default=None, description="HTML body content (sanitized)")
    attachments: List[EmailAttachmentMetadata] = Field(default_factory=list, description="Attachments")
    labels: List[str] = Field(default_factory=list, description="Folder or label identifiers")
    is_untrusted: bool = Field(default=True, description="Flag marking inbound content as untrusted input")
    security_notice: Optional[str] = Field(default=None, description="Security findings or prompt injection warning")


class EmailSearchRequest(BaseModel):
    """Request model for searching emails with structured and query parameters."""

    model_config = ConfigDict(extra="ignore")

    account_id: UUID = Field(..., description="Target email account UUID")
    query: Optional[str] = Field(default=None, max_length=500, description="Email search query string")
    from_sender: Optional[str] = Field(default=None, description="Search by sender email or domain")
    to_recipient: Optional[str] = Field(default=None, description="Search by recipient email")
    subject: Optional[str] = Field(default=None, description="Search by subject keyword")
    after_date: Optional[str] = Field(default=None, description="Filter messages after date (YYYY/MM/DD)")
    before_date: Optional[str] = Field(default=None, description="Filter messages before date (YYYY/MM/DD)")
    max_results: int = Field(default=10, ge=1, le=50, description="Maximum messages to return")
    page_token: Optional[str] = Field(default=None, description="Pagination token")
    include_spam_trash: bool = Field(default=False, description="Include spam and trash folders")


class EmailSearchResponse(BaseModel):
    """Response model for email search results."""

    model_config = ConfigDict(extra="ignore")

    messages: List[EmailMessage] = Field(default_factory=list, description="Matching messages")
    next_page_token: Optional[str] = Field(default=None, description="Next page pagination token")
    total_estimated: Optional[int] = Field(default=None, description="Estimated total matches")


class EmailDraftRequest(BaseModel):
    """Request model for creating an email draft."""

    model_config = ConfigDict(extra="ignore")

    account_id: UUID = Field(..., description="Target email account UUID")
    to: List[EmailAddress] = Field(..., min_length=1, description="Primary recipients")
    cc: List[EmailAddress] = Field(default_factory=list, description="CC recipients")
    bcc: List[EmailAddress] = Field(default_factory=list, description="BCC recipients")
    subject: str = Field(..., max_length=998, description="Subject line")
    body_text: str = Field(..., description="Plaintext email body")
    body_html: Optional[str] = Field(default=None, description="Optional HTML body")
    thread_id: Optional[str] = Field(default=None, description="Thread to draft reply in")
    attachments: List[EmailAttachmentInput] = Field(default_factory=list, description="Attachments")


class EmailDraftUpdateRequest(BaseModel):
    """Request model for updating an existing email draft."""

    model_config = ConfigDict(extra="ignore")

    account_id: UUID = Field(..., description="Target email account UUID")
    to: Optional[List[EmailAddress]] = Field(default=None, description="Updated primary recipients")
    cc: Optional[List[EmailAddress]] = Field(default=None, description="Updated CC recipients")
    bcc: Optional[List[EmailAddress]] = Field(default=None, description="Updated BCC recipients")
    subject: Optional[str] = Field(default=None, max_length=998, description="Updated subject line")
    body_text: Optional[str] = Field(default=None, description="Updated plaintext body")
    body_html: Optional[str] = Field(default=None, description="Updated HTML body")
    thread_id: Optional[str] = Field(default=None, description="Thread identifier")


class EmailDraftResponse(BaseModel):
    """Response model for draft creation and retrieval."""

    model_config = ConfigDict(extra="ignore")

    draft_id: str = Field(..., description="Draft identifier")
    message_id: Optional[str] = Field(default=None, description="Draft message ID")
    account_id: UUID = Field(..., description="Account UUID")
    subject: str = Field(default="", description="Draft subject")
    to: List[EmailAddress] = Field(default_factory=list, description="Recipients")
    cc: List[EmailAddress] = Field(default_factory=list, description="CC recipients")
    bcc: List[EmailAddress] = Field(default_factory=list, description="BCC recipients")
    body_text: Optional[str] = Field(default=None, description="Draft plaintext content")
    body_html: Optional[str] = Field(default=None, description="Draft HTML content")
    status: str = Field(default="drafted", description="Draft status")
    created_at: datetime = Field(default_factory=utcnow, description="Draft creation time")
    updated_at: Optional[datetime] = Field(default=None, description="Draft update time")


class EmailSendRequest(BaseModel):
    """Request model for sending an email (new message or approved draft)."""

    model_config = ConfigDict(extra="ignore")

    account_id: UUID = Field(..., description="Target email account UUID")
    draft_id: Optional[str] = Field(default=None, description="Optional existing draft ID to send")
    approval_id: Optional[UUID] = Field(default=None, description="Pre-granted human approval reference UUID")
    to: Optional[List[EmailAddress]] = Field(default=None, description="Primary recipients")
    cc: List[EmailAddress] = Field(default_factory=list, description="CC recipients")
    bcc: List[EmailAddress] = Field(default_factory=list, description="BCC recipients")
    subject: Optional[str] = Field(default=None, max_length=998, description="Subject line")
    body_text: Optional[str] = Field(default=None, description="Plaintext email body")
    body_html: Optional[str] = Field(default=None, description="Optional HTML body")
    thread_id: Optional[str] = Field(default=None, description="Thread ID if replying")
    attachments: List[EmailAttachmentInput] = Field(default_factory=list, description="Attachments")


class EmailSendResponse(BaseModel):
    """Response model for email sending."""

    model_config = ConfigDict(extra="ignore")

    message_id: str = Field(..., description="Sent message ID")
    thread_id: Optional[str] = Field(default=None, description="Thread ID")
    account_id: UUID = Field(..., description="Account UUID")
    sent_at: datetime = Field(default_factory=utcnow, description="Timestamp sent")
    status: str = Field(default="sent", description="Delivery status")


class EmailForwardRequest(BaseModel):
    """Request model for forwarding an email."""

    model_config = ConfigDict(extra="ignore")

    account_id: UUID = Field(..., description="Target email account UUID")
    original_message_id: str = Field(..., description="ID of original message to forward")
    approval_id: Optional[UUID] = Field(default=None, description="Pre-granted human approval reference UUID")
    to: List[EmailAddress] = Field(..., min_length=1, description="Forward recipients")
    cc: List[EmailAddress] = Field(default_factory=list, description="CC recipients")
    additional_comment: Optional[str] = Field(default=None, description="Comment prepended to forwarded email")
    forward_attachments: bool = Field(default=True, description="Whether to include original attachments")


class EmailForwardResponse(BaseModel):
    """Response model for forwarded email."""

    model_config = ConfigDict(extra="ignore")

    message_id: str = Field(..., description="Forwarded message ID")
    account_id: UUID = Field(..., description="Account UUID")
    forwarded_to: List[str] = Field(default_factory=list, description="Forwarded recipient emails")
    status: str = Field(default="forwarded", description="Forward status")
    sent_at: datetime = Field(default_factory=utcnow, description="Timestamp sent")


class EmailAccountResponse(BaseModel):
    """Response model representing connected email account (no secret tokens)."""

    model_config = ConfigDict(extra="ignore", from_attributes=True)

    id: UUID = Field(..., description="Account UUID")
    account_email: str = Field(..., description="Connected email address")
    provider: str = Field(..., description="Provider name (google, microsoft)")
    status: str = Field(..., description="Account status (active, revoked, expired)")
    granted_scopes: List[str] = Field(default_factory=list, description="Scopes authorized")
    created_at: datetime = Field(..., description="Account connection timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


class AttachmentMetadataResponse(BaseModel):
    """Attachment inspection and metadata response."""

    model_config = ConfigDict(extra="ignore")

    attachment_id: str = Field(..., description="Attachment ID")
    message_id: str = Field(..., description="Parent message ID")
    filename: str = Field(..., description="Sanitized filename")
    content_type: str = Field(..., description="MIME content type")
    size_bytes: int = Field(..., description="Size in bytes")
    sha256_hash: str = Field(..., description="Cryptographic SHA-256 hash")
    quarantined: bool = Field(default=False, description="True if quarantined")
    quarantine_reason: Optional[str] = Field(default=None, description="Quarantine explanation")
    is_safe: bool = Field(default=True, description="Safety clearance status")
