"""Security schemas for policy authorization, content inspection, and recipient validation."""

from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class PolicyAction(str, Enum):
    """Actions authorized by the AgentShield policy engine."""

    READ = "READ"
    SEARCH = "SEARCH"
    DRAFT = "DRAFT"
    DRAFT_UPDATE = "DRAFT_UPDATE"
    SEND = "SEND"
    FORWARD = "FORWARD"
    ATTACHMENT_READ = "ATTACHMENT_READ"
    OAUTH_CONNECT = "OAUTH_CONNECT"
    OAUTH_REVOKE = "OAUTH_REVOKE"


class InspectionOutcome(str, Enum):
    """Discrete inspection classification outcomes."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    QUARANTINE = "QUARANTINE"


class PolicyRequest(BaseModel):
    """Contextual authorization request sent to the PolicyClient."""

    model_config = ConfigDict(extra="ignore")

    tenant_id: str = Field(..., description="Authenticated tenant identifier")
    agent_id: str = Field(..., description="Authenticated agent identifier")
    action: PolicyAction = Field(..., description="Operation being attempted")
    account_id: UUID = Field(..., description="Target email account identifier")
    resource_id: Optional[str] = Field(default=None, description="Target message/draft ID if applicable")
    recipients: List[str] = Field(default_factory=list, description="Target recipient email addresses")
    attachment_metadata: List[Dict[str, Any]] = Field(default_factory=list, description="Attachment metadata")
    risk_findings: List[str] = Field(default_factory=list, description="Security/DLP risk indicators")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Action-specific metadata")


class PolicyDecision(BaseModel):
    """Policy decision returned by the PolicyClient."""

    model_config = ConfigDict(extra="ignore")

    allowed: bool = Field(..., description="Whether action is permitted")
    reason: Optional[str] = Field(default=None, description="Explanation for decision")
    policy_id: Optional[str] = Field(default=None, description="Matching policy rule identifier")
    requires_human_approval: bool = Field(default=False, description="Whether action requires out-of-band approval")
    approval_id: Optional[UUID] = Field(default=None, description="Pending approval reference ID")


class InspectionResult(BaseModel):
    """Inspection outcome from DLP, PII, and content inspection engine."""

    model_config = ConfigDict(extra="ignore")

    safe: bool = Field(default=True, description="True if no safety/DLP violations found")
    outcome: InspectionOutcome = Field(default=InspectionOutcome.ALLOW, description="Policy-aligned outcome")
    flags: List[str] = Field(default_factory=list, description="Violation indicators or rule triggers")
    risk_findings: List[str] = Field(default_factory=list, description="Detailed risk summaries")
    pii_detected: List[str] = Field(default_factory=list, description="Categories of PII detected")
    prompt_injection_detected: bool = Field(default=False, description="True if prompt injection patterns found")
    suspicious_urls: List[str] = Field(default_factory=list, description="Phishing or high-risk URLs detected")
    sanitized_text: Optional[str] = Field(default=None, description="Redacted or sanitized text if applied")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic inspection details")


class RecipientValidationResult(BaseModel):
    """Validation result for destination recipients."""

    model_config = ConfigDict(extra="ignore")

    is_valid: bool = Field(..., description="Whether all recipients passed syntax and domain checks")
    invalid_recipients: List[str] = Field(default_factory=list, description="Malformed or blocked email addresses")
    external_recipients: List[str] = Field(default_factory=list, description="Recipients outside the trusted domain boundary")
    is_external: bool = Field(default=False, description="True if any recipient is external")
    risk_level: str = Field(default="LOW", description="Risk assessment: LOW, MEDIUM, HIGH, CRITICAL")
    reasons: List[str] = Field(default_factory=list, description="Validation failure or caution notes")


class AttachmentValidationResult(BaseModel):
    """Validation outcome for inbound/outbound attachments."""

    model_config = ConfigDict(extra="ignore")

    is_valid: bool = Field(..., description="Whether all attachments passed security filters")
    rejected_attachments: List[str] = Field(default_factory=list, description="Filenames that failed inspection")
    quarantined_attachments: List[str] = Field(default_factory=list, description="Attachments held in quarantine")
    reasons: List[str] = Field(default_factory=list, description="Reasons for rejections")


class SecurityContext(BaseModel):
    """Validated gateway identity context attached to each request."""

    model_config = ConfigDict(extra="ignore")

    tenant_id: str = Field(..., description="Tenant ID from authenticated gateway")
    agent_id: str = Field(..., description="Agent ID from authenticated gateway")
    request_id: str = Field(..., description="Correlation request ID")
    authenticated: bool = Field(default=True, description="Whether authentication was verified")
