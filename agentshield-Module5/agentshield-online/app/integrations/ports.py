"""
Integration ports for shared security services.

These interfaces decouple the five online capabilities from:
  - Person 1's shared security engine (content/DLP inspection)
  - Person 4's platform (policy, approval, audit)

Replace the local adapters with real implementations by swapping the
concrete class injected into AppRuntime at startup.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


# ── Content Inspection (Person 1 boundary) ────────────────────────────────────

class ContentInspectionPort(ABC):
    """
    Inspects arbitrary text/content for prompt injection, harmful instructions,
    policy violations, etc.

    Provided by Person 1 in production.
    Local adapter: LocalContentInspectionAdapter (development-only).
    """

    @abstractmethod
    async def inspect(
        self,
        content: str,
        source: str,
        metadata: dict[str, Any] | None = None,
    ) -> "InspectionResult":
        """
        Inspect content.

        Args:
            content:  The text/content to inspect.
            source:   ContentSource value (e.g. "external_webpage").
            metadata: Optional context (URL, sender, etc.).

        Returns:
            InspectionResult with safe_to_use flag and any findings.
        """


# ── Data / DLP Inspection (Person 1 boundary) ────────────────────────────────

class DataInspectionPort(ABC):
    """
    Detects PII, secrets, and sensitive data in outgoing or processed content.

    Provided by Person 1 in production.
    Local adapter: LocalDataInspectionAdapter (development-only).
    """

    @abstractmethod
    async def inspect(
        self,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> "InspectionResult":
        """
        Scan content for sensitive data.

        Returns:
            InspectionResult with safe_to_use flag and any findings.
        """


# ── Policy Authorization (Person 4 boundary) ─────────────────────────────────

class PolicyPort(ABC):
    """
    Checks whether an agent action is authorized by policy.

    Provided by Person 4 (OPA-based) in production.
    Local adapter: LocalPolicyAdapter — defaults to DENY.
    """

    @abstractmethod
    async def authorize(
        self,
        context: "PolicyContext",
    ) -> "PolicyDecision":
        """
        Evaluate policy for the given action context.

        Returns:
            PolicyDecision with allow/deny and policy_id.
        """


# ── Human Approval (Person 4 boundary) ────────────────────────────────────────

class ApprovalPort(ABC):
    """
    Requests and verifies human approval for high-risk operations.

    Provided by Person 4 in production.
    Local adapter: LocalApprovalAdapter — requires explicit test approval token.
    """

    @abstractmethod
    async def request_approval(
        self,
        action: "ApprovalRequest",
    ) -> "ApprovalTicket":
        """
        Submit an action for human approval.

        Returns:
            ApprovalTicket with approval_request_id.
        """

    @abstractmethod
    async def verify_approval(
        self,
        approval_id: str,
        action_hash: str,
    ) -> "ApprovalVerification":
        """
        Verify that a previously-issued approval is still valid and matches
        the exact action hash.

        Args:
            approval_id:  The approval_request_id from request_approval().
            action_hash:  SHA-256 fingerprint of the exact action being executed.

        Returns:
            ApprovalVerification indicating valid/invalid and single-use consumed.
        """


# ── Audit Logging (Person 4 boundary) ────────────────────────────────────────

class AuditPort(ABC):
    """
    Records security decisions and operation outcomes.

    Provided by Person 4 in production.
    Local adapter: LocalAuditAdapter — writes structured JSON to stdout/log.
    """

    @abstractmethod
    async def record(
        self,
        event: "AuditEvent",
    ) -> None:
        """Record an audit event. Must never raise — log errors internally."""


# ── Secret Provider ───────────────────────────────────────────────────────────

class SecretProviderPort(ABC):
    """
    Retrieves credentials for connectors and providers.
    Credentials are NEVER exposed to LLM contexts.

    Local adapter: LocalSecretProvider — reads from environment variables.
    Production: Vault adapter.
    """

    @abstractmethod
    async def get_credential(
        self,
        credential_id: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """
        Retrieve a credential by ID.

        Returns:
            The secret value as a string.

        Raises:
            CredentialError if the credential is not found or access is denied.
        """


# ── Shared data models for port contracts ────────────────────────────────────

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class InspectionFinding:
    finding_type: str
    severity: str
    description: str
    location: str | None = None


@dataclass
class InspectionResult:
    safe_to_use: bool
    findings: list[InspectionFinding] = field(default_factory=list)
    summary: str = ""
    inspected_by: str = "unknown"


@dataclass
class PolicyContext:
    agent_id: str
    tenant_id: str
    capability: str
    operation: str
    resource: str | None = None
    additional: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    allowed: bool
    policy_id: str | None = None
    reason: str = ""


@dataclass
class ApprovalRequest:
    action_type: str          # "email_send", "payment", etc.
    agent_id: str
    tenant_id: str
    action_hash: str           # SHA-256 of canonical action
    action_summary: str
    action_details: dict[str, Any] = field(default_factory=dict)
    expires_seconds: int = 300


@dataclass
class ApprovalTicket:
    approval_request_id: str
    status: str                # "pending", "approved", "denied", "expired"
    expires_at: datetime | None = None


@dataclass
class ApprovalVerification:
    valid: bool
    consumed: bool             # True if this was the final use
    reason: str = ""


@dataclass
class AuditEvent:
    event_type: str            # "BROWSER_NAVIGATE", "EMAIL_SEND", "PAYMENT_CREATE", etc.
    agent_id: str
    tenant_id: str
    capability: str
    operation: str
    decision: str              # SecurityDecision value
    status: str                # OperationStatus value
    request_id: str
    resource: str | None = None
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
