"""
AgentShield Offline — Integration Ports (Interfaces).

These are the replaceable interfaces between Person 2's offline module and:
  - Person 1: ContentInspectionPort, DataInspectionPort
  - Person 4: PolicyPort, AuditPort, ApprovalPort

Use Python Protocol (structural subtyping) so adapters do not need to
explicitly inherit from these classes.

HOW TO INTEGRATE:
  1. Person 1 provides a concrete ContentInspectionAdapter and/or
     DataInspectionAdapter. Wire it into the dependency injection container
     in app/api/dependencies.py.
  2. Person 4 provides a concrete PolicyAdapter, AuditAdapter, and
     ApprovalAdapter. Wire them similarly.
  3. The local development adapters below (LocalPolicy*, LocalAudit*, etc.)
     can then be removed or kept as fallbacks.

See docs/integration_guide.md for full instructions.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

from app.core.contracts import AuditEvent, SecurityDecision


# ---------------------------------------------------------------------------
# Policy authorisation port
# Future owner: Person 4 (OPA / central policy engine)
# ---------------------------------------------------------------------------


@runtime_checkable
class PolicyPort(Protocol):
    """
    Authorises an agent's requested operation against a central policy store.
    Person 4 will provide a production implementation backed by OPA.
    """

    async def authorize(
        self,
        *,
        agent_id: str,
        tenant_id: str,
        operation: str,
        resource: str,
        context: Optional[dict[str, Any]] = None,
    ) -> SecurityDecision:
        """
        Returns SecurityDecision.ALLOW or SecurityDecision.DENY.
        May also return REQUIRE_APPROVAL for human-in-the-loop flows.
        """
        ...


# ---------------------------------------------------------------------------
# Content inspection port
# Future owner: Person 1 (prompt injection detector, PII detector)
# ---------------------------------------------------------------------------


@runtime_checkable
class ContentInspectionPort(Protocol):
    """
    Inspects extracted document or command output text for:
      - Prompt injection attempts
      - PII exposure
      - DLP policy violations

    Person 1 will provide a production implementation.
    The local development inspector is a limited rule-based placeholder.
    """

    async def inspect(
        self,
        content: str,
        *,
        source_metadata: Optional[dict[str, Any]] = None,
    ) -> "ContentInspectionResult":
        ...


@runtime_checkable
class DataInspectionPort(Protocol):
    """
    Inspects data blobs (environment outputs, logs, API responses) for
    sensitive data such as credentials, PII and confidential patterns.

    Person 1 will provide a production implementation.
    """

    async def inspect(
        self,
        content: str,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> "DataInspectionResult":
        ...


# ---------------------------------------------------------------------------
# Audit port
# Future owner: Person 4 (central audit service / SIEM integration)
# ---------------------------------------------------------------------------


@runtime_checkable
class AuditPort(Protocol):
    """
    Records security audit events.
    Person 4 will provide a production implementation backed by the
    central audit infrastructure.
    """

    async def record(self, event: AuditEvent) -> None:
        ...


# ---------------------------------------------------------------------------
# Human approval port
# Future owner: Person 4 (global approval manager)
# ---------------------------------------------------------------------------


@runtime_checkable
class ApprovalPort(Protocol):
    """
    Requests human approval for high-risk operations.
    Person 4 will provide a production implementation with UI integration.
    """

    async def request_approval(
        self,
        *,
        agent_id: str,
        tenant_id: str,
        operation: str,
        resource: str,
        reason: str,
        context: Optional[dict[str, Any]] = None,
        timeout_seconds: int = 300,
    ) -> bool:
        """Returns True if approved, False if denied or timed out."""
        ...


# ---------------------------------------------------------------------------
# Result dataclasses (shared with both local adapters and future implementations)
# ---------------------------------------------------------------------------


from dataclasses import dataclass, field


@dataclass
class ContentInspectionResult:
    passed: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    inspector: str = "unknown"
    note: str = ""


@dataclass
class DataInspectionResult:
    passed: bool
    redacted_content: Optional[str] = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    inspector: str = "unknown"
    note: str = ""
