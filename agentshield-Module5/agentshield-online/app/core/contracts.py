"""
Standard Pydantic request/response contracts used across all online capabilities.
Identity and tenant context must ALWAYS come from authenticated backend context,
never from LLM-supplied arguments.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.core.decisions import SecurityDecision, OperationStatus


def _new_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:16]}"


def _new_execution_id() -> str:
    return f"exec_{uuid.uuid4().hex[:16]}"


class SecurityContext(BaseModel):
    """
    Authenticated identity and routing context.
    Populated by the API dependency layer from verified JWT / API key,
    NOT from LLM-supplied parameters.
    """
    request_id: str = Field(default_factory=_new_request_id)
    agent_id: str
    tenant_id: str
    capability: str
    operation: str
    resource: str | None = None
    session_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"frozen": True}


class SecurityFinding(BaseModel):
    """A single security finding from an inspection or policy check."""
    finding_type: str          # e.g. "PROMPT_INJECTION", "PII_DETECTED"
    severity: str              # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    location: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GatewayResponse(BaseModel):
    """Standard security gateway response for ALL online operations."""
    request_id: str
    status: OperationStatus
    decision: SecurityDecision
    capability: str
    operation: str | None = None
    reason: str | None = None
    policy_id: str | None = None
    execution_id: str | None = None
    result: dict[str, Any] | None = None
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @classmethod
    def allow(
        cls,
        ctx: SecurityContext,
        result: dict[str, Any] | None = None,
        findings: list[SecurityFinding] | None = None,
    ) -> "GatewayResponse":
        return cls(
            request_id=ctx.request_id,
            status=OperationStatus.EXECUTED,
            decision=SecurityDecision.ALLOW,
            capability=ctx.capability,
            operation=ctx.operation,
            execution_id=_new_execution_id(),
            result=result or {},
            security_findings=findings or [],
        )

    @classmethod
    def deny(
        cls,
        ctx: SecurityContext,
        reason: str,
        policy_id: str | None = None,
        findings: list[SecurityFinding] | None = None,
    ) -> "GatewayResponse":
        return cls(
            request_id=ctx.request_id,
            status=OperationStatus.BLOCKED,
            decision=SecurityDecision.DENY,
            capability=ctx.capability,
            operation=ctx.operation,
            reason=reason,
            policy_id=policy_id,
            security_findings=findings or [],
        )

    @classmethod
    def pending_approval(
        cls,
        ctx: SecurityContext,
        approval_request_id: str,
        reason: str = "Human approval required",
    ) -> "GatewayResponse":
        return cls(
            request_id=ctx.request_id,
            status=OperationStatus.PENDING_APPROVAL,
            decision=SecurityDecision.REQUIRE_APPROVAL,
            capability=ctx.capability,
            operation=ctx.operation,
            reason=reason,
            result={"approval_request_id": approval_request_id},
        )

    @classmethod
    def quarantined(
        cls,
        ctx: SecurityContext,
        reason: str,
        quarantine_id: str | None = None,
    ) -> "GatewayResponse":
        return cls(
            request_id=ctx.request_id,
            status=OperationStatus.QUARANTINED,
            decision=SecurityDecision.QUARANTINE,
            capability=ctx.capability,
            operation=ctx.operation,
            reason=reason,
            result={"quarantine_id": quarantine_id} if quarantine_id else {},
        )


class ContentClassification(BaseModel):
    """Trust classification applied to all externally-sourced content."""
    source: str        # ContentSource enum value
    trust_level: str   # TrustLevel enum value
    sender: str | None = None
    url: str | None = None
    inspected: bool = False
    findings: list[SecurityFinding] = Field(default_factory=list)
    safe_to_return: bool = False
