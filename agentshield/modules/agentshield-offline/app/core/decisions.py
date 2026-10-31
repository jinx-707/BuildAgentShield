"""
AgentShield Offline — Decision builder helpers.

Convenience functions to construct consistent BaseOfflineResponse instances.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from app.core.contracts import (
    AuditEvent,
    BaseOfflineResponse,
    OfflineModule,
    RiskLevel,
    ResponseStatus,
    SecurityDecision,
    SecurityFinding,
)


def allow_response(
    *,
    request_id: str,
    module: OfflineModule,
    tool: str,
    result: Optional[dict[str, Any]] = None,
    execution_id: Optional[str] = None,
    findings: Optional[list[SecurityFinding]] = None,
    risk_level: RiskLevel = RiskLevel.LOW,
    reason: Optional[str] = None,
) -> BaseOfflineResponse:
    return BaseOfflineResponse(
        request_id=request_id,
        status=ResponseStatus.EXECUTED,
        decision=SecurityDecision.ALLOW,
        module=module,
        tool=tool,
        risk_level=risk_level,
        reason=reason,
        execution_id=execution_id or str(uuid.uuid4()),
        security_findings=findings or [],
        result=result,
    )


def deny_response(
    *,
    request_id: str,
    module: OfflineModule,
    tool: str,
    reason: str,
    risk_level: RiskLevel = RiskLevel.HIGH,
    findings: Optional[list[SecurityFinding]] = None,
) -> BaseOfflineResponse:
    return BaseOfflineResponse(
        request_id=request_id,
        status=ResponseStatus.BLOCKED,
        decision=SecurityDecision.DENY,
        module=module,
        tool=tool,
        risk_level=risk_level,
        reason=reason,
        security_findings=findings or [],
        result=None,
    )


def quarantine_response(
    *,
    request_id: str,
    module: OfflineModule,
    tool: str,
    reason: str,
    quarantine_id: str,
    risk_level: RiskLevel = RiskLevel.CRITICAL,
    findings: Optional[list[SecurityFinding]] = None,
) -> BaseOfflineResponse:
    return BaseOfflineResponse(
        request_id=request_id,
        status=ResponseStatus.QUARANTINED,
        decision=SecurityDecision.QUARANTINE,
        module=module,
        tool=tool,
        risk_level=risk_level,
        reason=reason,
        security_findings=findings or [],
        result={"quarantine_id": quarantine_id},
    )


def error_response(
    *,
    request_id: str,
    module: OfflineModule,
    tool: str,
    reason: str,
    risk_level: RiskLevel = RiskLevel.MEDIUM,
) -> BaseOfflineResponse:
    return BaseOfflineResponse(
        request_id=request_id,
        status=ResponseStatus.ERROR,
        decision=SecurityDecision.DENY,
        module=module,
        tool=tool,
        risk_level=risk_level,
        reason=reason,
        result=None,
    )


def unavailable_response(
    *,
    request_id: str,
    module: OfflineModule,
    tool: str,
    reason: str,
) -> BaseOfflineResponse:
    return BaseOfflineResponse(
        request_id=request_id,
        status=ResponseStatus.UNAVAILABLE,
        decision=SecurityDecision.DENY,
        module=module,
        tool=tool,
        risk_level=RiskLevel.HIGH,
        reason=reason,
        result=None,
    )


def build_audit_event(
    *,
    request_id: str,
    agent_id: str,
    tenant_id: str,
    module: OfflineModule,
    tool: str,
    operation: str,
    resource: Optional[str] = None,
    decision: SecurityDecision,
    risk_level: RiskLevel,
    reason: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> AuditEvent:
    return AuditEvent(
        request_id=request_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        module=module,
        tool=tool,
        operation=operation,
        resource=resource,
        decision=decision,
        risk_level=risk_level,
        reason=reason,
        metadata=metadata or {},
    )
