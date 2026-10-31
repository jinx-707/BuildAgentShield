"""AI Agent Security API routes for AgentShield Prompt 3.

Endpoint groups:
- /v1/ai-agent/authenticate — agent login (agent_id + secret)
- /v1/ai-agent/action — execute an agent action through enforcement
- /v1/ai-agent/executions — list agent executions (org-scoped)
- /v1/ai-agent/threats — list threat detections (org-scoped)
- /v1/ai-agent/dlp — list DLP findings (org-scoped)
- /v1/ai-agent/risk — list risk assessments (org-scoped)
- /v1/ai-agent/tools — list tool decisions (org-scoped)
- /v1/ai-agent/simulations — list attack simulation runs (org-scoped)

All endpoints are organization-scoped; cross-tenant access is impossible by
construction.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.ai_models import (
    AgentExecution,
    AttackSimulationRun,
    DlpFinding,
    RiskAssessment,
    ThreatDetection,
    ToolDecision,
)
from app.db.base import get_db_session
from app.db.models import Agent
from app.enterprise.auth import create_access_token
from app.enterprise.deps import get_current_principal, get_db, Principal
from app.services.ai_agent_security import AgentSecurityService

router = APIRouter(prefix="/v1/ai-agent", tags=["ai-agent"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AgentAuthenticateRequest(BaseModel):
    agent_id: str
    secret: str


class AgentAuthenticateResponse(BaseModel):
    agent_id: str
    organization_id: str
    name: str
    access_token: str
    token_type: str = "bearer"


class ActionRequest(BaseModel):
    action: str = Field(
        description="navigate, click, type, scroll, extract, screenshot, tool_call, file_download, form_submit, sensitive_access"
    )
    target: Optional[str] = Field(default=None, description="URL or action target")
    tool_name: Optional[str] = Field(default=None)
    tool_args: dict[str, Any] = Field(default_factory=dict)
    session_id: Optional[str] = None


class ActionResponse(BaseModel):
    execution_id: str
    agent_id: str
    organization_id: str
    action: str
    decision: str
    reason: str
    severity: str
    risk_score: Optional[int]
    threat: dict[str, Any]
    dlp: dict[str, Any]
    risk: dict[str, Any]
    enforcement: Optional[dict[str, Any]]
    created_at: Optional[str]


class ExecutionOut(BaseModel):
    id: str
    agent_id: str
    session_id: Optional[str]
    action: str
    target: Optional[str]
    decision: Optional[str]
    severity: str
    risk_score: Optional[int]
    trust_label: str
    created_at: Optional[str]

    class Config:
        from_attributes = True


class ThreatOut(BaseModel):
    id: str
    agent_id: Optional[str]
    session_id: Optional[str]
    threat_category: str
    detection_module: str
    detection_reason: Optional[str]
    severity: str
    action_taken: Optional[str]
    target: Optional[str]
    created_at: Optional[str]

    class Config:
        from_attributes = True


class DlpOut(BaseModel):
    id: str
    agent_id: Optional[str]
    session_id: Optional[str]
    detection_rule: str
    detection_reason: Optional[str]
    severity: str
    confidence: Optional[int]
    action_taken: Optional[str]
    target: Optional[str]
    created_at: Optional[str]

    class Config:
        from_attributes = True


class RiskOut(BaseModel):
    id: str
    agent_id: Optional[str]
    execution_id: Optional[str]
    risk_score: int
    severity: str
    enforcement_decision: str
    detection_reasons: list[str]
    created_at: Optional[str]

    class Config:
        from_attributes = True


class ToolDecisionOut(BaseModel):
    id: str
    agent_id: str
    session_id: Optional[str]
    tool_name: str
    decision: str
    reason: Optional[str]
    risk_score: Optional[int]
    created_at: Optional[str]

    class Config:
        from_attributes = True


class SimulationOut(BaseModel):
    id: str
    agent_id: Optional[str]
    session_id: Optional[str]
    scenario_id: str
    scenario_name: str
    threat_category: Optional[str]
    attempted_action: Optional[str]
    policy_decision: Optional[str]
    enforcement_result: str
    created_at: Optional[str]

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def _get_service() -> AgentSecurityService:
    return AgentSecurityService()


def _iso(dt) -> Optional[str]:
    if dt is None:
        return None
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)


# ---------------------------------------------------------------------------
# Agent authentication
# ---------------------------------------------------------------------------


@router.post("/authenticate", response_model=AgentAuthenticateResponse)
def authenticate_agent(
    payload: AgentAuthenticateRequest,
    db: Session = Depends(get_db),
):
    service = _get_service()
    agent = service.authenticate_agent(
        agent_id=payload.agent_id, secret=payload.secret, db=db
    )
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_AGENT_CREDENTIALS", "message": "invalid agent id or secret"},
        )
    # Issue a JWT so the SDK can call /action without re-sending the secret.
    token = create_access_token(
        subject=agent.agent_id,
        organization_id=str(agent.organization_id),
        roles=["agent"],
    )
    return AgentAuthenticateResponse(
        agent_id=agent.agent_id,
        organization_id=str(agent.organization_id),
        name=agent.name,
        access_token=token,
    )


# ---------------------------------------------------------------------------
# Action execution
# ---------------------------------------------------------------------------


@router.post("/action", response_model=ActionResponse)
async def execute_action(
    payload: ActionRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    # Resolve the agent. Either a user principal (on behalf of an agent) or
    # the agent itself must be identifiable and organization-scoped.
    agent = None
    if principal.agent_id and db is not None:
        agent = (
            db.query(Agent)
            .filter(
                Agent.agent_id == principal.agent_id,
                Agent.organization_id == principal.organization_id,
            )
            .first()
        )
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AGENT_IDENTIFICATION_REQUIRED", "message": "agent identification required"},
        )

    service = _get_service()
    result = await service.execute_action(
        agent=agent,
        organization_id=principal.organization_id,
        action=payload.action,
        target=payload.target,
        tool_name=payload.tool_name,
        tool_args=payload.tool_args,
        session_id=payload.session_id,
        request_id=None,
        db=db,
    )

    return ActionResponse(**result)


# ---------------------------------------------------------------------------
# List endpoints (organization-scoped)
# ---------------------------------------------------------------------------


def _list(model, org_id, principal, db, limit=100, offset=0, order_by=None):
    if principal.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )
    query = db.query(model).filter(model.organization_id == org_id)
    if order_by is not None:
        query = query.order_by(order_by.desc())
    return query.offset(offset).limit(limit).all()


@router.get("/organizations/{org_id}/executions", response_model=list[ExecutionOut])
def list_executions(
    org_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    rows = _list(
        AgentExecution,
        org_id,
        principal,
        db,
        limit,
        offset,
        AgentExecution.created_at,
    )
    return [
        ExecutionOut(
            id=str(r.id),
            agent_id=str(r.agent_id),
            session_id=r.session_id,
            action=r.action,
            target=r.target,
            decision=r.decision,
            severity=r.severity,
            risk_score=r.risk_score,
            trust_label=r.trust_label,
            created_at=_iso(r.created_at),
        )
        for r in rows
    ]


@router.get("/organizations/{org_id}/threats", response_model=list[ThreatOut])
def list_threats(
    org_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    rows = _list(
        ThreatDetection,
        org_id,
        principal,
        db,
        limit,
        offset,
        ThreatDetection.created_at,
    )
    return [
        ThreatOut(
            id=str(r.id),
            agent_id=str(r.agent_id) if r.agent_id else None,
            session_id=r.session_id,
            threat_category=r.threat_category,
            detection_module=r.detection_module,
            detection_reason=r.detection_reason,
            severity=r.severity,
            action_taken=r.action_taken,
            target=r.target,
            created_at=_iso(r.created_at),
        )
        for r in rows
    ]


@router.get("/organizations/{org_id}/dlp", response_model=list[DlpOut])
def list_dlp(
    org_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    rows = _list(
        DlpFinding,
        org_id,
        principal,
        db,
        limit,
        offset,
        DlpFinding.created_at,
    )
    return [
        DlpOut(
            id=str(r.id),
            agent_id=str(r.agent_id) if r.agent_id else None,
            session_id=r.session_id,
            detection_rule=r.detection_rule,
            detection_reason=r.detection_reason,
            severity=r.severity,
            confidence=r.confidence,
            action_taken=r.action_taken,
            target=r.target,
            created_at=_iso(r.created_at),
        )
        for r in rows
    ]


@router.get("/organizations/{org_id}/risk", response_model=list[RiskOut])
def list_risk(
    org_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    rows = _list(
        RiskAssessment,
        org_id,
        principal,
        db,
        limit,
        offset,
        RiskAssessment.created_at,
    )
    return [
        RiskOut(
            id=str(r.id),
            agent_id=str(r.agent_id) if r.agent_id else None,
            execution_id=str(r.execution_id) if r.execution_id else None,
            risk_score=r.risk_score,
            severity=r.severity,
            enforcement_decision=r.enforcement_decision,
            detection_reasons=list(r.detection_reasons or []),
            created_at=_iso(r.created_at),
        )
        for r in rows
    ]


@router.get("/organizations/{org_id}/tools", response_model=list[ToolDecisionOut])
def list_tools(
    org_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    rows = _list(
        ToolDecision,
        org_id,
        principal,
        db,
        limit,
        offset,
        ToolDecision.created_at,
    )
    return [
        ToolDecisionOut(
            id=str(r.id),
            agent_id=str(r.agent_id),
            session_id=r.session_id,
            tool_name=r.tool_name,
            decision=r.decision,
            reason=r.reason,
            risk_score=r.risk_score,
            created_at=_iso(r.created_at),
        )
        for r in rows
    ]


@router.get("/organizations/{org_id}/simulations", response_model=list[SimulationOut])
def list_simulations(
    org_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    rows = _list(
        AttackSimulationRun,
        org_id,
        principal,
        db,
        limit,
        offset,
        AttackSimulationRun.created_at,
    )
    return [
        SimulationOut(
            id=str(r.id),
            agent_id=str(r.agent_id) if r.agent_id else None,
            session_id=r.session_id,
            scenario_id=r.scenario_id,
            scenario_name=r.scenario_name,
            threat_category=r.threat_category,
            attempted_action=r.attempted_action,
            policy_decision=r.policy_decision,
            enforcement_result=r.enforcement_result,
            created_at=_iso(r.created_at),
        )
        for r in rows
    ]
