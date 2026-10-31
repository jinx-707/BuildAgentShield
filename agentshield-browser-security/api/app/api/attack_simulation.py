"""Attack simulation lab API routes for AgentShield Prompt 3.

Endpoints:
- POST /v1/attack-simulation/run — execute all attack scenarios
- GET /v1/attack-simulation/scenarios — scenario catalog
- GET /v1/attack-simulation/runs — list simulation runs (org-scoped)
- GET /v1/attack-simulation/runs/{run_id} — get a run with evidence (org-scoped)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.ai_models import (
    AttackSimulationRun,
    ScenarioEvidence,
)
from app.db.base import get_db_session
from app.enterprise.deps import get_current_principal, get_db, Principal
from app.services.attack_simulation import (
    AttackSimulationLab,
    ENFORCEMENT_RESULT_ERROR,
)

router = APIRouter(prefix="/v1/attack-simulation", tags=["attack-simulation"])


class SimulationRunRequest(BaseModel):
    organization_id: str
    agent_id: str | None = None
    session_id: str | None = None


class SimulationRunResponse(BaseModel):
    results: list[dict[str, Any]]


class ScenarioOut(BaseModel):
    scenario_id: str
    scenario_name: str
    threat_category: str | None


class SimulationRunOut(BaseModel):
    id: str
    scenario_id: str
    scenario_name: str
    threat_category: str | None
    attempted_action: str | None
    policy_decision: str | None
    enforcement_result: str
    created_at: str | None

    class Config:
        from_attributes = True


class SimulationEvidenceOut(BaseModel):
    id: str
    evidence_type: str
    description: str | None
    content: dict[str, Any]
    created_at: str | None

    class Config:
        from_attributes = True


class SimulationDetailOut(BaseModel):
    run: SimulationRunOut
    evidence: list[SimulationEvidenceOut]


# ---------------------------------------------------------------------------
# Scenario catalog
# ---------------------------------------------------------------------------


SCENARIOS = [
    ScenarioOut(
        scenario_id="unauthorized-destination",
        scenario_name="Unauthorized destination access",
        threat_category="suspicious_navigation",
    ),
    ScenarioOut(
        scenario_id="ssrf-metadata",
        scenario_name="SSRF against mock metadata endpoint",
        threat_category="suspicious_navigation",
    ),
    ScenarioOut(
        scenario_id="malicious-redirect",
        scenario_name="Malicious redirect to metadata",
        threat_category="unauthorized_redirect",
    ),
    ScenarioOut(
        scenario_id="indirect-prompt-injection",
        scenario_name="Indirect prompt injection",
        threat_category="indirect_prompt_injection",
    ),
    ScenarioOut(
        scenario_id="unauthorized-tool-invocation",
        scenario_name="Unauthorized tool invocation",
        threat_category="tool_misuse",
    ),
    ScenarioOut(
        scenario_id="excessive-permissions",
        scenario_name="Excessive permissions",
        threat_category="excessive_agent_permissions",
    ),
    ScenarioOut(
        scenario_id="sensitive-data-exfil",
        scenario_name="Sensitive data exfiltration",
        threat_category="data_exfiltration_attempt",
    ),
    ScenarioOut(
        scenario_id="session-ownership-violation",
        scenario_name="Session ownership violation",
        threat_category="session_isolation_violation",
    ),
    ScenarioOut(
        scenario_id="proxy-failure",
        scenario_name="Proxy failure / unreachable egress",
        threat_category="proxy_failure",
    ),
    ScenarioOut(
        scenario_id="direct-egress-bypass",
        scenario_name="Direct egress bypass attempt",
        threat_category="direct_egress_bypass",
    ),
]


@router.get("/scenarios", response_model=list[ScenarioOut])
def list_scenarios():
    return list(SCENARIOS)


# ---------------------------------------------------------------------------
# Run all scenarios
# ---------------------------------------------------------------------------


@router.post("/run", response_model=SimulationRunResponse, status_code=201)
def run_simulations(
    payload: SimulationRunRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    if principal.organization_id != payload.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )
    try:
        lab = AttackSimulationLab(
            base_url="http://127.0.0.1:8000",
            api_token=None,
        )
        results = lab.run_all(
            organization_id=payload.organization_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "SIMULATION_FAILED", "message": str(exc)},
        ) from exc
    return SimulationRunResponse(results=results)


# ---------------------------------------------------------------------------
# List runs
# ---------------------------------------------------------------------------


@router.get("/runs", response_model=list[SimulationRunOut])
def list_runs(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    rows = (
        db.query(AttackSimulationRun)
        .filter(AttackSimulationRun.organization_id == principal.organization_id)
        .order_by(AttackSimulationRun.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        SimulationRunOut(
            id=str(r.id),
            scenario_id=r.scenario_id,
            scenario_name=r.scenario_name,
            threat_category=r.threat_category,
            attempted_action=r.attempted_action,
            policy_decision=r.policy_decision,
            enforcement_result=r.enforcement_result,
            created_at=r.created_at.isoformat() if r.created_at else None,
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Get run with evidence
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}", response_model=SimulationDetailOut)
def get_run(
    run_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    run = (
        db.query(AttackSimulationRun)
        .filter(AttackSimulationRun.id == run_id)
        .first()
    )
    if not run:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "simulation run not found"})
    if run.organization_id != principal.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )
    evidence = (
        db.query(ScenarioEvidence)
        .filter(ScenarioEvidence.run_id == run_id)
        .order_by(ScenarioEvidence.created_at.asc())
        .all()
    )
    return SimulationDetailOut(
        run=SimulationRunOut(
            id=str(run.id),
            scenario_id=run.scenario_id,
            scenario_name=run.scenario_name,
            threat_category=run.threat_category,
            attempted_action=run.attempted_action,
            policy_decision=run.policy_decision,
            enforcement_result=run.enforcement_result,
            created_at=run.created_at.isoformat() if run.created_at else None,
        ),
        evidence=[
            SimulationEvidenceOut(
                id=str(e.id),
                evidence_type=e.evidence_type,
                description=e.description,
                content=e.content,
                created_at=e.created_at.isoformat() if e.created_at else None,
            )
            for e in evidence
        ],
    )
