"""Attack simulation lab API routes for AgentShield Prompt 3.

Endpoints:
- POST /v1/attack-simulation/run — execute all attack scenarios
- GET /v1/attack-simulation/scenarios — scenario catalog
- GET /v1/attack-simulation/runs — list simulation runs (org-scoped)
- GET /v1/attack-simulation/runs/{run_id} — get a run with evidence (org-scoped)
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.ai_models import (
    AttackSimulationRun,
    ScenarioEvidence,
)
from app.db.base import get_db_session
from app.config import get_settings
from app.db.models import Agent
from app.enterprise.auth import create_access_token
from app.enterprise.deps import get_current_principal, get_db, Principal
from app.services.attack_simulation import (
    AttackSimulationLab,
    ENFORCEMENT_RESULT_ERROR,
    SCENARIO_CATALOG,
    SCENARIO_ORDER,
)
from app.services.persistent_audit import PersistentAuditStore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/attack-simulation", tags=["attack-simulation"])


def _validate_external_target(target: str, organization_id: str) -> None:
    """Validate an externally-supplied target before executing against it.

    External targets are only permitted when explicitly authorized. The target
    must be an absolute http/https URL and must not target private/internal
    address ranges (loopback, link-local, RFC1918) to prevent using AgentShield
    as an open proxy against internal networks.
    """
    from urllib.parse import urlparse

    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "INVALID_EXTERNAL_TARGET",
                "message": "external target must be an absolute http/https URL",
            },
        )
    host = parsed.hostname.lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "EXTERNAL_TARGET_PRIVATE",
                "message": "external targets must not resolve to loopback or link-local addresses",
            },
        )
    # RFC1918 / private ranges (simple prefix check).
    private_prefixes = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
        "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
        "172.29.", "172.30.", "172.31.", "192.168.",
    )
    if any(host.startswith(p) for p in private_prefixes):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "EXTERNAL_TARGET_PRIVATE",
                "message": "external targets must not resolve to RFC1918 private addresses",
            },
        )


class SimulationRunRequest(BaseModel):
    organization_id: str
    agent_id: str
    session_id: str | None = None
    scenario_ids: list[str] | None = None
    external_target: str | None = None


class SimulationRunResponse(BaseModel):
    results: list[dict[str, Any]]


class ScenarioOut(BaseModel):
    scenario_id: str
    scenario_name: str
    threat_category: str | None
    category: str | None


class SimulationRunOut(BaseModel):
    id: str
    scenario_id: str
    scenario_name: str
    threat_category: str | None
    category: str | None
    attempted_action: str | None
    policy_decision: str | None
    enforcement_result: str
    requests_attempted: int | None = None
    requests_allowed: int | None = None
    requests_blocked: int | None = None
    detection_outcome: str | None = None
    execution_duration_ms: int | None = None
    failure_reason: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
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
# Scenario catalog (grouped into six security categories)
# ---------------------------------------------------------------------------


def _build_scenarios() -> list[ScenarioOut]:
    out: list[ScenarioOut] = []
    for scenario_id in SCENARIO_ORDER:
        cfg = SCENARIO_CATALOG[scenario_id]
        out.append(
            ScenarioOut(
                scenario_id=cfg["scenario_id"],
                scenario_name=cfg["scenario_name"],
                threat_category=cfg.get("threat_category"),
                category=cfg.get("category"),
            )
        )
    return out


SCENARIOS = _build_scenarios()


@router.get("/scenarios", response_model=list[ScenarioOut])
def list_scenarios():
    return list(SCENARIOS)


# ---------------------------------------------------------------------------
# Run all scenarios
# ---------------------------------------------------------------------------


@router.post("/run", response_model=SimulationRunResponse, status_code=201)
def run_simulations(
    request: Request,
    payload: SimulationRunRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    if principal.organization_id != payload.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )

    # Resolve the agent within the caller's organization for service-to-service
    # authentication. Internal calls to /v1/ai-agent/action require an agent
    # principal (subject=agent_id, roles=["agent"]); a user principal alone is
    # insufficient because the action endpoint resolves the agent via
    # principal.agent_id.
    agent = (
        db.query(Agent)
        .filter(
            Agent.agent_id == payload.agent_id,
            Agent.organization_id == principal.organization_id,
        )
        .first()
    )
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "AGENT_NOT_FOUND", "message": "agent not found in organization"},
        )

    # Issue a short-lived agent JWT so the simulation lab can authenticate its
    # internal enforcement-gateway calls as this agent within this org.
    agent_token = create_access_token(
        subject=agent.agent_id,
        organization_id=str(agent.organization_id),
        roles=["agent"],
    )

    scenario_ids = payload.scenario_ids or SCENARIO_ORDER

    # Validate scenario ids against the catalog.
    unknown = [sid for sid in scenario_ids if sid not in SCENARIO_CATALOG]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "UNKNOWN_SCENARIO",
                "message": f"unknown scenario(s): {', '.join(unknown)}",
            },
        )

    # External targets require explicit authorization. An external_target may
    # only be exercised when the caller holds the external:run permission and
    # the target is within the organization's authorized scope.
    if payload.external_target:
        principal.require_permission("external:run")
        _validate_external_target(payload.external_target, principal.organization_id)

    try:
        settings = get_settings()
        targets = {
            "prompt-injection": settings.attack_prompt_injection_target_url,
            "phishing": settings.attack_phishing_target_url,
            "ssrf": settings.attack_ssrf_target_url,
            "mock-metadata": settings.attack_mock_metadata_url,
            "malicious-download": settings.attack_malicious_download_target_url,
            "resource-exhaustion": settings.attack_resource_exhaustion_target_url,
            "dns-rebinding": settings.attack_dns_rebinding_target_url,
            "data-exfiltration": settings.attack_data_exfiltration_sink_url,
        }
        lab = AttackSimulationLab(
            base_url="http://127.0.0.1:8000",
            api_token=agent_token,
            targets=targets,
        )
        try:
            results = lab.run_selected(
                scenario_ids=scenario_ids,
                organization_id=payload.organization_id,
                agent_id=agent.id,
                session_id=payload.session_id,
                external_target=payload.external_target,
            )
            # Persist an audit event for every scenario executed, so the red-team
            # lab run is durable and organization-scoped in the audit trail.
            try:
                audit_store = PersistentAuditStore()
                actor = payload.agent_id
                for result in results:
                    audit_store.add(
                        type="action.execute",
                        actor=actor,
                        organization_id=payload.organization_id,
                        session_id=payload.session_id,
                        target=result.get("scenario_id"),
                        decision=result.get("policy_decision"),
                        reason=result.get("enforcement_result"),
                        metadata={
                            "scenario_id": result.get("scenario_id"),
                            "scenario_name": result.get("scenario_name"),
                            "enforcement_result": result.get("enforcement_result"),
                            "evidence": result.get("evidence", {}),
                        },
                    )
            except Exception:  # noqa: BLE001
                logger.exception("attack_simulation_audit_persist_failed")
        finally:
            lab.close()
    except Exception as exc:  # noqa: BLE001
        request_id = request.headers.get("x-request-id", "unknown")
        logger.error(
            "attack_simulation_failed",
            extra={
                "request_id": request_id,
                "organization_id": payload.organization_id,
                "error": str(exc),
            },
        )
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
            category=SCENARIO_CATALOG.get(r.scenario_id, {}).get("category"),
            attempted_action=r.attempted_action,
            policy_decision=r.policy_decision,
            enforcement_result=r.enforcement_result,
            requests_attempted=r.requests_attempted,
            requests_allowed=r.requests_allowed,
            requests_blocked=r.requests_blocked,
            detection_outcome=r.detection_outcome,
            execution_duration_ms=r.execution_duration_ms,
            failure_reason=r.failure_reason,
            started_at=r.started_at.isoformat() if r.started_at else None,
            completed_at=r.completed_at.isoformat() if r.completed_at else None,
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
            category=SCENARIO_CATALOG.get(run.scenario_id, {}).get("category"),
            attempted_action=run.attempted_action,
            policy_decision=run.policy_decision,
            enforcement_result=run.enforcement_result,
            requests_attempted=run.requests_attempted,
            requests_allowed=run.requests_allowed,
            requests_blocked=run.requests_blocked,
            detection_outcome=run.detection_outcome,
            execution_duration_ms=run.execution_duration_ms,
            failure_reason=run.failure_reason,
            started_at=run.started_at.isoformat() if run.started_at else None,
            completed_at=run.completed_at.isoformat() if run.completed_at else None,
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


# ---------------------------------------------------------------------------
# Run a single scenario
# ---------------------------------------------------------------------------


@router.post(
    "/scenarios/{scenario_id}/run",
    response_model=SimulationRunResponse,
    status_code=201,
)
def run_single_scenario(
    scenario_id: str,
    request: Request,
    payload: SimulationRunRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    if scenario_id not in SCENARIO_CATALOG:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "scenario not found"})
    if principal.organization_id != payload.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )

    agent = (
        db.query(Agent)
        .filter(
            Agent.agent_id == payload.agent_id,
            Agent.organization_id == principal.organization_id,
        )
        .first()
    )
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "AGENT_NOT_FOUND", "message": "agent not found in organization"},
        )

    agent_token = create_access_token(
        subject=agent.agent_id,
        organization_id=str(agent.organization_id),
        roles=["agent"],
    )

    if payload.external_target:
        principal.require_permission("external:run")
        _validate_external_target(payload.external_target, principal.organization_id)

    try:
        settings = get_settings()
        targets = {
            "prompt-injection": settings.attack_prompt_injection_target_url,
            "phishing": settings.attack_phishing_target_url,
            "ssrf": settings.attack_ssrf_target_url,
            "mock-metadata": settings.attack_mock_metadata_url,
            "malicious-download": settings.attack_malicious_download_target_url,
            "resource-exhaustion": settings.attack_resource_exhaustion_target_url,
            "dns-rebinding": settings.attack_dns_rebinding_target_url,
            "data-exfiltration": settings.attack_data_exfiltration_sink_url,
        }
        lab = AttackSimulationLab(
            base_url="http://127.0.0.1:8000",
            api_token=agent_token,
            targets=targets,
        )
        try:
            results = lab.run_selected(
                scenario_ids=[scenario_id],
                organization_id=payload.organization_id,
                agent_id=agent.id,
                session_id=payload.session_id,
                external_target=payload.external_target,
            )
        finally:
            lab.close()
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        request_id = request.headers.get("x-request-id", "unknown")
        logger.error(
            "attack_simulation_single_failed",
            extra={
                "request_id": request_id,
                "organization_id": payload.organization_id,
                "scenario_id": scenario_id,
                "error": str(exc),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "SIMULATION_FAILED", "message": str(exc)},
        ) from exc
    return SimulationRunResponse(results=results)

