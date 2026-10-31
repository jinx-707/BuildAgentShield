"""Cyber Range Campaign API routes for AgentShield.

Endpoints:
- POST /v1/simulations/campaigns — create a campaign
- GET /v1/simulations/campaigns — list organization campaigns
- GET /v1/simulations/campaigns/{campaign_id} — get campaign details
- POST /v1/simulations/campaigns/{campaign_id}/cancel — cancel campaign
- GET /v1/simulations/scenarios — list available scenarios
- GET /v1/simulations/scenarios/{scenario_id} — get scenario details
- POST /v1/simulations/scenarios/{scenario_id}/run — run a single scenario
- GET /v1/simulations/{simulation_id} — get simulation status
- GET /v1/simulations/{simulation_id}/evidence — get evidence
- GET /v1/simulations/{simulation_id}/events — retrieve simulation events (SSE)
- GET /v1/simulations/campaigns/{campaign_id}/report — retrieve final report
- GET /v1/simulations/campaigns/{campaign_id}/events — stream campaign events (SSE)
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.base import get_db_session
from app.enterprise.deps import get_current_principal, get_db, Principal

router = APIRouter(prefix="/v1/simulations", tags=["simulations"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CampaignCreateRequest(BaseModel):
    organization_id: str
    user_id: str
    name: str
    description: Optional[str] = None
    policy_version: str = "default"
    scenario_ids: list[str] = Field(default_factory=list)
    execution_mode: str = "sequential"
    max_concurrency: int = 1
    agent_id: Optional[str] = None


class CampaignResponse(BaseModel):
    id: str
    organization_id: str
    user_id: str
    name: str
    description: Optional[str]
    policy_version: str
    status: str
    scenario_ids: list[str]
    execution_mode: str
    max_concurrency: int
    started_at: Optional[str]
    completed_at: Optional[str]
    error: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


class ScenarioInfo(BaseModel):
    scenario_id: str
    name: str
    description: str
    target_service: str
    risk_category: str
    required_services: list[str]
    available: bool = True


class SimulationResponse(BaseModel):
    id: str
    campaign_id: str
    organization_id: str
    scenario_id: str
    target_id: str
    status: str
    assessment: Optional[str]
    policy_version: str
    browser_session_id: Optional[str]
    agent_id: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    error: Optional[str]
    agent_shield_decision: Optional[str]
    proxy_decision: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


class EvidenceResponse(BaseModel):
    id: str
    simulation_id: str
    evidence_type: str
    description: Optional[str]
    content: dict[str, Any]
    source: str
    created_at: Optional[str]

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Scenario catalog (static - matches simulation-controller)
# ---------------------------------------------------------------------------


SCENARIOS = {
    "prompt-injection": {
        "scenario_id": "prompt-injection",
        "name": "Indirect Prompt Injection",
        "description": "Test if malicious webpage content can inject instructions into an AI agent",
        "target_service": "prompt-injection-target",
        "risk_category": "AI Security",
        "required_services": ["prompt-injection-target", "browser-worker", "egress-proxy"],
    },
    "phishing": {
        "scenario_id": "phishing",
        "name": "Phishing & Credential Harvesting",
        "description": "Test detection of synthetic phishing pages and credential collection attempts",
        "target_service": "phishing-target",
        "risk_category": "Social Engineering",
        "required_services": ["phishing-target", "browser-worker", "egress-proxy"],
    },
    "ssrf": {
        "scenario_id": "ssrf",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Test SSRF protection against mock internal metadata service",
        "target_service": "ssrf-target",
        "risk_category": "Network Security",
        "required_services": ["ssrf-target", "mock-metadata", "browser-worker", "egress-proxy"],
    },
    "malicious-download": {
        "scenario_id": "malicious-download",
        "name": "Malicious File Downloads",
        "description": "Test file download inspection, MIME type validation, and quarantine",
        "target_service": "malicious-download-target",
        "risk_category": "Malware",
        "required_services": ["malicious-download-target", "browser-worker", "egress-proxy"],
    },
    "resource-exhaustion": {
        "scenario_id": "resource-exhaustion",
        "name": "Resource Exhaustion / Fork Bomb",
        "description": "Test detection of bounded resource exhaustion attempts",
        "target_service": "resource-exhaustion-target",
        "risk_category": "Denial of Service",
        "required_services": ["resource-exhaustion-target", "browser-worker", "egress-proxy"],
    },
    "dns-rebinding": {
        "scenario_id": "dns-rebinding",
        "name": "DNS Rebinding",
        "description": "Test DNS rebinding protection and destination validation",
        "target_service": "dns-rebinding-target",
        "risk_category": "Network Security",
        "required_services": ["dns-rebinding-target", "browser-worker", "egress-proxy"],
    },
    "data-exfiltration": {
        "scenario_id": "data-exfiltration",
        "name": "Data Exfiltration",
        "description": "Test DLP detection and blocking of synthetic secret exfiltration",
        "target_service": "data-exfiltration-sink",
        "risk_category": "Data Loss",
        "required_services": ["data-exfiltration-sink", "browser-worker", "egress-proxy"],
    },
}


# ---------------------------------------------------------------------------
# Scenario endpoints
# ---------------------------------------------------------------------------


@router.get("/scenarios", response_model=list[ScenarioInfo])
async def list_scenarios():
    results = []
    for scenario_id, config in SCENARIOS.items():
        # Check if required services are healthy
        available = True
        for svc in config["required_services"]:
            try:
                import httpx
                async with httpx.AsyncClient(timeout=2.0) as client:
                    if svc == "mock-metadata":
                        continue
                    port_map = {
                        "prompt-injection-target": 8081,
                        "phishing-target": 8082,
                        "ssrf-target": 8083,
                        "malicious-download-target": 8084,
                        "resource-exhaustion-target": 8085,
                        "dns-rebinding-target": 8086,
                        "data-exfiltration-sink": 8087,
                        "browser-worker": 8080,
                        "egress-proxy": 9090,
                    }
                    port = port_map.get(svc, 8081)
                    resp = await client.get(f"http://{svc}:{port}/health")
                    if resp.status_code != 200:
                        available = False
                        break
            except Exception:
                available = False
                break
        results.append(
            ScenarioInfo(
                scenario_id=config["scenario_id"],
                name=config["name"],
                description=config["description"],
                target_service=config["target_service"],
                risk_category=config["risk_category"],
                required_services=config["required_services"],
                available=available,
            )
        )
    return results


@router.get("/scenarios/{scenario_id}", response_model=ScenarioInfo)
async def get_scenario(scenario_id: str):
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Scenario not found")
    config = SCENARIOS[scenario_id]
    return ScenarioInfo(
        scenario_id=config["scenario_id"],
        name=config["name"],
        description=config["description"],
        target_service=config["target_service"],
        risk_category=config["risk_category"],
        required_services=config["required_services"],
        available=True,
    )


# ---------------------------------------------------------------------------
# Campaign endpoints
# ---------------------------------------------------------------------------


@router.post("/campaigns", response_model=CampaignResponse, status_code=201)
async def create_campaign(
    request: CampaignCreateRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    # Validate organization access
    if principal.organization_id != request.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )

    # Validate scenarios
    for sid in request.scenario_ids:
        if sid not in SCENARIOS:
            raise HTTPException(status_code=400, detail=f"Unknown scenario: {sid}")

    # Create campaign record
    import uuid
    from datetime import datetime, timezone

    campaign_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Store in database (using raw SQL for new tables)
    db.execute(
        text(
            """
            INSERT INTO simulation_campaigns (id, organization_id, user_id, name, description, policy_version, status, scenario_ids, execution_mode, max_concurrency, created_at, updated_at)
            VALUES (:id, :org_id, :user_id, :name, :desc, :policy, 'QUEUED', :scenarios, :mode, :concurrency, :created, :updated)
            """
        ),
        {
            "id": campaign_id,
            "org_id": request.organization_id,
            "user_id": request.user_id,
            "name": request.name,
            "desc": request.description,
            "policy": request.policy_version,
            "scenarios": request.scenario_ids,
            "mode": request.execution_mode,
            "concurrency": request.max_concurrency,
            "created": now,
            "updated": now,
        },
    )
    db.commit()

    # Create simulation records for each scenario
    for scenario_id in request.scenario_ids:
        sim_id = str(uuid.uuid4())
        config = SCENARIOS[scenario_id]
        db.execute(
            text(
                """
                INSERT INTO simulations (id, campaign_id, organization_id, scenario_id, target_id, status, policy_version, created_at, updated_at)
                VALUES (:id, :campaign_id, :org_id, :scenario_id, :target_id, 'QUEUED', :policy, :created, :updated)
                """
            ),
            {
                "id": sim_id,
                "campaign_id": campaign_id,
                "org_id": request.organization_id,
                "scenario_id": scenario_id,
                "target_id": config["target_service"],
                "policy": request.policy_version,
                "created": now,
                "updated": now,
            },
        )
    db.commit()

    # Trigger async execution via simulation-controller
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                "http://simulation-controller:8090/v1/simulations/campaigns/internal/start",
                json={"campaign_id": campaign_id},
            )
    except Exception as e:
        # Log but don't fail - controller will pick up QUEUED campaigns
        pass

    return CampaignResponse(
        id=campaign_id,
        organization_id=request.organization_id,
        user_id=request.user_id,
        name=request.name,
        description=request.description,
        policy_version=request.policy_version,
        status="QUEUED",
        scenario_ids=request.scenario_ids,
        execution_mode=request.execution_mode,
        max_concurrency=request.max_concurrency,
        started_at=None,
        completed_at=None,
        error=None,
        created_at=now,
    )


@router.get("/campaigns", response_model=list[CampaignResponse])
async def list_campaigns(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    rows = db.execute(
        text(
            """
            SELECT id, organization_id, user_id, name, description, policy_version, status,
                   scenario_ids, execution_mode, max_concurrency, started_at, completed_at, error, created_at
            FROM simulation_campaigns
            WHERE organization_id = :org_id
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {"org_id": principal.organization_id, "limit": limit, "offset": offset},
    ).fetchall()

    return [
        CampaignResponse(
            id=str(r.id),
            organization_id=str(r.organization_id),
            user_id=str(r.user_id),
            name=r.name,
            description=r.description,
            policy_version=r.policy_version,
            status=r.status,
            scenario_ids=r.scenario_ids,
            execution_mode=r.execution_mode,
            max_concurrency=r.max_concurrency,
            started_at=r.started_at.isoformat() if r.started_at else None,
            completed_at=r.completed_at.isoformat() if r.completed_at else None,
            error=r.error,
            created_at=r.created_at.isoformat() if r.created_at else None,
        )
        for r in rows
    ]


@router.get("/campaigns/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    campaign_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    row = db.execute(
        text(
            """
            SELECT id, organization_id, user_id, name, description, policy_version, status,
                   scenario_ids, execution_mode, max_concurrency, started_at, completed_at, error, created_at
            FROM simulation_campaigns
            WHERE id = :id
            """
        ),
        {"id": campaign_id},
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Campaign not found")

    if str(row.organization_id) != principal.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )

    return CampaignResponse(
        id=str(row.id),
        organization_id=str(row.organization_id),
        user_id=str(row.user_id),
        name=row.name,
        description=row.description,
        policy_version=row.policy_version,
        status=row.status,
        scenario_ids=row.scenario_ids,
        execution_mode=row.execution_mode,
        max_concurrency=row.max_concurrency,
        started_at=row.started_at.isoformat() if row.started_at else None,
        completed_at=row.completed_at.isoformat() if row.completed_at else None,
        error=row.error,
        created_at=row.created_at.isoformat() if row.created_at else None,
    )


@router.post("/campaigns/{campaign_id}/cancel")
async def cancel_campaign(
    campaign_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    row = db.execute(
        text(
            "SELECT organization_id, status FROM simulation_campaigns WHERE id = :id"
        ),
        {"id": campaign_id},
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Campaign not found")

    if str(row.organization_id) != principal.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )

    if row.status in ("COMPLETED", "FAILED", "CANCELLED"):
        raise HTTPException(status_code=400, detail="Campaign already finished")

    # Update campaign status
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        text(
            "UPDATE simulation_campaigns SET status = 'CANCELLED', completed_at = :now, updated_at = :now WHERE id = :id"
        ),
        {"id": campaign_id, "now": now},
    )

    # Cancel pending simulations
    db.execute(
        text(
            """
            UPDATE simulations SET status = 'CANCELLED', completed_at = :now, updated_at = :now
            WHERE campaign_id = :id AND status IN ('QUEUED', 'INITIALIZING', 'RUNNING')
            """
        ),
        {"id": campaign_id, "now": now},
    )
    db.commit()

    # Log event
    db.execute(
        text(
            """
            INSERT INTO campaign_events (id, campaign_id, event_type, message, data, created_at)
            VALUES (:id, :campaign_id, 'campaign_cancelled', 'Campaign cancelled by user', '{}', :now)
            """
        ),
        {"id": str(uuid.uuid4()), "campaign_id": campaign_id, "now": now},
    )
    db.commit()

    return {"status": "cancelled"}


@router.get("/campaigns/{campaign_id}/report")
async def get_campaign_report(
    campaign_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    campaign = db.execute(
        text("SELECT * FROM simulation_campaigns WHERE id = :id"),
        {"id": campaign_id},
    ).fetchone()

    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    if str(campaign.organization_id) != principal.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )

    simulations = db.execute(
        text("SELECT * FROM simulations WHERE campaign_id = :id ORDER BY created_at"),
        {"id": campaign_id},
    ).fetchall()

    passed = sum(1 for s in simulations if s.assessment == "PASS")
    failed = sum(1 for s in simulations if s.assessment == "FAIL")
    errors = sum(1 for s in simulations if s.assessment == "ERROR")
    inconclusive = sum(1 for s in simulations if s.assessment == "INCONCLUSIVE")

    detection_coverage = passed / len(simulations) * 100 if simulations else 0
    enforcement_coverage = (
        sum(1 for s in simulations if s.agent_shield_decision == "deny") / len(simulations) * 100
        if simulations
        else 0
    )

    failed_controls = [
        {
            "scenario_id": s.scenario_id,
            "scenario_name": SCENARIOS.get(s.scenario_id, {}).get("name", s.scenario_id),
            "assessment": s.assessment or "UNKNOWN",
            "error": s.error,
        }
        for s in simulations
        if s.assessment in ("FAIL", "ERROR")
    ]

    inconclusive_tests = [
        {
            "scenario_id": s.scenario_id,
            "scenario_name": SCENARIOS.get(s.scenario_id, {}).get("name", s.scenario_id),
            "reason": s.error or "Insufficient evidence",
        }
        for s in simulations
        if s.assessment == "INCONCLUSIVE"
    ]

    recommendations = []
    for s in simulations:
        if s.assessment == "FAIL":
            recommendations.append(f"Review {s.scenario_id} policy: control was bypassed")
        elif s.assessment == "ERROR":
            recommendations.append(f"Investigate {s.scenario_id} execution error: {s.error}")
    if not recommendations:
        recommendations.append("All controls verified. Consider expanding test coverage.")

    return {
        "campaign_id": str(campaign.id),
        "campaign_name": campaign.name,
        "organization_id": str(campaign.organization_id),
        "policy_version": campaign.policy_version,
        "execution_mode": campaign.execution_mode,
        "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
        "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
        "summary": {
            "total_scenarios": len(simulations),
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "inconclusive": inconclusive,
            "detection_coverage_pct": round(detection_coverage, 1),
            "enforcement_coverage_pct": round(enforcement_coverage, 1),
        },
        "scenario_results": [
            {
                "scenario_id": s.scenario_id,
                "scenario_name": SCENARIOS.get(s.scenario_id, {}).get("name", s.scenario_id),
                "status": s.status,
                "assessment": s.assessment,
                "agent_shield_decision": s.agent_shield_decision,
                "proxy_decision": s.proxy_decision,
                "evidence_count": 0,  # Could query evidence table
            }
            for s in simulations
        ],
        "failed_controls": failed_controls,
        "inconclusive_tests": inconclusive_tests,
        "recommendations": recommendations,
        "known_limitations": [
            "Simulations run in isolated Docker environment; real-world results may vary",
            "DNS rebinding test uses controlled domain within simulation network",
            "Resource exhaustion test is bounded by container limits",
            "Phishing test uses synthetic credentials only",
        ],
    }


# ---------------------------------------------------------------------------
# Simulation endpoints
# ---------------------------------------------------------------------------


@router.get("/{simulation_id}", response_model=SimulationResponse)
async def get_simulation(
    simulation_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    row = db.execute(
        text(
            """
            SELECT id, campaign_id, organization_id, scenario_id, target_id, status, assessment,
                   policy_version, browser_session_id, agent_id, started_at, completed_at,
                   error, agent_shield_decision, proxy_decision, created_at
            FROM simulations WHERE id = :id
            """
        ),
        {"id": simulation_id},
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Simulation not found")

    if str(row.organization_id) != principal.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )

    return SimulationResponse(
        id=str(row.id),
        campaign_id=str(row.campaign_id),
        organization_id=str(row.organization_id),
        scenario_id=row.scenario_id,
        target_id=row.target_id,
        status=row.status,
        assessment=row.assessment,
        policy_version=row.policy_version,
        browser_session_id=row.browser_session_id,
        agent_id=str(row.agent_id) if row.agent_id else None,
        started_at=row.started_at.isoformat() if row.started_at else None,
        completed_at=row.completed_at.isoformat() if row.completed_at else None,
        error=row.error,
        agent_shield_decision=row.agent_shield_decision,
        proxy_decision=row.proxy_decision,
        created_at=row.created_at.isoformat() if row.created_at else None,
    )


@router.get("/{simulation_id}/evidence", response_model=list[EvidenceResponse])
async def get_simulation_evidence(
    simulation_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    # Verify simulation belongs to organization
    sim = db.execute(
        text("SELECT organization_id FROM simulations WHERE id = :id"),
        {"id": simulation_id},
    ).fetchone()

    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")

    if str(sim.organization_id) != principal.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )

    evidence = db.execute(
        text(
            """
            SELECT id, simulation_id, evidence_type, description, content, source, created_at
            FROM simulation_evidence
            WHERE simulation_id = :sim_id
            ORDER BY created_at
            """
        ),
        {"sim_id": simulation_id},
    ).fetchall()

    return [
        EvidenceResponse(
            id=str(e.id),
            simulation_id=str(e.simulation_id),
            evidence_type=e.evidence_type,
            description=e.description,
            content=e.content,
            source=e.source,
            created_at=e.created_at.isoformat() if e.created_at else None,
        )
        for e in evidence
    ]


@router.get("/{simulation_id}/events")
async def stream_simulation_events(simulation_id: str, request: Request):
    """Stream simulation events via SSE."""
    from datetime import datetime, timezone
    import json

    # Verify access
    db = next(get_db_session())
    try:
        sim = db.execute(
            text("SELECT organization_id FROM simulations WHERE id = :id"),
            {"id": simulation_id},
        ).fetchone()
        if not sim or str(sim.organization_id) != (request.headers.get("x-organization-id") or ""):
            raise HTTPException(status_code=403, detail="Access denied")
    finally:
        db.close()

    async def event_generator():
        last_event_id = None
        while True:
            if await request.is_disconnected():
                break
            db = next(get_db_session())
            try:
                query = """
                    SELECT id, stage, message, data, created_at
                    FROM simulation_events
                    WHERE simulation_id = :sim_id
                """
                params = {"sim_id": simulation_id}
                if last_event_id:
                    query += " AND id > :last_id"
                    params["last_id"] = last_event_id
                query += " ORDER BY created_at LIMIT 100"

                events = db.execute(text(query), params).fetchall()
                for event in events:
                    yield f"data: {json.dumps({'id': str(event.id), 'stage': event.stage, 'message': event.message, 'data': event.data, 'timestamp': event.created_at.isoformat() if event.created_at else None})}\n\n"
                    last_event_id = event.id
            finally:
                db.close()
            await asyncio.sleep(1)

    import asyncio
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/campaigns/{campaign_id}/events")
async def stream_campaign_events(campaign_id: str, request: Request):
    """Stream campaign events via SSE."""
    import json

    # Verify access
    db = next(get_db_session())
    try:
        camp = db.execute(
            text("SELECT organization_id FROM simulation_campaigns WHERE id = :id"),
            {"id": campaign_id},
        ).fetchone()
        if not camp or str(camp.organization_id) != (request.headers.get("x-organization-id") or ""):
            raise HTTPException(status_code=403, detail="Access denied")
    finally:
        db.close()

    async def event_generator():
        last_event_id = None
        while True:
            if await request.is_disconnected():
                break
            db = next(get_db_session())
            try:
                query = """
                    SELECT id, event_type, message, data, created_at
                    FROM campaign_events
                    WHERE campaign_id = :camp_id
                """
                params = {"camp_id": campaign_id}
                if last_event_id:
                    query += " AND id > :last_id"
                    params["last_id"] = last_event_id
                query += " ORDER BY created_at LIMIT 100"

                events = db.execute(text(query), params).fetchall()
                for event in events:
                    yield f"data: {json.dumps({'id': str(event.id), 'type': event.event_type, 'message': event.message, 'data': event.data, 'timestamp': event.created_at.isoformat() if event.created_at else None})}\n\n"
                    last_event_id = event.id
            finally:
                db.close()
            await asyncio.sleep(1)

    import asyncio
    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Single scenario run
# ---------------------------------------------------------------------------


@router.post("/scenarios/{scenario_id}/run", response_model=SimulationResponse, status_code=201)
async def run_single_scenario(
    scenario_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    organization_id: str = Query(...),
    agent_id: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
):
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if principal.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cross-tenant access is not permitted"},
        )

    # Create a single-scenario campaign
    import uuid
    from datetime import datetime, timezone

    campaign_id = str(uuid.uuid4())
    sim_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    config = SCENARIOS[scenario_id]

    db.execute(
        text(
            """
            INSERT INTO simulation_campaigns (id, organization_id, user_id, name, description, policy_version, status, scenario_ids, execution_mode, max_concurrency, created_at, updated_at)
            VALUES (:id, :org_id, :user_id, :name, :desc, 'default', 'QUEUED', :scenarios, 'sequential', 1, :created, :updated)
            """
        ),
        {
            "id": campaign_id,
            "org_id": organization_id,
            "user_id": principal.user_id,
            "name": f"Single: {config['name']}",
            "desc": f"Single scenario run: {config['name']}",
            "scenarios": [scenario_id],
            "created": now,
            "updated": now,
        },
    )

    db.execute(
        text(
            """
            INSERT INTO simulations (id, campaign_id, organization_id, scenario_id, target_id, status, policy_version, agent_id, session_id, created_at, updated_at)
            VALUES (:id, :campaign_id, :org_id, :scenario_id, :target_id, 'QUEUED', 'default', :agent_id, :session_id, :created, :updated)
            """
        ),
        {
            "id": sim_id,
            "campaign_id": campaign_id,
            "org_id": organization_id,
            "scenario_id": scenario_id,
            "target_id": config["target_service"],
            "agent_id": agent_id,
            "session_id": session_id,
            "created": now,
            "updated": now,
        },
    )
    db.commit()

    # Trigger execution
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                "http://simulation-controller:8090/v1/simulations/campaigns/internal/start",
                json={"campaign_id": campaign_id},
            )
    except Exception:
        pass

    return SimulationResponse(
        id=sim_id,
        campaign_id=campaign_id,
        organization_id=organization_id,
        scenario_id=scenario_id,
        target_id=config["target_service"],
        status="QUEUED",
        assessment=None,
        policy_version="default",
        browser_session_id=None,
        agent_id=agent_id,
        started_at=None,
        completed_at=None,
        error=None,
        agent_shield_decision=None,
        proxy_decision=None,
        created_at=now,
    )