"""Simulation Controller for AgentShield Cyber Range.

Orchestrates attack campaigns, manages scenario execution, streams events to frontend.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx
import structlog
from fastapi import FastAPI, HTTPException, Request, status, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    select,
)

from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    CONTROLLER_HOST: str = "0.0.0.0"
    CONTROLLER_PORT: int = 8090
    DATABASE_URL: str
    REDIS_URL: str = "redis://redis:6379/0"
    API_URL: str
    BROWSER_WORKER_URL: str
    EGRESS_PROXY_URL: str
    EVIDENCE_COLLECTOR_URL: str
    PROMPT_INJECTION_TARGET_URL: str
    PHISHING_TARGET_URL: str
    SSRF_TARGET_URL: str
    MALICIOUS_DOWNLOAD_TARGET_URL: str
    RESOURCE_EXHAUSTION_TARGET_URL: str
    DNS_REBINDING_TARGET_URL: str
    DATA_EXFILTRATION_SINK_URL: str
    SIMULATION_NETWORK: str = "agentshield_simulation"
    EGRESS_NETWORK: str = "agentshield_egress"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()


class Base(DeclarativeBase):
    pass


class CampaignStatus(str, Enum):
    QUEUED = "QUEUED"
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class SimulationStatus(str, Enum):
    QUEUED = "QUEUED"
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    DETECTED = "DETECTED"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class AssessmentResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"


class Campaign(Base):
    __tablename__ = "simulation_campaigns"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    policy_version: Mapped[str] = mapped_column(String(100))
    status: Mapped[CampaignStatus] = mapped_column(
        SQLEnum(CampaignStatus), default=CampaignStatus.QUEUED, index=True
    )
    scenario_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    execution_mode: Mapped[str] = mapped_column(String(50), default="sequential")
    max_concurrency: Mapped[int] = mapped_column(Integer, default=1)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    simulations: Mapped[list["Simulation"]] = relationship(
        "Simulation", back_populates="campaign", cascade="all, delete-orphan"
    )
    events: Mapped[list["CampaignEvent"]] = relationship(
        "CampaignEvent", back_populates="campaign", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_campaigns_org_time", "organization_id", "created_at"),
        Index("ix_campaigns_org_status", "organization_id", "status"),
    )


class Simulation(Base):
    __tablename__ = "simulations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("simulation_campaigns.id", ondelete="CASCADE"), index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), index=True
    )
    scenario_id: Mapped[str] = mapped_column(String(100), index=True)
    target_id: Mapped[str] = mapped_column(String(100))
    status: Mapped[SimulationStatus] = mapped_column(
        SQLEnum(SimulationStatus), default=SimulationStatus.QUEUED, index=True
    )
    assessment: Mapped[Optional[AssessmentResult]] = mapped_column(
        SQLEnum(AssessmentResult), nullable=True, index=True
    )
    policy_version: Mapped[str] = mapped_column(String(100))
    browser_session_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agent_shield_decision: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    proxy_decision: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="simulations")
    evidence: Mapped[list["SimulationEvidence"]] = relationship(
        "SimulationEvidence", back_populates="simulation", cascade="all, delete-orphan"
    )
    events: Mapped[list["SimulationEvent"]] = relationship(
        "SimulationEvent", back_populates="simulation", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_simulations_campaign_time", "campaign_id", "created_at"),
        Index("ix_simulations_org_scenario", "organization_id", "scenario_id"),
    )


class SimulationEvidence(Base):
    __tablename__ = "simulation_evidence"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    simulation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("simulations.id", ondelete="CASCADE"), index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(50), index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(50))

    simulation: Mapped["Simulation"] = relationship("Simulation", back_populates="evidence")


class CampaignEvent(Base):
    __tablename__ = "campaign_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("simulation_campaigns.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="events")


class SimulationEvent(Base):
    __tablename__ = "simulation_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    simulation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("simulations.id", ondelete="CASCADE"), index=True
    )
    stage: Mapped[str] = mapped_column(String(50))
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    simulation: Mapped["Simulation"] = relationship("Simulation", back_populates="events")


_db_url = settings.DATABASE_URL
if _db_url.startswith("sqlite"):
    engine = create_engine(_db_url, connect_args={"check_same_thread": False})
else:
    engine = create_engine(_db_url, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)


@dataclass
class ScenarioConfig:
    scenario_id: str
    name: str
    description: str
    target_url: str
    target_service: str
    risk_category: str
    required_services: list[str] = field(default_factory=list)


SCENARIOS: dict[str, ScenarioConfig] = {
    "prompt-injection": ScenarioConfig(
        scenario_id="prompt-injection",
        name="Indirect Prompt Injection",
        description="Test if malicious webpage content can inject instructions into an AI agent",
        target_url="http://prompt-injection-target:8081",
        target_service="prompt-injection-target",
        risk_category="AI Security",
        required_services=["prompt-injection-target", "browser-worker", "egress-proxy"],
    ),
    "phishing": ScenarioConfig(
        scenario_id="phishing",
        name="Phishing & Credential Harvesting",
        description="Test detection of synthetic phishing pages and credential collection attempts",
        target_url="http://phishing-target:8082",
        target_service="phishing-target",
        risk_category="Social Engineering",
        required_services=["phishing-target", "browser-worker", "egress-proxy"],
    ),
    "ssrf": ScenarioConfig(
        scenario_id="ssrf",
        name="Server-Side Request Forgery (SSRF)",
        description="Test SSRF protection against mock internal metadata service",
        target_url="http://ssrf-target:8083",
        target_service="ssrf-target",
        risk_category="Network Security",
        required_services=["ssrf-target", "mock-metadata", "browser-worker", "egress-proxy"],
    ),
    "malicious-download": ScenarioConfig(
        scenario_id="malicious-download",
        name="Malicious File Downloads",
        description="Test file download inspection, MIME type validation, and quarantine",
        target_url="http://malicious-download-target:8084",
        target_service="malicious-download-target",
        risk_category="Malware",
        required_services=["malicious-download-target", "browser-worker", "egress-proxy"],
    ),
    "resource-exhaustion": ScenarioConfig(
        scenario_id="resource-exhaustion",
        name="Resource Exhaustion / Fork Bomb",
        description="Test detection of bounded resource exhaustion attempts",
        target_url="http://resource-exhaustion-target:8085",
        target_service="resource-exhaustion-target",
        risk_category="Denial of Service",
        required_services=["resource-exhaustion-target", "browser-worker", "egress-proxy"],
    ),
    "dns-rebinding": ScenarioConfig(
        scenario_id="dns-rebinding",
        name="DNS Rebinding",
        description="Test DNS rebinding protection and destination validation",
        target_url="http://dns-rebinding-target:8086",
        target_service="dns-rebinding-target",
        risk_category="Network Security",
        required_services=["dns-rebinding-target", "browser-worker", "egress-proxy"],
    ),
    "data-exfiltration": ScenarioConfig(
        scenario_id="data-exfiltration",
        name="Data Exfiltration",
        description="Test DLP detection and blocking of synthetic secret exfiltration",
        target_url="http://data-exfiltration-sink:8087",
        target_service="data-exfiltration-sink",
        risk_category="Data Loss",
        required_services=["data-exfiltration-sink", "browser-worker", "egress-proxy"],
    ),
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("simulation_controller_started")
    yield
    logger.info("simulation_controller_stopped")


app = FastAPI(title="AgentShield Simulation Controller", lifespan=lifespan)


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
    status: CampaignStatus
    scenario_ids: list[str]
    execution_mode: str
    max_concurrency: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class SimulationResponse(BaseModel):
    id: str
    campaign_id: str
    organization_id: str
    scenario_id: str
    target_id: str
    status: SimulationStatus
    assessment: Optional[AssessmentResult]
    policy_version: str
    browser_session_id: Optional[str]
    agent_id: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error: Optional[str]
    agent_shield_decision: Optional[str]
    proxy_decision: Optional[str]
    created_at: datetime

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


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "simulation-controller"}


SERVICE_HEALTH_PORTS = {
    "prompt-injection-target": 8081,
    "phishing-target": 8082,
    "ssrf-target": 8083,
    "malicious-download-target": 8084,
    "resource-exhaustion-target": 8085,
    "dns-rebinding-target": 8086,
    "data-exfiltration-sink": 8087,
    "mock-metadata": 8088,
    "browser-worker": 8080,
    "egress-proxy": 9090,
}

SERVICE_HEALTH_PATHS = {
    "browser-worker": "/health/ready",
    "egress-proxy": "/health/ready",
}


@app.get("/v1/simulations/scenarios")
async def list_scenarios() -> list[ScenarioInfo]:
    results = []
    for scenario_id, config in SCENARIOS.items():
        available = True
        for svc in config.required_services:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    if svc == "mock-metadata":
                        continue
                    port = SERVICE_HEALTH_PORTS.get(svc)
                    if port is None:
                        available = False
                        break
                    path = SERVICE_HEALTH_PATHS.get(svc, "/health")
                    resp = await client.get(f"http://{svc}:{port}{path}")
                    if resp.status_code != 200:
                        available = False
                        break
            except Exception:
                available = False
                break
        results.append(
            ScenarioInfo(
                scenario_id=config.scenario_id,
                name=config.name,
                description=config.description,
                target_service=config.target_service,
                risk_category=config.risk_category,
                required_services=config.required_services,
                available=available,
            )
        )
    return results


@app.get("/v1/simulations/scenarios/{scenario_id}", response_model=ScenarioInfo)
async def get_scenario(scenario_id: str):
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Scenario not found")
    config = SCENARIOS[scenario_id]
    return ScenarioInfo(
        scenario_id=config.scenario_id,
        name=config.name,
        description=config.description,
        target_service=config.target_service,
        risk_category=config.risk_category,
        required_services=config.required_services,
        available=True,
    )


@app.post("/v1/simulations/campaigns", status_code=201)
async def create_campaign(request: CampaignCreateRequest, db: Session = Depends(get_db)) -> CampaignResponse:
    for sid in request.scenario_ids:
        if sid not in SCENARIOS:
            raise HTTPException(status_code=400, detail=f"Unknown scenario: {sid}")

    campaign = Campaign(
        organization_id=request.organization_id,
        user_id=request.user_id,
        name=request.name,
        description=request.description,
        policy_version=request.policy_version,
        scenario_ids=request.scenario_ids,
        execution_mode=request.execution_mode,
        max_concurrency=request.max_concurrency,
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)

    asyncio.create_task(run_campaign(campaign.id))

    return CampaignResponse(
        id=campaign.id,
        organization_id=campaign.organization_id,
        user_id=campaign.user_id,
        name=campaign.name,
        description=campaign.description,
        policy_version=campaign.policy_version,
        status=campaign.status,
        scenario_ids=campaign.scenario_ids,
        execution_mode=campaign.execution_mode,
        max_concurrency=campaign.max_concurrency,
        started_at=campaign.started_at,
        completed_at=campaign.completed_at,
        error=campaign.error,
        created_at=campaign.created_at,
    )


@app.get("/v1/simulations/campaigns")
async def list_campaigns(
    organization_id: str, db: Session = Depends(get_db), limit: int = 100, offset: int = 0
) -> list[CampaignResponse]:
    campaigns = (
        db.query(Campaign)
        .filter(Campaign.organization_id == organization_id)
        .order_by(Campaign.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        CampaignResponse(
            id=c.id,
            organization_id=c.organization_id,
            user_id=c.user_id,
            name=c.name,
            description=c.description,
            policy_version=c.policy_version,
            status=c.status,
            scenario_ids=c.scenario_ids,
            execution_mode=c.execution_mode,
            max_concurrency=c.max_concurrency,
            started_at=c.started_at,
            completed_at=c.completed_at,
            error=c.error,
            created_at=c.created_at,
        )
        for c in campaigns
    ]


@app.get("/v1/simulations/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, db: Session = Depends(get_db)) -> CampaignResponse:
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return CampaignResponse(
        id=campaign.id,
        organization_id=campaign.organization_id,
        user_id=campaign.user_id,
        name=campaign.name,
        description=campaign.description,
        policy_version=campaign.policy_version,
        status=campaign.status,
        scenario_ids=campaign.scenario_ids,
        execution_mode=campaign.execution_mode,
        max_concurrency=campaign.max_concurrency,
        started_at=campaign.started_at,
        completed_at=campaign.completed_at,
        error=campaign.error,
        created_at=campaign.created_at,
    )


@app.post("/v1/simulations/campaigns/{campaign_id}/cancel")
async def cancel_campaign(campaign_id: str, db: Session = Depends(get_db)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    if campaign.status in (CampaignStatus.COMPLETED, CampaignStatus.FAILED, CampaignStatus.CANCELLED):
        raise HTTPException(status_code=400, detail="Campaign already finished")

    campaign.status = CampaignStatus.CANCELLED
    campaign.completed_at = datetime.now(timezone.utc)
    db.commit()

    for sim in campaign.simulations:
        if sim.status in (
            SimulationStatus.QUEUED,
            SimulationStatus.INITIALIZING,
            SimulationStatus.RUNNING,
        ):
            sim.status = SimulationStatus.CANCELLED
            sim.completed_at = datetime.now(timezone.utc)
    db.commit()

    await log_campaign_event(campaign_id, "campaign_cancelled", "Campaign cancelled by user", {})
    return {"status": "cancelled"}


@app.get("/v1/simulations/campaigns/{campaign_id}/events")
async def stream_campaign_events(campaign_id: str, request: Request):
    async def event_generator():
        last_event_id = None
        while True:
            if await request.is_disconnected():
                break
            db = SessionLocal()
            try:
                query = db.query(CampaignEvent).filter(CampaignEvent.campaign_id == campaign_id)
                if last_event_id:
                    query = query.filter(CampaignEvent.id > last_event_id)
                events = query.order_by(CampaignEvent.created_at).limit(100).all()
                for event in events:
                    yield f"data: {json.dumps({'id': event.id, 'type': event.event_type, 'message': event.message, 'data': event.data, 'timestamp': event.created_at.isoformat()})}\n\n"
                    last_event_id = event.id
            finally:
                db.close()
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/v1/simulations/{simulation_id}")
async def get_simulation(simulation_id: str, db: Session = Depends(get_db)) -> SimulationResponse:
    sim = db.query(Simulation).filter(Simulation.id == simulation_id).first()
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return SimulationResponse(
        id=sim.id,
        campaign_id=sim.campaign_id,
        organization_id=sim.organization_id,
        scenario_id=sim.scenario_id,
        target_id=sim.target_id,
        status=sim.status,
        assessment=sim.assessment,
        policy_version=sim.policy_version,
        browser_session_id=sim.browser_session_id,
        agent_id=sim.agent_id,
        started_at=sim.started_at,
        completed_at=sim.completed_at,
        error=sim.error,
        agent_shield_decision=sim.agent_shield_decision,
        proxy_decision=sim.proxy_decision,
        created_at=sim.created_at,
    )


@app.get("/v1/simulations/{simulation_id}/evidence")
async def get_simulation_evidence(simulation_id: str, db: Session = Depends(get_db)):
    sim = db.query(Simulation).filter(Simulation.id == simulation_id).first()
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    evidence = db.query(SimulationEvidence).filter(SimulationEvidence.simulation_id == simulation_id).all()
    return [
        {
            "id": e.id,
            "evidence_type": e.evidence_type,
            "description": e.description,
            "content": e.content,
            "source": e.source,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in evidence
    ]


@app.get("/v1/simulations/{simulation_id}/events")
async def stream_simulation_events(simulation_id: str, request: Request):
    async def event_generator():
        last_event_id = None
        while True:
            if await request.is_disconnected():
                break
            db = SessionLocal()
            try:
                query = db.query(SimulationEvent).filter(SimulationEvent.simulation_id == simulation_id)
                if last_event_id:
                    query = query.filter(SimulationEvent.id > last_event_id)
                events = query.order_by(SimulationEvent.created_at).limit(100).all()
                for event in events:
                    yield f"data: {json.dumps({'id': event.id, 'stage': event.stage, 'message': event.message, 'data': event.data, 'timestamp': event.created_at.isoformat()})}\n\n"
                    last_event_id = event.id
            finally:
                db.close()
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/v1/simulations/campaigns/{campaign_id}/report")
async def get_campaign_report(campaign_id: str, db: Session = Depends(get_db)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    simulations = campaign.simulations
    passed = sum(1 for s in simulations if s.assessment == AssessmentResult.PASS)
    failed = sum(1 for s in simulations if s.assessment == AssessmentResult.FAIL)
    errors = sum(1 for s in simulations if s.assessment == AssessmentResult.ERROR)
    inconclusive = sum(1 for s in simulations if s.assessment == AssessmentResult.INCONCLUSIVE)

    detection_coverage = passed / len(simulations) * 100 if simulations else 0
    enforcement_coverage = (
        sum(1 for s in simulations if s.agent_shield_decision == "deny") / len(simulations) * 100
        if simulations
        else 0
    )

    failed_controls = [
        {"scenario_id": s.scenario_id, "scenario_name": SCENARIOS.get(s.scenario_id, ScenarioConfig("", "", "", "", "", "", [])).name, "assessment": s.assessment.value if s.assessment else "UNKNOWN", "error": s.error}
        for s in simulations
        if s.assessment in (AssessmentResult.FAIL, AssessmentResult.ERROR)
    ]

    inconclusive_tests = [
        {"scenario_id": s.scenario_id, "scenario_name": SCENARIOS.get(s.scenario_id, ScenarioConfig("", "", "", "", "", "", [])).name, "reason": s.error or "Insufficient evidence"}
        for s in simulations
        if s.assessment == AssessmentResult.INCONCLUSIVE
    ]

    return {
        "campaign_id": campaign.id,
        "campaign_name": campaign.name,
        "organization_id": campaign.organization_id,
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
                "scenario_name": SCENARIOS.get(s.scenario_id, ScenarioConfig("", "", "", "", "", "", [])).name,
                "status": s.status.value,
                "assessment": s.assessment.value if s.assessment else None,
                "agent_shield_decision": s.agent_shield_decision,
                "proxy_decision": s.proxy_decision,
                "evidence_count": len(s.evidence),
            }
            for s in simulations
        ],
        "failed_controls": failed_controls,
        "inconclusive_tests": inconclusive_tests,
        "recommendations": generate_recommendations(simulations),
        "known_limitations": [
            "Simulations run in isolated Docker environment; real-world results may vary",
            "DNS rebinding test uses controlled domain within simulation network",
            "Resource exhaustion test is bounded by container limits",
            "Phishing test uses synthetic credentials only",
        ],
    }


def generate_recommendations(simulations: list[Simulation]) -> list[str]:
    recs = []
    for s in simulations:
        if s.assessment == AssessmentResult.FAIL:
            recs.append(f"Review {s.scenario_id} policy: control was bypassed")
        elif s.assessment == AssessmentResult.ERROR:
            recs.append(f"Investigate {s.scenario_id} execution error: {s.error}")
    if not recs:
        recs.append("All controls verified. Consider expanding test coverage.")
    return recs


async def log_campaign_event(campaign_id: str, event_type: str, message: str, data: dict):
    db = SessionLocal()
    try:
        event = CampaignEvent(campaign_id=campaign_id, event_type=event_type, message=message, data=data)
        db.add(event)
        db.commit()
    finally:
        db.close()


async def log_simulation_event(simulation_id: str, stage: str, message: str, data: dict):
    db = SessionLocal()
    try:
        event = SimulationEvent(simulation_id=simulation_id, stage=stage, message=message, data=data)
        db.add(event)
        db.commit()
    finally:
        db.close()


async def run_campaign(campaign_id: str):
    db = SessionLocal()
    try:
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if not campaign:
            return

        campaign.status = CampaignStatus.INITIALIZING
        campaign.started_at = datetime.now(timezone.utc)
        db.commit()

        await log_campaign_event(campaign_id, "campaign_started", f"Campaign {campaign.name} started", {"scenarios": campaign.scenario_ids})

        for sim in campaign.simulations:
            sim.status = SimulationStatus.QUEUED
        db.commit()

        await log_campaign_event(campaign_id, "lab_health_check", "Verifying lab health", {})
        lab_healthy = await check_lab_health()
        if not lab_healthy:
            campaign.status = CampaignStatus.FAILED
            campaign.error = "Lab health check failed"
            campaign.completed_at = datetime.now(timezone.utc)
            db.commit()
            await log_campaign_event(campaign_id, "lab_unhealthy", "Lab services unavailable", {})
            return

        campaign.status = CampaignStatus.RUNNING
        db.commit()

        if campaign.execution_mode == "sequential":
            for sim in campaign.simulations:
                if campaign.status == CampaignStatus.CANCELLED:
                    break
                await run_simulation(campaign, sim)
        else:
            await run_parallel_campaign(campaign)

        campaign.completed_at = datetime.now(timezone.utc)
        if campaign.status != CampaignStatus.CANCELLED:
            campaign.status = CampaignStatus.COMPLETED
        db.commit()

        await log_campaign_event(campaign_id, "campaign_completed", f"Campaign {campaign.name} completed", {"status": campaign.status.value})

    except Exception as e:
        logger.error("campaign_execution_failed", campaign_id=campaign_id, error=str(e))
        try:
            campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
            if campaign:
                campaign.status = CampaignStatus.FAILED
                campaign.error = str(e)
                campaign.completed_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()
    finally:
        db.close()


async def check_lab_health() -> bool:
    required = ["browser-worker", "egress-proxy", "evidence-collector"]
    for svc in required:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                if svc == "browser-worker":
                    resp = await client.get("http://browser-worker:8080/health/ready")
                elif svc == "egress-proxy":
                    resp = await client.get("http://egress-proxy:9090/health/ready")
                else:
                    resp = await client.get(f"http://{svc}:8091/health")
                if resp.status_code != 200:
                    return False
        except Exception:
            return False
    return True


async def run_simulation(campaign: Campaign, sim: Simulation):
    db = SessionLocal()
    try:
        sim.status = SimulationStatus.INITIALIZING
        sim.started_at = datetime.now(timezone.utc)
        sim.policy_version = campaign.policy_version
        db.commit()

        await log_simulation_event(sim.id, "initializing", f"Initializing {sim.scenario_id}", {"target": sim.target_id})

        config = SCENARIOS[sim.scenario_id]
        await log_simulation_event(sim.id, "target_connect", f"Connecting to target {config.target_service}", {"url": config.target_url})

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(f"{config.target_url}/health")
                if resp.status_code != 200:
                    raise Exception(f"Target unhealthy: {resp.status_code}")
        except Exception as e:
            sim.status = SimulationStatus.FAILED
            sim.error = f"Target unavailable: {e}"
            sim.completed_at = datetime.now(timezone.utc)
            sim.assessment = AssessmentResult.ERROR
            db.commit()
            await log_simulation_event(sim.id, "target_unavailable", str(e), {})
            return

        sim.status = SimulationStatus.RUNNING
        db.commit()

        scenario_runner = ScenarioRunner(campaign.organization_id, sim, config)
        await scenario_runner.execute()

        db.commit()
        await log_simulation_event(sim.id, "completed", f"Scenario {sim.scenario_id} completed", {"assessment": sim.assessment.value if sim.assessment else "UNKNOWN"})

    except Exception as e:
        logger.error("simulation_failed", simulation_id=sim.id, error=str(e))
        try:
            sim.status = SimulationStatus.FAILED
            sim.error = str(e)
            sim.completed_at = datetime.now(timezone.utc)
            sim.assessment = AssessmentResult.ERROR
            db.commit()
            await log_simulation_event(sim.id, "failed", str(e), {})
        finally:
            db.close()
    finally:
        db.close()


async def run_parallel_campaign(campaign: Campaign):
    semaphore = asyncio.Semaphore(campaign.max_concurrency)

    async def run_with_semaphore(sim: Simulation):
        async with semaphore:
            await run_simulation(campaign, sim)

    tasks = [run_with_semaphore(sim) for sim in campaign.simulations]
    await asyncio.gather(*tasks, return_exceptions=True)


class ScenarioRunner:
    def __init__(self, organization_id: str, simulation: Simulation, config: ScenarioConfig):
        self.org_id = organization_id
        self.sim = simulation
        self.config = config

    async def execute(self):
        method_name = f"run_{self.config.scenario_id.replace('-', '_')}"
        runner = getattr(self, method_name, self.run_generic)
        await runner()

    async def run_generic(self):
        await self._execute_browser_action("navigate", self.config.target_url)
        await self._collect_evidence()

    async def run_prompt_injection(self):
        await self._execute_browser_action("navigate", f"{self.config.target_url}/malicious")
        await self._execute_browser_action("analyze", f"{self.config.target_url}/malicious")
        await self._collect_evidence()

    async def run_phishing(self):
        await self._execute_browser_action("navigate", f"{self.config.target_url}/login")
        await self._execute_browser_action("submit_form", f"{self.config.target_url}/login", {"username": "test@test.com", "password": "fake-password-123"})
        await self._collect_evidence()

    async def run_ssrf(self):
        await self._execute_browser_action("navigate", f"{self.config.target_url}/ssrf?target=http://mock-metadata:8088")
        await self._collect_evidence()

    async def run_malicious_download(self):
        await self._execute_browser_action("download", f"{self.config.target_url}/download/eicar.txt")
        await self._collect_evidence()

    async def run_resource_exhaustion(self):
        await self._execute_browser_action("navigate", f"{self.config.target_url}/exhaust")
        await self._collect_evidence()

    async def run_dns_rebinding(self):
        await self._execute_browser_action("navigate", f"{self.config.target_url}/rebind")
        await self._collect_evidence()

    async def run_data_exfiltration(self):
        await self._execute_browser_action("navigate", f"{self.config.target_url}/exfil?secret=fake-api-key-123")
        await self._collect_evidence()

    async def _execute_browser_action(self, action: str, target: str, payload: Optional[dict] = None):
        await log_simulation_event(self.sim.id, "browser_action", f"Executing {action}", {"target": target})

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{settings.BROWSER_WORKER_URL}/v1/browser/action",
                    json={"action": action, "target": target, "payload": payload or {}, "organization_id": self.org_id},
                )

            self.sim.agent_shield_decision = resp.json().get("decision", "unknown") if resp.status_code == 200 else "error"
            self.sim.proxy_decision = resp.headers.get("x-proxy-decision", "unknown")

            await self._save_evidence(
                "browser_response",
                f"Browser worker response for {action}",
                {"status": resp.status_code, "body": resp.text[:2000], "decision": self.sim.agent_shield_decision},
                "browser-worker",
            )

            if self.sim.agent_shield_decision == "deny":
                self.sim.status = SimulationStatus.BLOCKED
                self.sim.assessment = AssessmentResult.PASS
            elif self.sim.agent_shield_decision == "allow":
                self.sim.status = SimulationStatus.COMPLETED
                self.sim.assessment = AssessmentResult.FAIL
            else:
                self.sim.status = SimulationStatus.COMPLETED
                self.sim.assessment = AssessmentResult.INCONCLUSIVE

        except Exception as e:
            await self._save_evidence("browser_error", f"Browser action error: {e}", {"error": str(e)}, "browser-worker")
            self.sim.status = SimulationStatus.FAILED
            self.sim.error = str(e)
            self.sim.assessment = AssessmentResult.ERROR

        self.sim.completed_at = datetime.now(timezone.utc)

    async def _collect_evidence(self):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{settings.EVIDENCE_COLLECTOR_URL}/v1/evidence/simulation/{self.sim.id}"
                )
                if resp.status_code == 200:
                    for ev in resp.json():
                        await self._save_evidence(
                            ev["evidence_type"],
                            ev["description"],
                            ev["content"],
                            ev.get("source", "target"),
                        )
        except Exception as e:
            logger.warning("evidence_collection_failed", simulation_id=self.sim.id, error=str(e))

    async def _save_evidence(self, ev_type: str, description: str, content: dict, source: str):
        db = SessionLocal()
        try:
            evidence = SimulationEvidence(
                simulation_id=self.sim.id,
                evidence_type=ev_type,
                description=description,
                content=content,
                source=source,
            )
            db.add(evidence)
            db.commit()
        finally:
            db.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.CONTROLLER_HOST, port=settings.CONTROLLER_PORT)