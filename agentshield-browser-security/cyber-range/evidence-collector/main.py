"""Evidence Collector for AgentShield Cyber Range.

Collects and stores evidence from simulation targets, browser worker, proxy, and other services.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

import structlog
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
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
    COLLECTOR_HOST: str = "0.0.0.0"
    COLLECTOR_PORT: int = 8091
    DATABASE_URL: str
    REDIS_URL: str = "redis://redis:6379/0"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()


class Base(DeclarativeBase):
    pass


class EvidenceRecord(Base):
    __tablename__ = "collected_evidence"

    id: Mapped[str] = mapped_column(
        PGUUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    simulation_id: Mapped[str] = mapped_column(String(36), index=True)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    campaign_id: Mapped[Optional[str]] = mapped_column(String(36), index=True, nullable=True)
    scenario_id: Mapped[str] = mapped_column(String(100), index=True)
    source: Mapped[str] = mapped_column(String(50), index=True)
    evidence_type: Mapped[str] = mapped_column(String(50), index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_evidence_sim_time", "simulation_id", "collected_at"),
        Index("ix_evidence_org_scenario", "organization_id", "scenario_id"),
        Index("ix_evidence_source_type", "source", "evidence_type"),
    )


engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("evidence_collector_started")
    yield
    logger.info("evidence_collector_stopped")


app = FastAPI(title="AgentShield Evidence Collector", lifespan=lifespan)


class EvidenceSubmitRequest(BaseModel):
    simulation_id: str
    organization_id: str
    campaign_id: Optional[str] = None
    scenario_id: str
    source: str
    evidence_type: str
    description: Optional[str] = None
    content: dict = Field(default_factory=dict)


class EvidenceResponse(BaseModel):
    id: str
    simulation_id: str
    organization_id: str
    campaign_id: Optional[str]
    scenario_id: str
    source: str
    evidence_type: str
    description: Optional[str]
    content: dict
    collected_at: datetime

    class Config:
        from_attributes = True


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "evidence-collector"}


@app.post("/v1/evidence", response_model=EvidenceResponse, status_code=201)
async def submit_evidence(request: EvidenceSubmitRequest, db: Session = next(get_db())):
    evidence = EvidenceRecord(
        simulation_id=request.simulation_id,
        organization_id=request.organization_id,
        campaign_id=request.campaign_id,
        scenario_id=request.scenario_id,
        source=request.source,
        evidence_type=request.evidence_type,
        description=request.description,
        content=request.content,
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    logger.info("evidence_collected", evidence_id=evidence.id, simulation_id=request.simulation_id, type=request.evidence_type)

    return EvidenceResponse(
        id=evidence.id,
        simulation_id=evidence.simulation_id,
        organization_id=evidence.organization_id,
        campaign_id=evidence.campaign_id,
        scenario_id=evidence.scenario_id,
        source=evidence.source,
        evidence_type=evidence.evidence_type,
        description=evidence.description,
        content=evidence.content,
        collected_at=evidence.collected_at,
    )


@app.get("/v1/evidence/simulation/{simulation_id}", response_model=list[EvidenceResponse])
async def get_simulation_evidence(simulation_id: str, db: Session = next(get_db())):
    evidence = (
        db.query(EvidenceRecord)
        .filter(EvidenceRecord.simulation_id == simulation_id)
        .order_by(EvidenceRecord.collected_at)
        .all()
    )
    return [
        EvidenceResponse(
            id=e.id,
            simulation_id=e.simulation_id,
            organization_id=e.organization_id,
            campaign_id=e.campaign_id,
            scenario_id=e.scenario_id,
            source=e.source,
            evidence_type=e.evidence_type,
            description=e.description,
            content=e.content,
            collected_at=e.collected_at,
        )
        for e in evidence
    ]


@app.get("/v1/evidence/campaign/{campaign_id}", response_model=list[EvidenceResponse])
async def get_campaign_evidence(campaign_id: str, db: Session = next(get_db())):
    evidence = (
        db.query(EvidenceRecord)
        .filter(EvidenceRecord.campaign_id == campaign_id)
        .order_by(EvidenceRecord.collected_at)
        .all()
    )
    return [
        EvidenceResponse(
            id=e.id,
            simulation_id=e.simulation_id,
            organization_id=e.organization_id,
            campaign_id=e.campaign_id,
            scenario_id=e.scenario_id,
            source=e.source,
            evidence_type=e.evidence_type,
            description=e.description,
            content=e.content,
            collected_at=e.collected_at,
        )
        for e in evidence
    ]


@app.get("/v1/evidence/organization/{organization_id}", response_model=list[EvidenceResponse])
async def get_organization_evidence(
    organization_id: str,
    db: Session = next(get_db()),
    scenario_id: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
):
    query = db.query(EvidenceRecord).filter(EvidenceRecord.organization_id == organization_id)
    if scenario_id:
        query = query.filter(EvidenceRecord.scenario_id == scenario_id)
    evidence = query.order_by(EvidenceRecord.collected_at.desc()).offset(offset).limit(limit).all()
    return [
        EvidenceResponse(
            id=e.id,
            simulation_id=e.simulation_id,
            organization_id=e.organization_id,
            campaign_id=e.campaign_id,
            scenario_id=e.scenario_id,
            source=e.source,
            evidence_type=e.evidence_type,
            description=e.description,
            content=e.content,
            collected_at=e.collected_at,
        )
        for e in evidence
    ]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.COLLECTOR_HOST, port=settings.COLLECTOR_PORT)