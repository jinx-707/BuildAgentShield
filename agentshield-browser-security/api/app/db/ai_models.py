"""AI Agent Security database models for AgentShield Prompt 3.

All tables are organization-scoped so multi-tenant isolation is enforced at
the query layer. Raw secrets and sensitive browser content are never stored.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    String,
    Column,
    ForeignKey,
    Index,
    Integer,
    Text,
    Boolean,
    DateTime,
)
from sqlalchemy import JSON
from sqlalchemy.orm import relationship

from app.db.base import Base, TimestampMixin


def generate_uuid() -> str:
    return str(uuid.uuid4())


class AgentExecution(Base, TimestampMixin):
    """A single AI agent action execution mediated by AgentShield."""

    __tablename__ = "agent_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id = Column(String(255), nullable=True, index=True)
    request_id = Column(String(255), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    target = Column(Text, nullable=True)
    decision = Column(String(50), nullable=True, index=True)
    reason = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="info")
    risk_score = Column(Integer, nullable=True)
    trust_label = Column(String(20), nullable=False, default="untrusted")
    evidence = Column(JSON, nullable=False, default=dict)

    organization = relationship("Organization")
    agent = relationship("Agent")

    __table_args__ = (
        Index("ix_agent_executions_org_time", "organization_id", "created_at"),
        Index("ix_agent_executions_org_action", "organization_id", "action"),
        Index("ix_agent_executions_org_decision", "organization_id", "decision"),
    )


class ThreatDetection(Base, TimestampMixin):
    """A threat detected during agent execution or content inspection."""

    __tablename__ = "threat_detections"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    session_id = Column(String(255), nullable=True, index=True)
    execution_id = Column(
        String(36),
        ForeignKey("agent_executions.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    threat_category = Column(String(100), nullable=False, index=True)
    detection_module = Column(String(100), nullable=False, index=True)
    detection_reason = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="medium")
    risk_score = Column(Integer, nullable=True)
    action_taken = Column(String(50), nullable=True)
    target = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=False, default=dict)

    organization = relationship("Organization")
    agent = relationship("Agent")
    execution = relationship("AgentExecution")

    __table_args__ = (
        Index("ix_threat_detections_org_time", "organization_id", "created_at"),
        Index(
            "ix_threat_detections_org_category",
            "organization_id",
            "threat_category",
        ),
        Index(
            "ix_threat_detections_org_severity",
            "organization_id",
            "severity",
        ),
    )


class RiskAssessment(Base, TimestampMixin):
    """A transparent, explainable risk assessment for an agent action."""

    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    execution_id = Column(
        String(36),
        ForeignKey("agent_executions.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    risk_score = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False, default="medium")
    recommended_action = Column(String(50), nullable=False)
    enforcement_decision = Column(String(50), nullable=False)
    detection_reasons = Column(JSON, nullable=False, default=list)
    risk_factors = Column(JSON, nullable=False, default=dict)

    organization = relationship("Organization")
    agent = relationship("Agent")
    execution = relationship("AgentExecution")

    __table_args__ = (
        Index("ix_risk_assessments_org_time", "organization_id", "created_at"),
        Index(
            "ix_risk_assessments_org_score",
            "organization_id",
            "risk_score",
        ),
    )


class DlpFinding(Base, TimestampMixin):
    """A data loss prevention finding; raw sensitive values are never stored."""

    __tablename__ = "dlp_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    session_id = Column(String(255), nullable=True, index=True)
    detection_rule = Column(String(100), nullable=False, index=True)
    detection_reason = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="medium")
    confidence = Column(Integer, nullable=True)
    action_taken = Column(String(50), nullable=True)
    target = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=False, default=dict)

    organization = relationship("Organization")
    agent = relationship("Agent")

    __table_args__ = (
        Index("ix_dlp_findings_org_time", "organization_id", "created_at"),
        Index("ix_dlp_findings_org_rule", "organization_id", "detection_rule"),
    )


class ToolDecision(Base, TimestampMixin):
    """An authorization decision for an agent tool invocation."""

    __tablename__ = "tool_decisions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id = Column(String(255), nullable=True, index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    tool_args = Column(JSON, nullable=False, default=dict)
    decision = Column(String(50), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    policy_references = Column(JSON, nullable=False, default=list)
    risk_score = Column(Integer, nullable=True)

    organization = relationship("Organization")
    agent = relationship("Agent")

    __table_args__ = (
        Index("ix_tool_decisions_org_time", "organization_id", "created_at"),
        Index("ix_tool_decisions_org_tool", "organization_id", "tool_name"),
        Index("ix_tool_decisions_org_decision", "organization_id", "decision"),
    )


class AttackSimulationRun(Base, TimestampMixin):
    """An attack simulation scenario run from the red team lab."""

    __tablename__ = "attack_simulation_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    session_id = Column(String(255), nullable=True, index=True)
    scenario_id = Column(String(100), nullable=False, index=True)
    scenario_name = Column(String(255), nullable=False)
    threat_category = Column(String(100), nullable=True)
    attempted_action = Column(Text, nullable=True)
    policy_decision = Column(String(50), nullable=True)
    enforcement_result = Column(String(20), nullable=False, index=True)
    # --- Real execution metrics (PHASE 2/6) ---
    requests_attempted = Column(Integer, nullable=False, default=0)
    requests_allowed = Column(Integer, nullable=False, default=0)
    requests_blocked = Column(Integer, nullable=False, default=0)
    detection_outcome = Column(String(20), nullable=True)  # detected / not_detected
    execution_duration_ms = Column(Integer, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    failure_reason = Column(Text, nullable=True)
    # ------------------------------------------
    evidence = Column(JSON, nullable=False, default=dict)

    organization = relationship("Organization")
    agent = relationship("Agent")

    __table_args__ = (
        Index("ix_attack_simulation_runs_org_time", "organization_id", "created_at"),
        Index(
            "ix_attack_simulation_runs_org_scenario",
            "organization_id",
            "scenario_id",
        ),
        Index(
            "ix_attack_simulation_runs_org_result",
            "organization_id",
            "enforcement_result",
        ),
    )


class ScenarioEvidence(Base, TimestampMixin):
    """Evidence artifacts for an attack simulation scenario."""

    __tablename__ = "scenario_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    run_id = Column(
        String(36),
        ForeignKey("attack_simulation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_type = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    content = Column(JSON, nullable=False, default=dict)

    run = relationship("AttackSimulationRun")
