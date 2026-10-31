"""Prompt 3 AI agent security tables

Revision ID: 0002_ai_agent_security
Revises: 0001_initial
Create Date: 2026-10-31
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0002_ai_agent_security"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_executions",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("session_id", sa.String(length=255), nullable=True),
        sa.Column("request_id", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("target", sa.Text(), nullable=True),
        sa.Column("decision", sa.String(length=50), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
            server_default="info",
        ),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column(
            "trust_label",
            sa.String(length=20),
            nullable=False,
            server_default="untrusted",
        ),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_agent_executions_organization_id"),
        "agent_executions",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_agent_executions_agent_id"),
        "agent_executions",
        ["agent_id"],
    )
    op.create_index(
        op.f("ix_agent_executions_session_id"),
        "agent_executions",
        ["session_id"],
    )
    op.create_index(
        op.f("ix_agent_executions_request_id"),
        "agent_executions",
        ["request_id"],
    )
    op.create_index(
        op.f("ix_agent_executions_action"),
        "agent_executions",
        ["action"],
    )
    op.create_index(
        op.f("ix_agent_executions_decision"),
        "agent_executions",
        ["decision"],
    )
    op.create_index(
        "ix_agent_executions_org_time",
        "agent_executions",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_agent_executions_org_action",
        "agent_executions",
        ["organization_id", "action"],
    )
    op.create_index(
        "ix_agent_executions_org_decision",
        "agent_executions",
        ["organization_id", "decision"],
    )

    op.create_table(
        "threat_detections",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=False),
            nullable=True,
        ),
        sa.Column("session_id", sa.String(length=255), nullable=True),
        sa.Column(
            "execution_id",
            postgresql.UUID(as_uuid=False),
            nullable=True,
        ),
        sa.Column("threat_category", sa.String(length=100), nullable=False),
        sa.Column(
            "detection_module",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column("detection_reason", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
            server_default="medium",
        ),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("action_taken", sa.String(length=50), nullable=True),
        sa.Column("target", sa.Text(), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["execution_id"],
            ["agent_executions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_threat_detections_organization_id"),
        "threat_detections",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_threat_detections_agent_id"),
        "threat_detections",
        ["agent_id"],
    )
    op.create_index(
        op.f("ix_threat_detections_session_id"),
        "threat_detections",
        ["session_id"],
    )
    op.create_index(
        op.f("ix_threat_detections_execution_id"),
        "threat_detections",
        ["execution_id"],
    )
    op.create_index(
        op.f("ix_threat_detections_threat_category"),
        "threat_detections",
        ["threat_category"],
    )
    op.create_index(
        op.f("ix_threat_detections_detection_module"),
        "threat_detections",
        ["detection_module"],
    )
    op.create_index(
        op.f("ix_threat_detections_severity"),
        "threat_detections",
        ["severity"],
    )
    op.create_index(
        "ix_threat_detections_org_time",
        "threat_detections",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_threat_detections_org_category",
        "threat_detections",
        ["organization_id", "threat_category"],
    )
    op.create_index(
        "ix_threat_detections_org_severity",
        "threat_detections",
        ["organization_id", "severity"],
    )

    op.create_table(
        "risk_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=False),
            nullable=True,
        ),
        sa.Column(
            "execution_id",
            postgresql.UUID(as_uuid=False),
            nullable=True,
        ),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
            server_default="medium",
        ),
        sa.Column(
            "recommended_action",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "enforcement_decision",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "detection_reasons",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "risk_factors",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["execution_id"],
            ["agent_executions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_risk_assessments_organization_id"),
        "risk_assessments",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_risk_assessments_agent_id"),
        "risk_assessments",
        ["agent_id"],
    )
    op.create_index(
        op.f("ix_risk_assessments_execution_id"),
        "risk_assessments",
        ["execution_id"],
    )
    op.create_index(
        op.f("ix_risk_assessments_severity"),
        "risk_assessments",
        ["severity"],
    )
    op.create_index(
        "ix_risk_assessments_org_time",
        "risk_assessments",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_risk_assessments_org_score",
        "risk_assessments",
        ["organization_id", "risk_score"],
    )

    op.create_table(
        "dlp_findings",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=False),
            nullable=True,
        ),
        sa.Column("session_id", sa.String(length=255), nullable=True),
        sa.Column("detection_rule", sa.String(length=100), nullable=False),
        sa.Column("detection_reason", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
            server_default="medium",
        ),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("action_taken", sa.String(length=50), nullable=True),
        sa.Column("target", sa.Text(), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_dlp_findings_organization_id"),
        "dlp_findings",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_dlp_findings_agent_id"),
        "dlp_findings",
        ["agent_id"],
    )
    op.create_index(
        op.f("ix_dlp_findings_session_id"),
        "dlp_findings",
        ["session_id"],
    )
    op.create_index(
        op.f("ix_dlp_findings_detection_rule"),
        "dlp_findings",
        ["detection_rule"],
    )
    op.create_index(
        op.f("ix_dlp_findings_severity"),
        "dlp_findings",
        ["severity"],
    )
    op.create_index(
        "ix_dlp_findings_org_time",
        "dlp_findings",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_dlp_findings_org_rule",
        "dlp_findings",
        ["organization_id", "detection_rule"],
    )

    op.create_table(
        "tool_decisions",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("session_id", sa.String(length=255), nullable=True),
        sa.Column("tool_name", sa.String(length=100), nullable=False),
        sa.Column(
            "tool_args",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("decision", sa.String(length=50), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "policy_references",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_tool_decisions_organization_id"),
        "tool_decisions",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_tool_decisions_agent_id"),
        "tool_decisions",
        ["agent_id"],
    )
    op.create_index(
        op.f("ix_tool_decisions_session_id"),
        "tool_decisions",
        ["session_id"],
    )
    op.create_index(
        op.f("ix_tool_decisions_tool_name"),
        "tool_decisions",
        ["tool_name"],
    )
    op.create_index(
        op.f("ix_tool_decisions_decision"),
        "tool_decisions",
        ["decision"],
    )
    op.create_index(
        "ix_tool_decisions_org_time",
        "tool_decisions",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_tool_decisions_org_tool",
        "tool_decisions",
        ["organization_id", "tool_name"],
    )
    op.create_index(
        "ix_tool_decisions_org_decision",
        "tool_decisions",
        ["organization_id", "decision"],
    )

    op.create_table(
        "attack_simulation_runs",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=False),
            nullable=True,
        ),
        sa.Column("session_id", sa.String(length=255), nullable=True),
        sa.Column("scenario_id", sa.String(length=100), nullable=False),
        sa.Column("scenario_name", sa.String(length=255), nullable=False),
        sa.Column("threat_category", sa.String(length=100), nullable=True),
        sa.Column("attempted_action", sa.Text(), nullable=True),
        sa.Column("policy_decision", sa.String(length=50), nullable=True),
        sa.Column(
            "enforcement_result",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_attack_simulation_runs_organization_id"),
        "attack_simulation_runs",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_attack_simulation_runs_agent_id"),
        "attack_simulation_runs",
        ["agent_id"],
    )
    op.create_index(
        op.f("ix_attack_simulation_runs_session_id"),
        "attack_simulation_runs",
        ["session_id"],
    )
    op.create_index(
        op.f("ix_attack_simulation_runs_scenario_id"),
        "attack_simulation_runs",
        ["scenario_id"],
    )
    op.create_index(
        op.f("ix_attack_simulation_runs_threat_category"),
        "attack_simulation_runs",
        ["threat_category"],
    )
    op.create_index(
        op.f("ix_attack_simulation_runs_enforcement_result"),
        "attack_simulation_runs",
        ["enforcement_result"],
    )
    op.create_index(
        "ix_attack_simulation_runs_org_time",
        "attack_simulation_runs",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_attack_simulation_runs_org_scenario",
        "attack_simulation_runs",
        ["organization_id", "scenario_id"],
    )
    op.create_index(
        "ix_attack_simulation_runs_org_result",
        "attack_simulation_runs",
        ["organization_id", "enforcement_result"],
    )

    op.create_table(
        "scenario_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("evidence_type", sa.String(length=50), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "content",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["attack_simulation_runs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_scenario_evidence_run_id"),
        "scenario_evidence",
        ["run_id"],
    )
    op.create_index(
        op.f("ix_scenario_evidence_evidence_type"),
        "scenario_evidence",
        ["evidence_type"],
    )


def downgrade() -> None:
    op.drop_table("scenario_evidence")
    op.drop_table("attack_simulation_runs")
    op.drop_table("tool_decisions")
    op.drop_table("dlp_findings")
    op.drop_table("risk_assessments")
    op.drop_table("threat_detections")
    op.drop_table("agent_executions")
