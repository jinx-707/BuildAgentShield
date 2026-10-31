"""Add campaign and simulation tables for cyber range

Revision ID: 0004_cyber_range_campaigns
Revises: 0003_hybrid_deployment
Create Date: 2026-10-31
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0004_cyber_range_campaigns"
down_revision = "0003_hybrid_deployment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "simulation_campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("policy_version", sa.String(length=100), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED",
                "INITIALIZING",
                "RUNNING",
                "COMPLETED",
                "FAILED",
                "CANCELLED",
                "TIMED_OUT",
                name="campaign_status",
            ),
            nullable=False,
            server_default="QUEUED",
        ),
        sa.Column("scenario_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
        sa.Column("execution_mode", sa.String(length=50), nullable=False, server_default="sequential"),
        sa.Column("max_concurrency", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
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
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_simulation_campaigns_organization_id"),
        "simulation_campaigns",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_simulation_campaigns_user_id"),
        "simulation_campaigns",
        ["user_id"],
    )
    op.create_index(
        op.f("ix_simulation_campaigns_status"),
        "simulation_campaigns",
        ["status"],
    )
    op.create_index(
        "ix_campaigns_org_time",
        "simulation_campaigns",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_campaigns_org_status",
        "simulation_campaigns",
        ["organization_id", "status"],
    )

    op.create_table(
        "simulations",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("scenario_id", sa.String(length=100), nullable=False),
        sa.Column("target_id", sa.String(length=100), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED",
                "INITIALIZING",
                "RUNNING",
                "DETECTED",
                "BLOCKED",
                "COMPLETED",
                "FAILED",
                "CANCELLED",
                "TIMED_OUT",
                name="simulation_status",
            ),
            nullable=False,
            server_default="QUEUED",
        ),
        sa.Column(
            "assessment",
            sa.Enum(
                "PASS",
                "FAIL",
                "ERROR",
                "INCONCLUSIVE",
                name="assessment_result",
            ),
            nullable=True,
        ),
        sa.Column("policy_version", sa.String(length=100), nullable=False),
        sa.Column("browser_session_id", sa.String(length=255), nullable=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=False),
            nullable=True,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("agent_shield_decision", sa.String(length=50), nullable=True),
        sa.Column("proxy_decision", sa.String(length=50), nullable=True),
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
            ["campaign_id"],
            ["simulation_campaigns.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_simulations_campaign_id"),
        "simulations",
        ["campaign_id"],
    )
    op.create_index(
        op.f("ix_simulations_organization_id"),
        "simulations",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_simulations_scenario_id"),
        "simulations",
        ["scenario_id"],
    )
    op.create_index(
        op.f("ix_simulations_status"),
        "simulations",
        ["status"],
    )
    op.create_index(
        op.f("ix_simulations_assessment"),
        "simulations",
        ["assessment"],
    )
    op.create_index(
        "ix_simulations_campaign_time",
        "simulations",
        ["campaign_id", "created_at"],
    )
    op.create_index(
        "ix_simulations_org_scenario",
        "simulations",
        ["organization_id", "scenario_id"],
    )

    op.create_table(
        "simulation_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "simulation_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("evidence_type", sa.String(length=50), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("source", sa.String(length=50), nullable=False),
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
            ["simulation_id"],
            ["simulations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_simulation_evidence_simulation_id"),
        "simulation_evidence",
        ["simulation_id"],
    )
    op.create_index(
        op.f("ix_simulation_evidence_evidence_type"),
        "simulation_evidence",
        ["evidence_type"],
    )
    op.create_index(
        op.f("ix_simulation_evidence_source"),
        "simulation_evidence",
        ["source"],
    )

    op.create_table(
        "campaign_events",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["simulation_campaigns.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_campaign_events_campaign_id"),
        "campaign_events",
        ["campaign_id"],
    )
    op.create_index(
        op.f("ix_campaign_events_event_type"),
        "campaign_events",
        ["event_type"],
    )

    op.create_table(
        "simulation_events",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "simulation_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("stage", sa.String(length=50), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["simulation_id"],
            ["simulations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_simulation_events_simulation_id"),
        "simulation_events",
        ["simulation_id"],
    )
    op.create_index(
        op.f("ix_simulation_events_stage"),
        "simulation_events",
        ["stage"],
    )


def downgrade() -> None:
    op.drop_table("simulation_events")
    op.drop_table("campaign_events")
    op.drop_table("simulation_evidence")
    op.drop_table("simulations")
    op.drop_table("simulation_campaigns")
    op.execute("DROP TYPE IF EXISTS campaign_status")
    op.execute("DROP TYPE IF EXISTS simulation_status")
    op.execute("DROP TYPE IF EXISTS assessment_result")