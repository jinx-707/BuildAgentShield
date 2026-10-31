"""Add capability permissions, scopes, and approval queue tables

Revision ID: 0005_capability_permissions
Revises: 0004_cyber_range_campaigns
Create Date: 2026-10-31
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0005_capability_permissions"
down_revision = "0004_cyber_range_campaigns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add scopes column to agents table
    op.add_column(
        "agents",
        sa.Column("scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    # Create capabilities table
    op.create_table(
        "capabilities",
        sa.Column("id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "tools",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_capabilities_org_key"),
        "capabilities",
        ["organization_id", "key"],
        unique=True,
    )
    op.create_index(
        op.f("ix_capabilities_key"), "capabilities", ["key"]
    )

    # Create agent_capabilities table
    op.create_table(
        "agent_capabilities",
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
        sa.Column(
            "capability_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "allowed_tools",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "resource_scope",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "allowed_domains",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "require_approval",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("payment_budget", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["capability_id"],
            ["capabilities.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_agent_capabilities_agent"), "agent_capabilities", ["agent_id"]
    )
    op.create_index(
        op.f("ix_agent_capabilities_capability"),
        "agent_capabilities",
        ["capability_id"],
    )
    op.create_index(
        op.f("ix_agent_capabilities_org_agent"),
        "agent_capabilities",
        ["organization_id", "agent_id"],
    )
    op.create_unique_constraint(
        "uq_agent_capability", "agent_capabilities", ["agent_id", "capability_id"]
    )

    # Create approval_requests table
    op.create_table(
        "approval_requests",
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
        sa.Column(
            "capability_id",
            postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("tool_name", sa.String(length=100), nullable=False),
        sa.Column(
            "tool_args",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("target", sa.String(length=500), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["capability_id"],
            ["capabilities.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_approval_requests_agent"), "approval_requests", ["agent_id"]
    )
    op.create_index(
        op.f("ix_approval_requests_status"), "approval_requests", ["status"]
    )


def downgrade() -> None:
    op.drop_table("approval_requests")
    op.drop_table("agent_capabilities")
    op.drop_table("capabilities")
    op.drop_column("agents", "scopes")
