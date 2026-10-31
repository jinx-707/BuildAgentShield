"""Hybrid deployment: extend deployments table with enrollment and sync fields.

Revision ID: 0003_hybrid_deployment
Revises: 0002_ai_agent_security
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_hybrid_deployment"
down_revision = "0002_ai_agent_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add new columns to the deployments table.
    op.add_column(
        "deployments",
        sa.Column("profile", sa.String(50), nullable=False, server_default="hybrid"),
    )
    op.add_column(
        "deployments",
        sa.Column("location_label", sa.String(255), nullable=True),
    )
    op.add_column(
        "deployments",
        sa.Column("data_plane_version", sa.String(128), nullable=True),
    )
    op.add_column(
        "deployments",
        sa.Column("enrollment_token_hash", sa.String(64), nullable=True),
    )
    op.add_column(
        "deployments",
        sa.Column("enrollment_token_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "deployments",
        sa.Column("deployment_secret_hash", sa.String(64), nullable=True),
    )
    op.add_column(
        "deployments",
        sa.Column("current_policy_version", sa.String(255), nullable=True),
    )
    op.add_column(
        "deployments",
        sa.Column(
            "current_policy_sequence",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "deployments",
        sa.Column("last_policy_sync_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "deployments",
        sa.Column("disconnected_since", sa.DateTime(timezone=True), nullable=True),
    )

    # Migrate status default value from "pending" → "pending_enrollment"
    op.execute(
        "UPDATE deployments SET status = 'pending_enrollment' WHERE status = 'pending'"
    )

    # Drop the old plaintext enrollment_token column (previously stored tokens
    # in cleartext — now replaced by enrollment_token_hash).
    op.drop_column("deployments", "enrollment_token")


def downgrade() -> None:
    op.add_column(
        "deployments",
        sa.Column("enrollment_token", sa.String(255), nullable=True),
    )
    op.drop_column("deployments", "disconnected_since")
    op.drop_column("deployments", "last_policy_sync_at")
    op.drop_column("deployments", "current_policy_sequence")
    op.drop_column("deployments", "current_policy_version")
    op.drop_column("deployments", "deployment_secret_hash")
    op.drop_column("deployments", "enrollment_token_expires_at")
    op.drop_column("deployments", "enrollment_token_hash")
    op.drop_column("deployments", "data_plane_version")
    op.drop_column("deployments", "location_label")
    op.drop_column("deployments", "profile")
