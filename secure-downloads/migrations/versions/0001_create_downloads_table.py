"""Create downloads table.

Revision ID: 0001
Revises:
Create Date: 2026-10-31 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# SQLite-compatible ENUM stored as VARCHAR
_STATE_ENUM_VALUES = (
    "PENDING",
    "VALIDATING",
    "DOWNLOADING",
    "DOWNLOADED",
    "VERIFYING",
    "SCANNING",
    "APPROVED",
    "QUARANTINED",
    "REJECTED",
    "FAILED",
    "EXPIRED",
)


def upgrade() -> None:
    op.create_table(
        "downloads",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False),
        sa.Column("original_url", sa.Text(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(*_STATE_ENUM_VALUES, name="download_state"),
            nullable=False,
            server_default="PENDING",
        ),
        sa.Column("original_filename", sa.Text(), nullable=True),
        sa.Column("detected_mime_type", sa.String(256), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("file_sha256", sa.String(64), nullable=True),
        sa.Column("storage_ref", sa.String(512), nullable=True),
        sa.Column("scan_result", sa.String(64), nullable=True),
        sa.Column("scan_detail", sa.Text(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("handoff_completed", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.create_index("ix_downloads_tenant_id", "downloads", ["tenant_id"])
    op.create_index("ix_downloads_agent_id", "downloads", ["agent_id"])
    op.create_index("ix_downloads_state", "downloads", ["state"])
    op.create_index("ix_downloads_expires_at", "downloads", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_downloads_expires_at", table_name="downloads")
    op.drop_index("ix_downloads_state", table_name="downloads")
    op.drop_index("ix_downloads_agent_id", table_name="downloads")
    op.drop_index("ix_downloads_tenant_id", table_name="downloads")
    op.drop_table("downloads")
    # Drop the Enum type (no-op on SQLite, required on PostgreSQL)
    sa.Enum(name="download_state").drop(op.get_bind(), checkfirst=True)
