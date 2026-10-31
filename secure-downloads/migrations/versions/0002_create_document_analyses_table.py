"""Create document_analyses table.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-31 05:30:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ANALYSIS_STATE_VALUES = (
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
)


def upgrade() -> None:
    op.create_table(
        "document_analyses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "download_id",
            sa.String(36),
            sa.ForeignKey("downloads.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column(
            "state",
            sa.Enum(*_ANALYSIS_STATE_VALUES, name="analysis_state"),
            nullable=False,
            server_default="PENDING",
        ),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.Column("provider_analysis_id", sa.String(128), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("retryable", sa.Boolean(), nullable=True),
        sa.Column("result_json", sa.Text(), nullable=True),
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
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    # One analysis job per download: duplicate submissions cannot create a
    # second job even under concurrent requests.
    op.create_index(
        "ix_document_analyses_download_id",
        "document_analyses",
        ["download_id"],
        unique=True,
    )
    op.create_index(
        "ix_document_analyses_tenant_id", "document_analyses", ["tenant_id"]
    )
    op.create_index("ix_document_analyses_state", "document_analyses", ["state"])


def downgrade() -> None:
    op.drop_index("ix_document_analyses_state", table_name="document_analyses")
    op.drop_index("ix_document_analyses_tenant_id", table_name="document_analyses")
    op.drop_index("ix_document_analyses_download_id", table_name="document_analyses")
    op.drop_table("document_analyses")
    sa.Enum(name="analysis_state").drop(op.get_bind(), checkfirst=True)
