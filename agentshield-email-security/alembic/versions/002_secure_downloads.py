"""Module 3 secure downloads table.

Revision ID: 002_secure_downloads
Revises: 001_initial_schema
Create Date: 2026-10-31 00:40:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "002_secure_downloads"
down_revision: Union[str, None] = "001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "secure_downloads",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("original_url", sa.String(length=2048), nullable=False),
        sa.Column("source_hostname", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("storage_zone", sa.String(length=32), nullable=False, server_default="none"),
        sa.Column("storage_ref", sa.String(length=64), nullable=True),
        sa.Column("expected_type", sa.String(length=128), nullable=True),
        sa.Column("detected_mime", sa.String(length=128), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("original_filename", sa.String(length=255), nullable=True),
        sa.Column("redirect_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scan_verdict", sa.String(length=64), nullable=True),
        sa.Column("scanner_version", sa.String(length=128), nullable=True),
        sa.Column("threat_name", sa.String(length=255), nullable=True),
        sa.Column("scan_in_progress", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("findings_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("policy_decision", sa.String(length=16), nullable=False, server_default="DENY"),
        sa.Column("handoff_status", sa.String(length=32), nullable=False, server_default="none"),
        sa.Column("handoff_idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_ref", name="uq_secure_downloads_storage_ref"),
        sa.CheckConstraint(
            "status IN ("
            "'pending','validating','downloading','downloaded',"
            "'scanning','quarantined','approved',"
            "'rejected','failed','expired'"
            ")",
            name="ck_secure_downloads_status",
        ),
        sa.CheckConstraint(
            "storage_zone IN ('none','temp','quarantine','approved')",
            name="ck_secure_downloads_storage_zone",
        ),
        sa.CheckConstraint(
            "status != 'approved' OR storage_zone = 'approved'",
            name="ck_secure_downloads_approved_status_zone",
        ),
        sa.CheckConstraint(
            "storage_zone != 'approved' OR status = 'approved'",
            name="ck_secure_downloads_approved_zone_status",
        ),
        sa.CheckConstraint(
            "status != 'quarantined' OR storage_zone = 'quarantine'",
            name="ck_secure_downloads_quarantined_status_zone",
        ),
        sa.CheckConstraint(
            "storage_zone != 'quarantine' OR status != 'approved'",
            name="ck_secure_downloads_quarantine_not_approved",
        ),
        sa.CheckConstraint(
            "policy_decision IN ('DENY','ALLOW')",
            name="ck_secure_downloads_policy_decision",
        ),
        sa.CheckConstraint(
            "handoff_status IN ('none','completed','rejected')",
            name="ck_secure_downloads_handoff_status",
        ),
        sa.CheckConstraint(
            "handoff_status != 'completed' OR status = 'approved'",
            name="ck_secure_downloads_handoff_approved_only",
        ),
        sa.CheckConstraint(
            "sha256 IS NULL OR length(sha256) = 64",
            name="ck_secure_downloads_sha256_len",
        ),
    )
    op.create_index("ix_secure_downloads_tenant_id", "secure_downloads", ["tenant_id"])
    op.create_index("ix_secure_downloads_agent_id", "secure_downloads", ["agent_id"])
    op.create_index("ix_secure_downloads_status", "secure_downloads", ["status"])
    op.create_index("ix_secure_downloads_sha256", "secure_downloads", ["sha256"])
    op.create_index("ix_secure_downloads_created_at", "secure_downloads", ["created_at"])
    op.create_index("ix_secure_downloads_expires_at", "secure_downloads", ["expires_at"])
    op.create_index(
        "ix_secure_downloads_tenant_agent",
        "secure_downloads",
        ["tenant_id", "agent_id"],
    )
    op.create_index(
        "ix_secure_downloads_tenant_status",
        "secure_downloads",
        ["tenant_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_secure_downloads_tenant_status", table_name="secure_downloads")
    op.drop_index("ix_secure_downloads_tenant_agent", table_name="secure_downloads")
    op.drop_index("ix_secure_downloads_expires_at", table_name="secure_downloads")
    op.drop_index("ix_secure_downloads_created_at", table_name="secure_downloads")
    op.drop_index("ix_secure_downloads_sha256", table_name="secure_downloads")
    op.drop_index("ix_secure_downloads_status", table_name="secure_downloads")
    op.drop_index("ix_secure_downloads_agent_id", table_name="secure_downloads")
    op.drop_index("ix_secure_downloads_tenant_id", table_name="secure_downloads")
    op.drop_table("secure_downloads")
