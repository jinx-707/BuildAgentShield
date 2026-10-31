"""Initial AgentShield email security schema.

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-10-30 19:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. oauth_accounts table
    op.create_table(
        "oauth_accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("account_email", sa.String(length=255), nullable=False),
        sa.Column("encrypted_access_token", sa.Text(), nullable=False),
        sa.Column("encrypted_refresh_token", sa.Text(), nullable=True),
        sa.Column("token_expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("granted_scopes", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_oauth_accounts_tenant_id", "oauth_accounts", ["tenant_id"])
    op.create_index("ix_oauth_accounts_agent_id", "oauth_accounts", ["agent_id"])
    op.create_index("ix_oauth_accounts_account_email", "oauth_accounts", ["account_email"])

    # 2. oauth_states table
    op.create_table(
        "oauth_states",
        sa.Column("state_token", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False, server_default="google"),
        sa.Column("requested_scopes", sa.JSON(), nullable=False),
        sa.Column("redirect_uri", sa.String(length=512), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("state_token"),
    )

    # 3. email_audit_records table
    op.create_table(
        "email_audit_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("policy_decision_id", sa.String(length=128), nullable=True),
        sa.Column("inspection_reference_id", sa.String(length=128), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_email_audit_records_tenant_id", "email_audit_records", ["tenant_id"])
    op.create_index("ix_email_audit_records_agent_id", "email_audit_records", ["agent_id"])
    op.create_index("ix_email_audit_records_event_type", "email_audit_records", ["event_type"])
    op.create_index("ix_email_audit_records_status", "email_audit_records", ["status"])
    op.create_index("ix_email_audit_records_timestamp", "email_audit_records", ["timestamp"])

    # 4. approval_references table
    op.create_table(
        "approval_references",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=True),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("target_resource", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=998), nullable=True),
        sa.Column("recipients", sa.JSON(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("attachment_hashes", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("payload_summary", sa.JSON(), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_approval_references_tenant_id", "approval_references", ["tenant_id"])
    op.create_index("ix_approval_references_agent_id", "approval_references", ["agent_id"])
    op.create_index("ix_approval_references_account_id", "approval_references", ["account_id"])
    op.create_index("ix_approval_references_content_hash", "approval_references", ["content_hash"])

    # 5. attachment_quarantine_records table
    op.create_table(
        "attachment_quarantine_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.String(length=128), nullable=False),
        sa.Column("attachment_id", sa.String(length=128), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256_hash", sa.String(length=64), nullable=False),
        sa.Column("quarantine_reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_attachment_quarantine_records_tenant_id", "attachment_quarantine_records", ["tenant_id"])
    op.create_index("ix_attachment_quarantine_records_agent_id", "attachment_quarantine_records", ["agent_id"])
    op.create_index("ix_attachment_quarantine_records_message_id", "attachment_quarantine_records", ["message_id"])
    op.create_index("ix_attachment_quarantine_records_attachment_id", "attachment_quarantine_records", ["attachment_id"])
    op.create_index("ix_attachment_quarantine_records_sha256_hash", "attachment_quarantine_records", ["sha256_hash"])


def downgrade() -> None:
    op.drop_table("attachment_quarantine_records")
    op.drop_table("approval_references")
    op.drop_table("email_audit_records")
    op.drop_table("oauth_states")
    op.drop_table("oauth_accounts")
