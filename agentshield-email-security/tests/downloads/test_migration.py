"""Alembic revision chain and secure_downloads upgrade/downgrade tests."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Base

REPO_ROOT = Path(__file__).resolve().parents[2]


def _alembic_script() -> ScriptDirectory:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    return ScriptDirectory.from_config(cfg)


class TestAlembicRevisionChain:
    def test_002_revises_001(self):
        script = _alembic_script()
        rev = script.get_revision("002_secure_downloads")
        assert rev is not None
        assert rev.down_revision == "001_initial_schema"

    def test_head_includes_secure_downloads(self):
        script = _alembic_script()
        # Verify that the secure_downloads revision is reachable from head
        heads = script.get_heads()
        # heads may advance beyond 002 as new migrations are added;
        # confirm 002_secure_downloads is in the full revision chain.
        all_ids = {rev.revision for rev in script.walk_revisions(base="base", head="heads")}
        assert "002_secure_downloads" in all_ids, (
            f"002_secure_downloads not found in revision chain; heads={heads}, chain={all_ids}"
        )

    def test_revision_chain_contains_email_and_downloads(self):
        script = _alembic_script()
        ids = {rev.revision for rev in script.walk_revisions(base="base", head="heads")}
        assert "001_initial_schema" in ids
        assert "002_secure_downloads" in ids


class TestSecureDownloadsSchema:
    def test_metadata_columns(self):
        table = Base.metadata.tables["secure_downloads"]
        column_names = set(table.columns.keys())
        expected = {
            "id",
            "tenant_id",
            "agent_id",
            "original_url",
            "source_hostname",
            "status",
            "storage_zone",
            "storage_ref",
            "expected_type",
            "detected_mime",
            "size_bytes",
            "sha256",
            "original_filename",
            "redirect_count",
            "scan_verdict",
            "scanner_version",
            "threat_name",
            "scan_in_progress",
            "findings_json",
            "policy_decision",
            "handoff_status",
            "handoff_idempotency_key",
            "failure_code",
            "failure_reason",
            "created_at",
            "updated_at",
            "expires_at",
        }
        assert expected <= column_names
        assert "file_bytes" not in column_names
        assert "content" not in column_names
        assert "encrypted_access_token" not in column_names

    def test_security_check_constraints_present(self):
        table = Base.metadata.tables["secure_downloads"]
        names = {ck.name for ck in table.constraints if getattr(ck, "name", None)}
        assert "ck_secure_downloads_approved_status_zone" in names
        assert "ck_secure_downloads_quarantined_status_zone" in names
        assert "ck_secure_downloads_handoff_approved_only" in names
        assert "ck_secure_downloads_quarantine_not_approved" in names

    @pytest.mark.asyncio
    async def test_create_all_creates_table(self, db_session: AsyncSession):
        conn = await db_session.connection()

        def _inspect(sync_conn):
            insp = inspect(sync_conn)
            return insp.has_table("secure_downloads"), insp.get_columns("secure_downloads")

        has_table, columns = await conn.run_sync(_inspect)
        assert has_table is True
        names = {col["name"] for col in columns}
        assert "sha256" in names
        assert "storage_zone" in names
        assert "original_url" in names
        assert "policy_decision" in names


def _run_alembic(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


class TestAlembicUpgradeDowngrade:
    def test_upgrade_and_downgrade_isolated_sqlite(self, tmp_path: Path):
        db_path = tmp_path / "phase_b.db"
        env = os.environ.copy()
        env["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
        env["APP_ENV"] = "test"
        env["PYTHONPATH"] = str(REPO_ROOT)

        up = _run_alembic(["upgrade", "head"], env)
        assert up.returncode == 0, up.stdout + up.stderr

        engine = create_engine(f"sqlite:///{db_path}")
        with engine.connect() as conn:
            tables = inspect(conn).get_table_names()
            assert "secure_downloads" in tables
            assert "oauth_accounts" in tables
            cols = {c["name"] for c in inspect(conn).get_columns("secure_downloads")}
            assert "original_url" in cols
            assert "storage_zone" in cols
            indexes = {i["name"] for i in inspect(conn).get_indexes("secure_downloads")}
            assert "ix_secure_downloads_tenant_id" in indexes
            oauth_count = conn.execute(text("SELECT COUNT(*) FROM oauth_accounts")).scalar()
            assert oauth_count == 0

        down = _run_alembic(["downgrade", "001_initial_schema"], env)
        assert down.returncode == 0, down.stdout + down.stderr

        with engine.connect() as conn:
            tables = inspect(conn).get_table_names()
            assert "secure_downloads" not in tables
            assert "oauth_accounts" in tables

        up_again = _run_alembic(["upgrade", "head"], env)
        assert up_again.returncode == 0, up_again.stdout + up_again.stderr
        with engine.connect() as conn:
            assert "secure_downloads" in inspect(conn).get_table_names()
        engine.dispose()
