"""SecureDownload model persistence, constraints, tenant isolation, and schemas."""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Base
from app.downloads.enums import (
    DownloadStatus,
    HandoffStatus,
    PolicyDecision,
    StorageZone,
)
from app.downloads.exceptions import InvalidStateTransitionError
from app.downloads.models import SecureDownload
from app.downloads.repository import SecureDownloadRepository
from app.downloads.schemas import DownloadRecordResponse


def _new_download(**overrides) -> SecureDownload:
    values = dict(
        id=uuid.uuid4(),
        tenant_id="tenant-a",
        agent_id="agent-a",
        original_url="https://files.example.com/report.pdf",
        source_hostname="files.example.com",
        status=DownloadStatus.PENDING.value,
        storage_zone=StorageZone.NONE.value,
        findings_json={},
        policy_decision=PolicyDecision.DENY.value,
        handoff_status=HandoffStatus.NONE.value,
    )
    values.update(overrides)
    return SecureDownload(**values)


class TestSecureDownloadLifecycleMethods:
    def test_cannot_approve_from_pending(self):
        rec = _new_download()
        with pytest.raises(InvalidStateTransitionError):
            rec.mark_approved("a" * 64)

    def test_downloaded_is_not_approved(self):
        rec = _new_download(status=DownloadStatus.DOWNLOADING.value, storage_zone=StorageZone.TEMP.value)
        rec.mark_downloaded("a" * 64)
        assert rec.status == DownloadStatus.DOWNLOADED.value
        assert rec.storage_zone == StorageZone.TEMP.value
        assert rec.policy_decision == PolicyDecision.DENY.value
        with pytest.raises(InvalidStateTransitionError):
            rec.mark_approved("a" * 64)

    def test_happy_path_approve_from_scanning(self):
        rec = _new_download(status=DownloadStatus.SCANNING.value, storage_zone=StorageZone.TEMP.value)
        rec.scan_verdict = "CLEAN"
        rec.sha256 = "b" * 64
        rec.mark_approved("a" * 64)
        assert rec.status == DownloadStatus.APPROVED.value
        assert rec.storage_zone == StorageZone.APPROVED.value
        assert rec.policy_decision == PolicyDecision.ALLOW.value

    def test_quarantine_from_scanning(self):
        rec = _new_download(status=DownloadStatus.SCANNING.value, storage_zone=StorageZone.TEMP.value)
        rec.mark_quarantined("c" * 64, reason="ClamAV infected")
        assert rec.status == DownloadStatus.QUARANTINED.value
        assert rec.storage_zone == StorageZone.QUARANTINE.value
        assert rec.policy_decision == PolicyDecision.DENY.value
        with pytest.raises(InvalidStateTransitionError):
            rec.assert_eligible_for_handoff()

    def test_transition_to_cannot_silently_approve(self):
        rec = _new_download(status=DownloadStatus.SCANNING.value, storage_zone=StorageZone.TEMP.value)
        with pytest.raises(InvalidStateTransitionError):
            rec.transition_to(DownloadStatus.APPROVED, storage_zone=StorageZone.APPROVED)

    def test_handoff_requires_clean_approved_file(self):
        rec = _new_download(status=DownloadStatus.SCANNING.value, storage_zone=StorageZone.TEMP.value)
        rec.sha256 = "d" * 64
        rec.scan_verdict = "CLEAN"
        rec.mark_approved("e" * 64)
        rec.assert_eligible_for_handoff()

        rec.scan_verdict = "SCANNER_UNAVAILABLE"
        with pytest.raises(InvalidStateTransitionError):
            rec.assert_eligible_for_handoff()

    def test_redacts_url_userinfo(self):
        rec = _new_download(original_url="https://user:secret@files.example.com/report.pdf?token=1")
        assert "secret" not in rec.original_url
        assert "user:" not in rec.original_url
        assert rec.original_url.startswith("https://files.example.com/")

    def test_sanitizes_original_filename(self):
        rec = _new_download(original_filename="../../evil.pdf")
        assert rec.original_filename == "evil.pdf"

    def test_response_schema_omits_filesystem_paths(self):
        rec = _new_download()
        rec.created_at = rec.updated_at = datetime.now(timezone.utc)
        payload = DownloadRecordResponse.model_validate(rec).model_dump()
        assert "filesystem_path" not in payload
        assert "path" not in payload
        dumped = str(payload)
        assert "storage/downloads" not in dumped


@pytest.mark.asyncio
class TestSecureDownloadPersistence:
    async def test_table_registered_on_base(self):
        assert "secure_downloads" in Base.metadata.tables

    async def test_indexes_and_constraints_present(self):
        table = Base.metadata.tables["secure_downloads"]
        index_names = {idx.name for idx in table.indexes}
        assert "ix_secure_downloads_tenant_id" in index_names
        assert "ix_secure_downloads_tenant_agent" in index_names
        assert "ix_secure_downloads_tenant_status" in index_names
        ck_names = {ck.name for ck in table.constraints if getattr(ck, "name", None)}
        assert "ck_secure_downloads_approved_status_zone" in ck_names
        assert "ck_secure_downloads_sha256_len" in ck_names

    async def test_insert_and_fetch(self, db_session: AsyncSession):
        rec = _new_download()
        db_session.add(rec)
        await db_session.flush()
        loaded = await db_session.get(SecureDownload, rec.id)
        assert loaded is not None
        assert loaded.status == "pending"
        assert loaded.policy_decision == "DENY"
        assert loaded.storage_zone == "none"
        assert loaded.original_url == "https://files.example.com/report.pdf"

    async def test_check_rejects_approved_in_temp(self, db_session: AsyncSession):
        rec = _new_download(
            status=DownloadStatus.APPROVED.value,
            storage_zone=StorageZone.TEMP.value,
            policy_decision=PolicyDecision.ALLOW.value,
        )
        db_session.add(rec)
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()

    async def test_check_rejects_quarantined_in_approved(self, db_session: AsyncSession):
        rec = _new_download(
            status=DownloadStatus.QUARANTINED.value,
            storage_zone=StorageZone.APPROVED.value,
        )
        db_session.add(rec)
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()

    async def test_check_rejects_handoff_completed_when_not_approved(
        self, db_session: AsyncSession
    ):
        rec = _new_download(
            status=DownloadStatus.QUARANTINED.value,
            storage_zone=StorageZone.QUARANTINE.value,
            handoff_status=HandoffStatus.COMPLETED.value,
        )
        db_session.add(rec)
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()

    async def test_check_rejects_unknown_status(self, db_session: AsyncSession):
        with pytest.raises(IntegrityError):
            await db_session.execute(
                text(
                    "INSERT INTO secure_downloads ("
                    "id, tenant_id, agent_id, original_url, source_hostname, "
                    "status, storage_zone, findings_json, policy_decision, handoff_status, "
                    "redirect_count, scan_in_progress, created_at, updated_at"
                    ") VALUES ("
                    ":id, 't', 'a', 'https://x.example/file', 'x.example', "
                    "'not-a-state', 'none', '{}', 'DENY', 'none', "
                    "0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                ),
                {"id": str(uuid.uuid4())},
            )
        await db_session.rollback()

    async def test_tenant_isolation(self, db_session: AsyncSession):
        repo = SecureDownloadRepository(db_session)
        rec = await repo.create(
            tenant_id="tenant-a",
            agent_id="agent-a",
            original_url="https://files.example.com/a.pdf",
        )
        await db_session.flush()

        same = await repo.get(rec.id, "tenant-a", "agent-a")
        assert same is not None
        assert same.id == rec.id

        cross_tenant = await repo.get(rec.id, "tenant-b", "agent-a")
        assert cross_tenant is None

        cross_agent = await repo.get(rec.id, "tenant-a", "agent-b")
        assert cross_agent is None

        tenant_only = await repo.get_for_tenant(rec.id, "tenant-b")
        assert tenant_only is None

    async def test_sqlite_schema_has_table(self, db_session: AsyncSession):
        conn = await db_session.connection()

        def _inspect(sync_conn):
            insp = inspect(sync_conn)
            return insp.has_table("secure_downloads"), insp.get_indexes("secure_downloads")

        has_table, indexes = await conn.run_sync(_inspect)
        assert has_table is True
        names = {idx["name"] for idx in indexes}
        assert "ix_secure_downloads_tenant_id" in names
