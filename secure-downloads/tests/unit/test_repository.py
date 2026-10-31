"""Tests for the DownloadRepository (database layer)."""
from __future__ import annotations

import pytest

from models.download import Download, DownloadState
from security.errors import NOT_FOUND, DownloadSecurityError
from services.repository import DownloadRepository


class TestCreateAndGet:
    async def test_create_returns_pending_record(self, repo):
        record = await repo.create(
            download_id="dl-001",
            tenant_id="tenant-a",
            agent_id="agent-1",
            original_url="https://example.com/file.pdf",
        )
        assert record.id == "dl-001"
        assert record.tenant_id == "tenant-a"
        assert record.state == DownloadState.PENDING

    async def test_get_returns_record(self, repo):
        await repo.create(
            download_id="dl-002",
            tenant_id="tenant-a",
            agent_id="agent-1",
            original_url="https://example.com/file.pdf",
        )
        record = await repo.get(download_id="dl-002", tenant_id="tenant-a")
        assert record.id == "dl-002"

    async def test_get_not_found_raises(self, repo):
        with pytest.raises(DownloadSecurityError) as exc_info:
            await repo.get(download_id="nonexistent", tenant_id="tenant-a")
        assert exc_info.value.code == NOT_FOUND

    async def test_get_wrong_tenant_returns_not_found(self, repo):
        """Cross-tenant access must return NOT_FOUND, not PERMISSION_DENIED."""
        await repo.create(
            download_id="dl-003",
            tenant_id="tenant-a",
            agent_id="agent-1",
            original_url="https://example.com/file.pdf",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            await repo.get(download_id="dl-003", tenant_id="tenant-b")
        # Must be NOT_FOUND — not PERMISSION_DENIED — to avoid enumeration.
        assert exc_info.value.code == NOT_FOUND


class TestStateTransitions:
    async def test_update_state_valid_transition(self, repo):
        await repo.create(
            download_id="dl-010",
            tenant_id="tenant-a",
            agent_id="agent-1",
            original_url="https://example.com/file.pdf",
        )
        record = await repo.update_state(
            download_id="dl-010",
            tenant_id="tenant-a",
            target_state=DownloadState.VALIDATING,
        )
        assert record.state == DownloadState.VALIDATING

    async def test_update_state_invalid_transition_raises(self, repo):
        from models.download import DownloadStateError

        await repo.create(
            download_id="dl-011",
            tenant_id="tenant-a",
            agent_id="agent-1",
            original_url="https://example.com/file.pdf",
        )
        with pytest.raises(DownloadStateError):
            await repo.update_state(
                download_id="dl-011",
                tenant_id="tenant-a",
                target_state=DownloadState.APPROVED,  # Invalid from PENDING
            )


class TestTenantIsolation:
    async def test_two_tenants_separate_records(self, repo):
        await repo.create(
            download_id="dl-a",
            tenant_id="tenant-A",
            agent_id="agent-1",
            original_url="https://example.com/a.pdf",
        )
        await repo.create(
            download_id="dl-b",
            tenant_id="tenant-B",
            agent_id="agent-1",
            original_url="https://example.com/b.pdf",
        )
        a = await repo.get(download_id="dl-a", tenant_id="tenant-A")
        b = await repo.get(download_id="dl-b", tenant_id="tenant-B")
        assert a.tenant_id == "tenant-A"
        assert b.tenant_id == "tenant-B"

    async def test_tenant_b_cannot_read_tenant_a_record(self, repo):
        await repo.create(
            download_id="dl-c",
            tenant_id="tenant-A",
            agent_id="agent-1",
            original_url="https://example.com/c.pdf",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            await repo.get(download_id="dl-c", tenant_id="tenant-B")
        assert exc_info.value.code == NOT_FOUND


class TestMetadataUpdate:
    async def test_update_file_metadata(self, repo):
        await repo.create(
            download_id="dl-meta",
            tenant_id="tenant-a",
            agent_id="agent-1",
            original_url="https://example.com/file.pdf",
        )
        record = await repo.update_file_metadata(
            download_id="dl-meta",
            tenant_id="tenant-a",
            sha256="abc123",
            file_size=12345,
            detected_mime="application/pdf",
            original_filename="report.pdf",
            storage_ref="temporary/uuid-here",
        )
        assert record.file_sha256 == "abc123"
        assert record.file_size == 12345
        assert record.detected_mime_type == "application/pdf"
        # storage_ref is stored but NEVER included in API responses.

    async def test_scan_result_persisted(self, repo):
        await repo.create(
            download_id="dl-scan",
            tenant_id="tenant-a",
            agent_id="agent-1",
            original_url="https://example.com/file.pdf",
        )
        record = await repo.update_scan_result(
            download_id="dl-scan",
            tenant_id="tenant-a",
            scan_result="CLEAN",
            scan_detail=None,
        )
        assert record.scan_result == "CLEAN"


class TestExpiry:
    async def test_list_expired_returns_records_past_deadline(self, repo):
        from datetime import datetime, timedelta, timezone

        past = datetime.now(tz=timezone.utc) - timedelta(seconds=1)
        await repo.create(
            download_id="dl-exp",
            tenant_id="tenant-a",
            agent_id="agent-1",
            original_url="https://example.com/file.pdf",
        )
        await repo.set_expiry(
            download_id="dl-exp",
            tenant_id="tenant-a",
            expires_at=past,
        )
        expired = await repo.list_expired(before=datetime.now(tz=timezone.utc))
        assert any(r.id == "dl-exp" for r in expired)

    async def test_list_expired_excludes_future_expiry(self, repo):
        from datetime import datetime, timedelta, timezone

        future = datetime.now(tz=timezone.utc) + timedelta(hours=1)
        await repo.create(
            download_id="dl-future",
            tenant_id="tenant-a",
            agent_id="agent-1",
            original_url="https://example.com/file.pdf",
        )
        await repo.set_expiry(
            download_id="dl-future",
            tenant_id="tenant-a",
            expires_at=future,
        )
        expired = await repo.list_expired(before=datetime.now(tz=timezone.utc))
        assert not any(r.id == "dl-future" for r in expired)
