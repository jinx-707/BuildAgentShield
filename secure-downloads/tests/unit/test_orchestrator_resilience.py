"""
Orchestrator resilience tests (Prompt 3, Phase 3E).

Drives the real lifecycle state machine, real SQLite repository and real
storage zones.  Only the network streamer and the ClamAV daemon are
substituted, because those require external processes.  Every test asserts a
durable outcome: terminal state, fixed failure text, released concurrency
slot, and no stray file in any zone.
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from models.database import Base, get_async_engine, get_async_session
from models.download import DownloadState
from security.errors import DownloadSecurityError, MIME_NOT_ALLOWED
from services.downloader import DownloadResult
from services.orchestrator import DownloadOrchestrator
from services.repository import DownloadRepository
from services.scanner import ScanResult, ScanVerdict
from storage.manager import StorageManager, StorageRef, StorageZone

TENANT = "tenant-resilience"
BODY = b"%PDF-1.7\nresilience body\n%%EOF\n"


@pytest.fixture
async def storage(tmp_path):
    manager = StorageManager(str(tmp_path / "storage"))
    manager.initialize()
    return manager


@pytest.fixture
async def repository(tmp_path):
    engine = get_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'resilience.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield DownloadRepository(get_async_session(engine))
    await engine.dispose()


class CleanScanner:
    def __init__(self) -> None:
        self.calls: list[Path] = []

    async def scan(self, file_path: Path) -> ScanResult:
        self.calls.append(file_path)
        return ScanResult(verdict=ScanVerdict.CLEAN)

    async def is_available(self) -> bool:
        return True


class SuccessfulStreamer:
    def __init__(self, storage: StorageManager, *, gate: asyncio.Event | None = None) -> None:
        self._storage = storage
        self._gate = gate
        self.calls = 0

    async def download(self, raw_url: str) -> DownloadResult:
        self.calls += 1
        path, ref = self._storage.allocate_temp_path()
        path.write_bytes(BODY)
        if self._gate is not None:
            try:
                await self._gate.wait()
            except asyncio.CancelledError:
                # The real DownloadStreamer discards the partial file on
                # cancellation; mirror that here so the test exercises the
                # orchestrator's state recovery, not a fake leak.
                path.unlink(missing_ok=True)
                raise
        return DownloadResult(
            storage_ref=ref,
            sha256=hashlib.sha256(BODY).hexdigest(),
            file_size=len(BODY),
            detected_mime="application/pdf",
            original_filename="report.pdf",
            final_url=raw_url,
            redirect_count=0,
        )


class RaisingStreamer:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def download(self, raw_url: str) -> DownloadResult:
        raise self._exc


def build(repository, storage, streamer, scanner=None, *, max_concurrent=5) -> DownloadOrchestrator:
    return DownloadOrchestrator(
        repository=repository,
        streamer=streamer,  # type: ignore[arg-type]
        scanner=scanner or CleanScanner(),  # type: ignore[arg-type]
        storage_manager=storage,
        max_concurrent_per_tenant=max_concurrent,
        approved_ttl_seconds=3600,
    )


async def wait_state(repository, download_id, states, *, timeout=5.0):
    async def poll():
        while True:
            record = await repository.get(download_id=download_id, tenant_id=TENANT)
            if record.state in states:
                return record
            await asyncio.sleep(0.01)

    return await asyncio.wait_for(poll(), timeout=timeout)


def zone_files(storage: StorageManager, zone: StorageZone) -> list[Path]:
    directory = Path(storage._root) / zone.value
    return sorted(p for p in directory.iterdir()) if directory.exists() else []


@pytest.fixture
async def orchestrators():
    created: list[DownloadOrchestrator] = []

    def factory(repository, storage, streamer, scanner=None, **kwargs):
        orchestrator = build(repository, storage, streamer, scanner, **kwargs)
        created.append(orchestrator)
        return orchestrator

    yield factory
    for orchestrator in created:
        await orchestrator.shutdown(timeout=5)


class TestSuccessfulLifecycle:
    async def test_download_is_approved_and_slot_released(self, repository, storage, orchestrators):
        orchestrator = orchestrators(repository, storage, SuccessfulStreamer(storage))
        record = await orchestrator.initiate_download(
            tenant_id=TENANT, agent_id="agent", url="https://example.com/report.pdf"
        )
        final = await wait_state(repository, record.id, {DownloadState.APPROVED})

        assert final.failure_reason is None
        assert final.file_sha256 == hashlib.sha256(BODY).hexdigest()
        assert final.scan_result == "CLEAN"
        assert final.storage_ref.startswith("approved/")
        assert zone_files(storage, StorageZone.TEMPORARY) == []
        approved = zone_files(storage, StorageZone.APPROVED)
        assert len(approved) == 1
        assert orchestrator._active.get(TENANT, 0) == 0


class TestFailuresLeaveConsistentState:
    async def test_security_rejection_cleans_up(self, repository, storage, orchestrators):
        exc = DownloadSecurityError(MIME_NOT_ALLOWED, "File type is not permitted.", http_status=403)
        orchestrator = orchestrators(repository, storage, RaisingStreamer(exc))
        record = await orchestrator.initiate_download(
            tenant_id=TENANT, agent_id="agent", url="https://example.com/x"
        )
        final = await wait_state(repository, record.id, {DownloadState.REJECTED})
        assert final.failure_reason == "File type is not permitted."
        assert zone_files(storage, StorageZone.TEMPORARY) == []
        assert orchestrator._active.get(TENANT, 0) == 0

    async def test_unexpected_streamer_error_is_fixed_text(self, repository, storage, orchestrators):
        orchestrator = orchestrators(
            repository, storage, RaisingStreamer(RuntimeError("secret internal detail"))
        )
        record = await orchestrator.initiate_download(
            tenant_id=TENANT, agent_id="agent", url="https://example.com/x"
        )
        final = await wait_state(repository, record.id, {DownloadState.FAILED})
        assert final.failure_reason == "The download failed unexpectedly."
        assert "secret internal detail" not in (final.failure_reason or "")
        assert zone_files(storage, StorageZone.TEMPORARY) == []

    async def test_storage_move_failure_is_failed_and_cleaned(
        self, repository, storage, orchestrators, monkeypatch
    ):
        orchestrator = orchestrators(repository, storage, SuccessfulStreamer(storage))

        def fail_move(ref):
            raise OSError("simulated storage failure")

        monkeypatch.setattr(storage, "move_to_approved", fail_move)
        record = await orchestrator.initiate_download(
            tenant_id=TENANT, agent_id="agent", url="https://example.com/report.pdf"
        )
        final = await wait_state(repository, record.id, {DownloadState.FAILED})
        assert final.failure_reason == "The download could not be stored securely."
        assert zone_files(storage, StorageZone.TEMPORARY) == []
        assert zone_files(storage, StorageZone.APPROVED) == []
        assert zone_files(storage, StorageZone.QUARANTINE) == []

    async def test_database_create_failure_releases_slot(self, repository, storage, orchestrators, monkeypatch):
        orchestrator = orchestrators(repository, storage, SuccessfulStreamer(storage))

        async def fail_create(**kwargs):
            raise RuntimeError("database unavailable")

        monkeypatch.setattr(repository, "create", fail_create)
        with pytest.raises(RuntimeError):
            await orchestrator.initiate_download(
                tenant_id=TENANT, agent_id="agent", url="https://example.com/x"
            )
        assert orchestrator._active.get(TENANT, 0) == 0
        assert orchestrator._tasks == set()


class TestShutdownCancellation:
    async def test_shutdown_cancels_download_and_cleans_up(self, repository, storage, orchestrators):
        gate = asyncio.Event()
        streamer = SuccessfulStreamer(storage, gate=gate)
        orchestrator = orchestrators(repository, storage, streamer)

        record = await orchestrator.initiate_download(
            tenant_id=TENANT, agent_id="agent", url="https://example.com/report.pdf"
        )
        await wait_state(repository, record.id, {DownloadState.DOWNLOADING})
        assert len(zone_files(storage, StorageZone.TEMPORARY)) == 1

        await orchestrator.shutdown(timeout=5)

        final = await repository.get(download_id=record.id, tenant_id=TENANT)
        assert final.state == DownloadState.FAILED
        assert final.failure_reason == "Processing was cancelled before completion."
        assert zone_files(storage, StorageZone.TEMPORARY) == []
        assert orchestrator._active.get(TENANT, 0) == 0


class TestRecoveryAndExpiry:
    async def test_recovery_fails_active_rows_and_reclaims_files(self, repository, storage):
        orchestrator = build(repository, storage, RaisingStreamer(RuntimeError("unused")))

        downloading = await repository.create(
            download_id=str(uuid.uuid4()),
            tenant_id=TENANT,
            agent_id="agent",
            original_url="https://example.com/a",
        )
        await repository.update_state(
            download_id=downloading.id, tenant_id=TENANT, target_state=DownloadState.VALIDATING
        )
        await repository.update_state(
            download_id=downloading.id, tenant_id=TENANT, target_state=DownloadState.DOWNLOADING
        )

        downloaded = await repository.create(
            download_id=str(uuid.uuid4()),
            tenant_id=TENANT,
            agent_id="agent",
            original_url="https://example.com/b",
        )
        path, ref = storage.allocate_temp_path()
        path.write_bytes(BODY)
        await repository.update_state(
            download_id=downloaded.id, tenant_id=TENANT, target_state=DownloadState.VALIDATING
        )
        await repository.update_state(
            download_id=downloaded.id, tenant_id=TENANT, target_state=DownloadState.DOWNLOADING
        )
        await repository.update_file_metadata(
            download_id=downloaded.id,
            tenant_id=TENANT,
            sha256=hashlib.sha256(BODY).hexdigest(),
            file_size=len(BODY),
            detected_mime="application/pdf",
            original_filename="b.pdf",
            storage_ref=ref.ref_string,
        )
        await repository.update_state(
            download_id=downloaded.id, tenant_id=TENANT, target_state=DownloadState.DOWNLOADED
        )

        rejected = await repository.create(
            download_id=str(uuid.uuid4()),
            tenant_id=TENANT,
            agent_id="agent",
            original_url="https://example.com/c",
        )
        await repository.update_state(
            download_id=rejected.id,
            tenant_id=TENANT,
            target_state=DownloadState.REJECTED,
            reason="already terminal",
        )

        recovered = await orchestrator.recover_interrupted_downloads()

        assert recovered == 2
        for record in (downloading, downloaded):
            refreshed = await repository.get(download_id=record.id, tenant_id=TENANT)
            assert refreshed.state == DownloadState.FAILED
            assert "restart" in (refreshed.failure_reason or "").lower()
        assert not path.exists()
        untouched = await repository.get(download_id=rejected.id, tenant_id=TENANT)
        assert untouched.state == DownloadState.REJECTED
        assert untouched.failure_reason == "already terminal"

    async def test_expiry_removes_approved_file_and_marks_expired(self, repository, storage):
        orchestrator = build(repository, storage, RaisingStreamer(RuntimeError("unused")))
        record = await repository.create(
            download_id=str(uuid.uuid4()),
            tenant_id=TENANT,
            agent_id="agent",
            original_url="https://example.com/a",
        )
        path, temp_ref = storage.allocate_temp_path()
        path.write_bytes(BODY)
        await repository.update_state(
            download_id=record.id, tenant_id=TENANT, target_state=DownloadState.VALIDATING
        )
        await repository.update_state(
            download_id=record.id, tenant_id=TENANT, target_state=DownloadState.DOWNLOADING
        )
        approved_ref = storage.move_to_approved(temp_ref)
        await repository.update_file_metadata(
            download_id=record.id,
            tenant_id=TENANT,
            sha256=hashlib.sha256(BODY).hexdigest(),
            file_size=len(BODY),
            detected_mime="application/pdf",
            original_filename="a.pdf",
            storage_ref=approved_ref.ref_string,
        )
        await repository.update_state(
            download_id=record.id, tenant_id=TENANT, target_state=DownloadState.DOWNLOADED
        )
        await repository.update_state(
            download_id=record.id, tenant_id=TENANT, target_state=DownloadState.VERIFYING
        )
        await repository.update_state(
            download_id=record.id, tenant_id=TENANT, target_state=DownloadState.SCANNING
        )
        await repository.update_state(
            download_id=record.id, tenant_id=TENANT, target_state=DownloadState.APPROVED
        )
        await repository.set_expiry(
            download_id=record.id,
            tenant_id=TENANT,
            expires_at=datetime.now(tz=timezone.utc) - timedelta(minutes=1),
        )

        expired = await orchestrator.expire_old_downloads()

        assert expired == 1
        final = await repository.get(download_id=record.id, tenant_id=TENANT)
        assert final.state == DownloadState.EXPIRED
        assert zone_files(storage, StorageZone.APPROVED) == []
