"""
F6 — concurrency tests for the scan-and-store phase.

The scan phase can be entered by the automatic lifecycle and by manual
POST /scan requests.  These tests drive the orchestrator with scripted
scanners to prove that, for one download:

* the phase is serialized by a per-download lock and runs at most once;
* a queued duplicate observes the post-DOWNLOADED state and no-ops;
* there is no global lock — different downloads scan concurrently;
* failure, cancellation, a missing/moved file and a repeated request all
  leave exactly one consistent state and no stray storage.

Storage and database are real (tmp_path filesystem + file-backed SQLite);
only the scanner — an external daemon — is substituted.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from config.settings import Settings  # noqa: F401  (imported for parity with other suites)
from models.database import Base, get_async_engine, get_async_session
from models.download import Download, DownloadState
from security.errors import INVALID_STATE, DownloadSecurityError
from services.orchestrator import DownloadOrchestrator
from services.repository import DownloadRepository
from services.scanner import ScanResult, ScanVerdict
from storage.manager import StorageManager, StorageRef, StorageZone

PDF_BODY = b"%PDF-1.7\nconcurrency test payload\n%%EOF\n"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
async def storage(tmp_path):
    manager = StorageManager(str(tmp_path / "storage"))
    manager.initialize()
    yield manager
    # Nothing to clean up — tmp_path belongs to pytest.


@pytest.fixture
async def repository(tmp_path):
    engine = get_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'scan.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield DownloadRepository(get_async_session(engine))
    await engine.dispose()


class _NoopStreamer:
    """The download step is out of scope here; records are seeded directly."""

    async def download(self, url: str):  # pragma: no cover - never called
        raise AssertionError("streamer must not be used in scan-concurrency tests")


def build_orchestrator(repository, storage, scanner) -> DownloadOrchestrator:
    return DownloadOrchestrator(
        repository=repository,
        streamer=_NoopStreamer(),  # type: ignore[arg-type]
        scanner=scanner,  # type: ignore[arg-type]
        storage_manager=storage,
    )


# ── Scripted scanners ─────────────────────────────────────────────────────────

class GateScanner:
    """
    Blocks inside scan() until released.

    Lets a test hold the scan phase open while a second caller arrives, which
    is exactly the race the per-download lock exists to close.
    """

    def __init__(self, verdict: ScanVerdict = ScanVerdict.CLEAN) -> None:
        self.verdict = verdict
        self.calls: list[Path] = []
        self.entered = asyncio.Event()
        self._release = asyncio.Event()

    def release(self) -> None:
        self._release.set()

    async def scan(self, file_path: Path) -> ScanResult:
        self.calls.append(file_path)
        self.entered.set()
        await self._release.wait()
        return ScanResult(verdict=self.verdict, detail="gate")

    async def is_available(self) -> bool:
        return True


class OverlapScanner:
    """
    Requires two concurrent scan() calls to make progress.

    If locking were global (one lock for all downloads) the second download
    could never enter while the first waited here, and wait_for() would time
    out — turning the test into a proof about lock scope rather than intent.
    """

    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0
        self.calls: list[Path] = []
        self._both_here = asyncio.Event()

    async def scan(self, file_path: Path) -> ScanResult:
        self.calls.append(file_path)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        if self.active >= 2:
            self._both_here.set()
        try:
            await asyncio.wait_for(self._both_here.wait(), timeout=5.0)
        finally:
            self.active -= 1
        return ScanResult(verdict=ScanVerdict.CLEAN, detail="overlap")

    async def is_available(self) -> bool:
        return True


class RaisingScanner:
    """Simulates a scanner that errors out (fail-closed path)."""

    def __init__(self) -> None:
        self.calls: list[Path] = []

    async def scan(self, file_path: Path) -> ScanResult:
        self.calls.append(file_path)
        raise RuntimeError("clamd socket closed")

    async def is_available(self) -> bool:
        return True


class CountingScanner:
    """Returns immediately and counts invocations."""

    def __init__(self, verdict: ScanVerdict = ScanVerdict.CLEAN) -> None:
        self.verdict = verdict
        self.calls: list[Path] = []

    async def scan(self, file_path: Path) -> ScanResult:
        self.calls.append(file_path)
        return ScanResult(verdict=self.verdict, detail="counted")

    async def is_available(self) -> bool:
        return True


# ── Helpers ───────────────────────────────────────────────────────────────────

async def seed_downloaded(
    repository: DownloadRepository,
    storage: StorageManager,
    *,
    tenant_id: str = "tenant-a",
    body: bytes = PDF_BODY,
    sha_override: str | None = None,
) -> Download:
    """Create a record already in DOWNLOADED with a real file in temporary storage."""
    download_id = str(uuid.uuid4())
    await repository.create(
        download_id=download_id,
        tenant_id=tenant_id,
        agent_id="agent-1",
        original_url="https://example.com/report.pdf",
    )
    temp_path, temp_ref = storage.allocate_temp_path()
    temp_path.write_bytes(body)

    await repository.update_state(
        download_id=download_id,
        tenant_id=tenant_id,
        target_state=DownloadState.VALIDATING,
    )
    await repository.update_state(
        download_id=download_id,
        tenant_id=tenant_id,
        target_state=DownloadState.DOWNLOADING,
    )
    await repository.update_file_metadata(
        download_id=download_id,
        tenant_id=tenant_id,
        sha256=sha_override or storage.compute_sha256(temp_ref),
        file_size=len(body),
        detected_mime="application/pdf",
        original_filename="report.pdf",
        storage_ref=temp_ref.ref_string,
    )
    return await repository.update_state(
        download_id=download_id,
        tenant_id=tenant_id,
        target_state=DownloadState.DOWNLOADED,
    )


def zone_files(storage: StorageManager, zone: StorageZone) -> list[str]:
    directory = Path(storage._root) / zone.value  # noqa: SLF001 - test inspection
    return sorted(p.name for p in directory.iterdir()) if directory.exists() else []


async def wait_for_state(
    repository: DownloadRepository,
    download_id: str,
    tenant_id: str,
    states: set[DownloadState],
    *,
    timeout: float = 5.0,
) -> Download:
    """Poll until the persisted record reaches one of `states`."""

    async def _poll() -> Download:
        while True:
            record = await repository.get(download_id=download_id, tenant_id=tenant_id)
            if record.state in states:
                return record
            await asyncio.sleep(0.01)

    return await asyncio.wait_for(_poll(), timeout=timeout)


async def wait_for_count(scanner, expected: int, *, timeout: float = 5.0) -> None:
    async def _poll() -> None:
        while len(scanner.calls) != expected:
            await asyncio.sleep(0.01)

    await asyncio.wait_for(_poll(), timeout=timeout)


# ── Tests: the manual-vs-automatic race ───────────────────────────────────────

async def test_manual_scan_during_automatic_lifecycle_does_not_scan_twice(
    repository, storage
):
    """
    Manual POST /scan arriving while the automatic lifecycle holds the lock.

    The manual request is answered idempotently (the record is already past
    DOWNLOADED), no second scan task is created, and the file is approved once.
    """
    scanner = GateScanner()
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(repository, storage)

    auto = asyncio.create_task(orch._run_scan_and_store(record))
    await asyncio.wait_for(scanner.entered.wait(), timeout=5.0)

    manual = await orch.request_scan(
        download_id=record.id, tenant_id=record.tenant_id
    )
    assert manual.state in {DownloadState.VERIFYING, DownloadState.SCANNING}

    scanner.release()
    await auto

    final = await repository.get(download_id=record.id, tenant_id=record.tenant_id)
    assert final.state is DownloadState.APPROVED
    assert len(scanner.calls) == 1
    assert len(zone_files(storage, StorageZone.APPROVED)) == 1
    assert zone_files(storage, StorageZone.TEMPORARY) == []


async def test_two_concurrent_scan_calls_scan_and_move_once(repository, storage):
    """
    Two callers enter the phase while the record is still DOWNLOADED.

    Both pass the pre-lock state check, so the lock plus the re-check under it
    is what keeps the scan, the storage move and the APPROVED transition to
    one execution each.
    """
    scanner = GateScanner()
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(repository, storage)

    first = asyncio.create_task(orch._run_scan_and_store(record))
    await asyncio.wait_for(scanner.entered.wait(), timeout=5.0)

    second = asyncio.create_task(orch._run_scan_and_store(record))
    await asyncio.sleep(0.05)  # let the second caller queue on the lock
    assert len(scanner.calls) == 1

    scanner.release()
    await asyncio.gather(first, second)

    final = await repository.get(download_id=record.id, tenant_id=record.tenant_id)
    assert final.state is DownloadState.APPROVED
    assert len(scanner.calls) == 1
    assert len(zone_files(storage, StorageZone.APPROVED)) == 1
    assert zone_files(storage, StorageZone.TEMPORARY) == []
    # The ref stored after approval points at the approved zone.
    assert StorageRef.parse(final.storage_ref).zone is StorageZone.APPROVED


async def test_two_simultaneous_manual_requests_are_serialized(repository, storage):
    """Two POST /scan calls in the same tick: one scan, one approval."""
    scanner = GateScanner()
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(repository, storage)

    a = await orch.request_scan(download_id=record.id, tenant_id=record.tenant_id)
    b = await orch.request_scan(download_id=record.id, tenant_id=record.tenant_id)
    assert a.state is DownloadState.DOWNLOADED
    assert b.state is DownloadState.DOWNLOADED

    await asyncio.wait_for(scanner.entered.wait(), timeout=5.0)
    scanner.release()

    await wait_for_state(
        repository,
        record.id,
        record.tenant_id,
        {DownloadState.APPROVED, DownloadState.QUARANTINED, DownloadState.FAILED},
    )
    await asyncio.sleep(0.1)

    final = await repository.get(download_id=record.id, tenant_id=record.tenant_id)
    assert final.state is DownloadState.APPROVED
    assert len(scanner.calls) == 1
    assert len(zone_files(storage, StorageZone.APPROVED)) == 1


# ── Tests: lock scope ─────────────────────────────────────────────────────────

async def test_lock_is_per_download_not_global(repository, storage):
    """Different downloads scan at the same time (no shared lock across them)."""
    scanner = OverlapScanner()
    orch = build_orchestrator(repository, storage, scanner)

    one = await seed_downloaded(repository, storage, tenant_id="tenant-a")
    two = await seed_downloaded(repository, storage, tenant_id="tenant-b")

    await asyncio.gather(
        orch._run_scan_and_store(one),
        orch._run_scan_and_store(two),
    )

    assert scanner.max_active == 2, "scans were serialized by a global lock"
    assert len(scanner.calls) == 2
    for record in (one, two):
        final = await repository.get(
            download_id=record.id, tenant_id=record.tenant_id
        )
        assert final.state is DownloadState.APPROVED
    assert len(zone_files(storage, StorageZone.APPROVED)) == 2


async def test_scan_lock_entries_are_reclaimed(repository, storage):
    """The per-download lock dict does not grow with every download."""
    scanner = CountingScanner()
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(repository, storage)

    await orch._run_scan_and_store(record)
    await orch._run_scan_and_store(record)

    assert orch._scan_locks == {}
    assert orch._scan_lock_waiters == {}


# ── Tests: failure, cancellation, missing file, repeats ───────────────────────

async def test_infected_verdict_quarantines_once(repository, storage):
    scanner = CountingScanner(verdict=ScanVerdict.INFECTED)
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(repository, storage)

    await orch._run_scan_and_store(record)
    # A follow-up scan must not move or transition the record again.
    await orch._run_scan_and_store(record)

    final = await repository.get(download_id=record.id, tenant_id=record.tenant_id)
    assert final.state is DownloadState.QUARANTINED
    assert final.scan_result == "INFECTED"
    assert StorageRef.parse(final.storage_ref).zone is StorageZone.QUARANTINE
    assert len(zone_files(storage, StorageZone.QUARANTINE)) == 1
    assert zone_files(storage, StorageZone.APPROVED) == []
    assert len(scanner.calls) == 1

    # QUARANTINED is a terminal, past-DOWNLOADED state: a later manual request
    # is answered idempotently and never re-runs the scan or moves the file.
    idempotent = await orch.request_scan(
        download_id=record.id, tenant_id=record.tenant_id
    )
    assert idempotent.state is DownloadState.QUARANTINED
    await asyncio.sleep(0.05)
    assert len(scanner.calls) == 1
    assert len(zone_files(storage, StorageZone.QUARANTINE)) == 1


async def test_scanner_error_fails_and_cleans_temp(repository, storage):
    scanner = RaisingScanner()
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(repository, storage)

    await orch._run_scan_and_store(record)
    await wait_for_state(
        repository, record.id, record.tenant_id, {DownloadState.FAILED}
    )

    final = await repository.get(download_id=record.id, tenant_id=record.tenant_id)
    assert final.state is DownloadState.FAILED
    assert final.scan_result == "ERROR"
    assert zone_files(storage, StorageZone.TEMPORARY) == []
    assert zone_files(storage, StorageZone.APPROVED) == []

    with pytest.raises(DownloadSecurityError) as exc_info:
        await orch.request_scan(download_id=record.id, tenant_id=record.tenant_id)
    assert exc_info.value.code == INVALID_STATE


async def test_cancelled_scan_leaves_failed_state_and_no_temp(repository, storage):
    """
    Cancelling mid-scan must not strand the record.

    Before the fix, CancelledError bypassed cleanup and the record stayed in
    SCANNING with its temporary file on disk.
    """
    scanner = GateScanner()
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(repository, storage)

    task = asyncio.create_task(orch._run_scan_and_store(record))
    await asyncio.wait_for(scanner.entered.wait(), timeout=5.0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    final = await wait_for_state(
        repository, record.id, record.tenant_id, {DownloadState.FAILED}
    )
    assert "cancelled" in (final.failure_reason or "").lower()
    await asyncio.sleep(0.05)
    assert zone_files(storage, StorageZone.TEMPORARY) == []
    assert zone_files(storage, StorageZone.APPROVED) == []
    assert orch._scan_locks == {}


async def test_missing_temp_file_is_never_approved(repository, storage):
    """A file removed/moved out from under the scan fails closed."""
    scanner = CountingScanner()
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(repository, storage)

    # Simulate the temporary file having already left the temporary zone.
    ref = StorageRef.parse(record.storage_ref)
    storage.delete(ref)

    await orch._run_scan_and_store(record)

    final = await repository.get(download_id=record.id, tenant_id=record.tenant_id)
    assert final.state is DownloadState.FAILED
    assert len(scanner.calls) == 0
    assert zone_files(storage, StorageZone.APPROVED) == []


async def test_checksum_mismatch_rejects_and_removes_temp(repository, storage):
    scanner = CountingScanner()
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(
        repository, storage, sha_override="0" * 64
    )

    await orch._run_scan_and_store(record)

    final = await repository.get(download_id=record.id, tenant_id=record.tenant_id)
    assert final.state is DownloadState.REJECTED
    assert len(scanner.calls) == 0, "a mismatched file must not reach the scanner"
    assert zone_files(storage, StorageZone.TEMPORARY) == []


async def test_repeated_scan_after_approval_is_idempotent(repository, storage):
    scanner = CountingScanner()
    orch = build_orchestrator(repository, storage, scanner)
    record = await seed_downloaded(repository, storage)

    await orch._run_scan_and_store(record)
    approved = await repository.get(download_id=record.id, tenant_id=record.tenant_id)
    assert approved.state is DownloadState.APPROVED

    for _ in range(3):
        again = await orch.request_scan(
            download_id=record.id, tenant_id=record.tenant_id
        )
        assert again.state is DownloadState.APPROVED
        await orch._run_scan_and_store(record)

    await asyncio.sleep(0.1)
    final = await repository.get(download_id=record.id, tenant_id=record.tenant_id)
    assert final.state is DownloadState.APPROVED
    assert len(scanner.calls) == 1
    assert len(zone_files(storage, StorageZone.APPROVED)) == 1
    # Approval sets a TTL; SQLite returns it as a naive timestamp.
    assert final.expires_at is not None
