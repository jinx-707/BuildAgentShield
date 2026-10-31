"""
Download orchestrator.

Implements the full download lifecycle from PENDING to APPROVED or QUARANTINED.

The orchestrator owns the lifecycle state machine.  It delegates to:
  - DownloadPreflight  — URL validation + SSRF guard (pre-download)
  - DownloadStreamer    — proxy-enforced streaming to temporary storage
  - MimeValidator      — magic-byte MIME detection (already called inside streamer)
  - ClamAvScanner      — malware scan
  - StorageManager     — zone transitions
  - DownloadRepository — metadata persistence

Concurrency model
-----------------
A per-tenant semaphore limits simultaneous active downloads.  If the limit
is reached the new request is rejected with CONCURRENCY_LIMIT_EXCEEDED.

Scan serialization
------------------
The scan-and-store phase of a download (checksum verification, ClamAV scan,
zone move, terminal state transition) can be entered by two callers: the
automatic lifecycle and a manual POST /scan.  Both paths run under a
per-download asyncio.Lock (reference-counted so entries are reclaimed), which
prevents:

* a manual scan racing the automatic lifecycle over the same file;
* two simultaneous manual scans executing twice;
* duplicate storage moves and double APPROVED/QUARANTINED transitions.

The lock is per download — different downloads scan concurrently — and is
never a global lock held across ClamAV I/O.  On entry, under the lock, the
record is re-read: anything that is not in DOWNLOADED means the work is
already done or in progress elsewhere, and the scan exits as a no-op.
If the scan task is cancelled mid-flight, a shielded recovery transition puts
the record into FAILED (a consistent terminal state) and deletes the
temporary file before the cancellation propagates.

Design decisions
----------------
1. The orchestrator is the only layer that drives state transitions.
2. Database state and filesystem state are updated in tandem.  If the database
   write fails, the file is cleaned up.
3. An APPROVED file must not skip the SCANNING state.  The transition
   SCANNING → APPROVED is the only path to approved storage.
4. On any unrecoverable error the record transitions to FAILED and the temp
   file is cleaned up.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from models.download import Download, DownloadState
from security.errors import (
    CONCURRENCY_LIMIT_EXCEEDED,
    INVALID_STATE,
    NOT_FOUND,
    DownloadSecurityError,
)
from services.downloader import DownloadStreamer
from services.repository import DownloadRepository
from services.scanner import ClamAvScanner, ScanVerdict
from storage.manager import StorageManager, StorageRef, StorageZone

logger = logging.getLogger(__name__)

# Fixed, content-free reason strings.  Raw exception text can contain internal
# paths, database details or scanner internals and must never reach the API.
_REASON_INTERNAL_FAILURE = "The download failed unexpectedly."
_REASON_SCAN_FAILED = "The malware scan could not be completed."
_REASON_CHECKSUM_MISMATCH = (
    "The stored file does not match its recorded checksum."
)
_REASON_STORAGE_FAILED = "The download could not be stored securely."
_REASON_CANCELLED = "Processing was cancelled before completion."
_REASON_RESTART = "Processing was interrupted by a service restart."

_ACTIVE_STATES = (
    DownloadState.PENDING,
    DownloadState.VALIDATING,
    DownloadState.DOWNLOADING,
    DownloadState.DOWNLOADED,
    DownloadState.VERIFYING,
    DownloadState.SCANNING,
)


class DownloadOrchestrator:
    def __init__(
        self,
        *,
        repository: DownloadRepository,
        streamer: DownloadStreamer,
        scanner: ClamAvScanner,
        storage_manager: StorageManager,
        max_concurrent_per_tenant: int = 5,
        approved_ttl_seconds: int = 3600,
    ) -> None:
        self._repo = repository
        self._streamer = streamer
        self._scanner = scanner
        self._storage = storage_manager
        self._max_concurrent = max_concurrent_per_tenant
        self._approved_ttl = approved_ttl_seconds
        # Per-tenant semaphores (created lazily).
        self._semaphores: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self._max_concurrent)
        )
        # Active (queued or running) lifecycle count per tenant.  Checked and
        # incremented with no await in between, so concurrent requests cannot
        # both slip past the limit the way a bare semaphore probe could.
        self._active: dict[str, int] = defaultdict(int)
        # Background lifecycle/scan tasks, so shutdown can cancel and await
        # them instead of leaving untracked work behind the event loop.
        self._tasks: set[asyncio.Task] = set()
        # Per-download scan locks (reference-counted, reclaimed at zero).
        self._scan_locks: dict[str, asyncio.Lock] = {}
        self._scan_lock_waiters: dict[str, int] = {}

    # ── Scan locking ────────────────────────────────────────────────────────

    def _enter_scan_lock(self, download_id: str) -> asyncio.Lock:
        # No awaits between dict operations: on a single-threaded event loop
        # this critical section cannot interleave, so creation/refcounting
        # needs no additional guard and scanning never blocks other downloads.
        lock = self._scan_locks.get(download_id)
        if lock is None:
            lock = self._scan_locks[download_id] = asyncio.Lock()
        self._scan_lock_waiters[download_id] = (
            self._scan_lock_waiters.get(download_id, 0) + 1
        )
        return lock

    def _leave_scan_lock(self, download_id: str) -> None:
        remaining = self._scan_lock_waiters.get(download_id, 0) - 1
        if remaining <= 0:
            self._scan_lock_waiters.pop(download_id, None)
            self._scan_locks.pop(download_id, None)
        else:
            self._scan_lock_waiters[download_id] = remaining

    async def initiate_download(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        url: str,
    ) -> Download:
        """
        Create a new download record and kick off the full lifecycle asynchronously.

        Returns the initial Download record (state=PENDING).  The lifecycle
        continues in a background task.
        """
        sem = self._semaphores[tenant_id]
        # The check and the increment below contain no await, so two requests
        # on the event loop cannot both observe a free slot.
        if self._active[tenant_id] >= self._max_concurrent:
            raise DownloadSecurityError(
                CONCURRENCY_LIMIT_EXCEEDED,
                f"Maximum concurrent downloads ({self._max_concurrent}) for this "
                "tenant have been reached.  Retry later.",
                http_status=429,
            )
        self._active[tenant_id] += 1

        download_id = str(uuid.uuid4())
        try:
            record = await self._repo.create(
                download_id=download_id,
                tenant_id=tenant_id,
                agent_id=agent_id,
                original_url=url,
            )
        except Exception:
            self._release_active(tenant_id)
            raise

        # Run the lifecycle in the background so the API returns immediately.
        # The task is tracked so shutdown can cancel and await it.
        task = asyncio.create_task(
            self._run_lifecycle(record, sem),
            name=f"download-{download_id}",
        )
        self._track(task)
        return record

    async def recover_interrupted_downloads(self) -> int:
        """
        Fail downloads that were mid-flight when the process stopped.

        Called once at startup, before any new work is accepted.  A record in
        a non-terminal state has no owner after a restart, and its temporary
        file (if any) is an orphan; both are resolved here so the API never
        reports a stale in-progress download.
        """
        active = await self._repo.list_active()
        for record in active:
            try:
                if record.storage_ref:
                    try:
                        self._storage.delete(StorageRef.parse(record.storage_ref))
                    except ValueError:
                        pass
                await self._repo.update_state(
                    download_id=record.id,
                    tenant_id=record.tenant_id,
                    target_state=DownloadState.FAILED,
                    reason=_REASON_RESTART,
                )
            except Exception as exc:
                logger.error(
                    "download_recovery_failed",
                    extra={
                        "download_id": record.id,
                        "error_type": type(exc).__name__,
                    },
                )
        if active:
            logger.info("downloads_recovered", extra={"count": len(active)})
        return len(active)

    async def shutdown(self, *, timeout: float = 10.0) -> None:
        """Cancel and await in-flight background work (application shutdown)."""
        tasks = [task for task in self._tasks if not task.done()]
        if not tasks:
            return
        for task in tasks:
            task.cancel()
        await asyncio.wait(tasks, timeout=timeout)

    def _track(self, task: asyncio.Task) -> None:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _release_active(self, tenant_id: str) -> None:
        remaining = self._active.get(tenant_id, 0) - 1
        if remaining <= 0:
            self._active.pop(tenant_id, None)
        else:
            self._active[tenant_id] = remaining

    async def get_status(self, *, download_id: str, tenant_id: str) -> Download:
        return await self._repo.get(download_id=download_id, tenant_id=tenant_id)

    async def get_metadata(self, *, download_id: str, tenant_id: str) -> Download:
        return await self._repo.get(download_id=download_id, tenant_id=tenant_id)

    async def request_scan(self, *, download_id: str, tenant_id: str) -> Download:
        """
        Manually trigger a scan on a DOWNLOADED record.

        This is an idempotent trigger: if the record is already past DOWNLOADED
        (i.e. VERIFYING, SCANNING, APPROVED, QUARANTINED) it returns the current
        record without error.  A caller cannot use this endpoint to bypass the
        lifecycle: the record must be in DOWNLOADED state or the request is rejected.

        The scan itself runs under the download's per-record lock, so a manual
        trigger racing the automatic lifecycle (or another manual trigger)
        executes the scan phase at most once; the queued duplicate observes the
        post-DOWNLOADED state under the lock and exits as a no-op.
        """
        record = await self._repo.get(download_id=download_id, tenant_id=tenant_id)
        if record.state in {
            DownloadState.VERIFYING,
            DownloadState.SCANNING,
            DownloadState.APPROVED,
            DownloadState.QUARANTINED,
        }:
            # Already past DOWNLOADED — idempotent.
            return record

        if record.state != DownloadState.DOWNLOADED:
            raise DownloadSecurityError(
                INVALID_STATE,
                f"Scan can only be requested for downloads in DOWNLOADED state. "
                f"Current state: {record.state.value}.",
                http_status=409,
            )

        # Kick off scan in background.  Tracked so shutdown can await it.
        task = asyncio.create_task(
            self._run_scan_and_store(record),
            name=f"scan-{download_id}",
        )
        self._track(task)
        return record

    async def expire_old_downloads(self) -> int:
        """
        Expire and clean up records whose TTL has passed.

        Returns the number of records expired.
        """
        now = datetime.now(tz=timezone.utc)
        expired = await self._repo.list_expired(before=now)
        count = 0
        for record in expired:
            try:
                # Delete the physical file if still present.
                if record.storage_ref:
                    ref = StorageRef.parse(record.storage_ref)
                    self._storage.delete(ref)
                await self._repo.update_state(
                    download_id=record.id,
                    tenant_id=record.tenant_id,
                    target_state=DownloadState.EXPIRED,
                    reason="TTL expired",
                )
                count += 1
            except Exception as exc:
                logger.error(
                    "expiry_error",
                    extra={"download_id": record.id, "error_type": type(exc).__name__},
                )
        return count

    # ── Internal lifecycle ────────────────────────────────────────────────────

    async def _run_lifecycle(
        self, record: Download, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            try:
                await self._run_validation_and_download(record)
            except asyncio.CancelledError:
                await self._recover_after_download_cancel(record)
                raise
            except Exception as exc:
                logger.error(
                    "download_lifecycle_failed",
                    extra={
                        "download_id": record.id,
                        "tenant_id": record.tenant_id,
                        "error_type": type(exc).__name__,
                    },
                )
                await self._fail_if_active(
                    record.id, record.tenant_id, _REASON_INTERNAL_FAILURE
                )
            finally:
                self._release_active(record.tenant_id)

    async def _recover_after_download_cancel(self, record: Download) -> None:
        """
        Leave a consistent FAILED record when a lifecycle task is cancelled.

        Runs shielded from the cancellation so the state write and temp-file
        cleanup complete before the task exits (e.g. at shutdown).
        """

        async def _recover() -> None:
            try:
                current = await self._repo.get(
                    download_id=record.id, tenant_id=record.tenant_id
                )
                if current.state in _ACTIVE_STATES:
                    if current.storage_ref:
                        self._cleanup_storage(current.storage_ref)
                    await self._fail(
                        record.id,
                        record.tenant_id,
                        DownloadState.FAILED,
                        _REASON_CANCELLED,
                    )
            except Exception as exc:
                logger.error(
                    "download_cancel_recovery_failed",
                    extra={
                        "download_id": record.id,
                        "error_type": type(exc).__name__,
                    },
                )

        recovery = asyncio.create_task(
            _recover(), name=f"download-cancel-{record.id}"
        )
        try:
            await asyncio.shield(recovery)
        except asyncio.CancelledError:
            # The shield keeps the recovery task running to completion.
            pass

    async def _run_validation_and_download(self, record: Download) -> None:
        download_id = record.id
        tenant_id = record.tenant_id

        # PENDING → VALIDATING
        try:
            record = await self._repo.update_state(
                download_id=download_id,
                tenant_id=tenant_id,
                target_state=DownloadState.VALIDATING,
            )
        except Exception as exc:
            logger.error("state_update_failed", extra={"stage": "VALIDATING", "error_type": type(exc).__name__})
            return

        # Validate URL (SSRF pre-flight).
        try:
            # VALIDATING → DOWNLOADING
            record = await self._repo.update_state(
                download_id=download_id,
                tenant_id=tenant_id,
                target_state=DownloadState.DOWNLOADING,
            )
        except DownloadSecurityError as exc:
            await self._fail(download_id, tenant_id, DownloadState.REJECTED, str(exc))
            return

        # Stream the file.
        temp_ref = None
        try:
            result = await self._streamer.download(record.original_url)
            temp_ref = result.storage_ref

            # DOWNLOADING → DOWNLOADED
            record = await self._repo.update_file_metadata(
                download_id=download_id,
                tenant_id=tenant_id,
                sha256=result.sha256,
                file_size=result.file_size,
                detected_mime=result.detected_mime,
                original_filename=result.original_filename,
                storage_ref=temp_ref.ref_string,
            )
            record = await self._repo.update_state(
                download_id=download_id,
                tenant_id=tenant_id,
                target_state=DownloadState.DOWNLOADED,
            )
        except DownloadSecurityError as exc:
            if temp_ref:
                self._storage.delete(temp_ref)
            state = (
                DownloadState.REJECTED
                if exc.http_status == 403
                else DownloadState.FAILED
            )
            logger.warning(
                "download_rejected",
                extra={
                    "download_id": download_id,
                    "tenant_id": tenant_id,
                    "code": exc.code,
                },
            )
            await self._fail(download_id, tenant_id, state, exc.message)
            return
        except Exception as exc:
            if temp_ref:
                self._storage.delete(temp_ref)
            logger.error(
                "download_unexpected_error",
                extra={
                    "download_id": download_id,
                    "tenant_id": tenant_id,
                    "error_type": type(exc).__name__,
                },
            )
            await self._fail(
                download_id,
                tenant_id,
                DownloadState.FAILED,
                _REASON_INTERNAL_FAILURE,
            )
            return

        # Continue with verification + scanning.
        await self._run_scan_and_store(record)

    async def _run_scan_and_store(self, record: Download) -> None:
        """
        Serialized scan-and-store for one download.

        Manual scans (request_scan) and the automatic lifecycle both enter
        here; the per-download lock plus the state re-check under it make the
        whole phase exactly-once.  The lock is held for this download only.
        """
        lock = self._enter_scan_lock(record.id)
        try:
            async with lock:
                current = await self._repo.get(
                    download_id=record.id, tenant_id=record.tenant_id
                )
                if current.state != DownloadState.DOWNLOADED:
                    logger.info(
                        "scan_skipped_not_downloaded",
                        extra={
                            "download_id": record.id,
                            "state": current.state.value,
                        },
                    )
                    return
                await self._run_scan_locked(current)
        except asyncio.CancelledError:
            await self._recover_after_cancel(record)
            raise
        except Exception as exc:
            # Any unexpected failure in the scan/store phase must still leave a
            # terminal, identifiable record and no stray temporary file.
            logger.error(
                "scan_phase_unexpected_error",
                extra={
                    "download_id": record.id,
                    "error_type": type(exc).__name__,
                },
            )
            await self._fail_if_active(
                record.id, record.tenant_id, _REASON_INTERNAL_FAILURE
            )
        finally:
            self._leave_scan_lock(record.id)

    async def _recover_after_cancel(self, record: Download) -> None:
        """
        Leave a consistent record after the scan task was cancelled.

        The recovery runs as an independent task shielded from this
        cancellation so the state write cannot itself be interrupted and the
        record never stays in VERIFYING/SCANNING forever.
        """
        async def _recover() -> None:
            try:
                current = await self._repo.get(
                    download_id=record.id, tenant_id=record.tenant_id
                )
                if current.state in {
                    DownloadState.DOWNLOADED,
                    DownloadState.VERIFYING,
                    DownloadState.SCANNING,
                }:
                    await self._fail(
                        record.id,
                        record.tenant_id,
                        DownloadState.FAILED,
                        _REASON_CANCELLED,
                    )
                    if current.storage_ref:
                        self._cleanup_storage(current.storage_ref)
            except Exception as exc:
                logger.error(
                    "scan_cancel_recovery_failed",
                    extra={"download_id": record.id, "error_type": type(exc).__name__},
                )

        recovery = asyncio.create_task(_recover(), name=f"scan-cancel-{record.id}")
        try:
            await asyncio.shield(recovery)
        except asyncio.CancelledError:
            # The shield keeps `recovery` running to completion even though
            # this task stays cancelled.
            pass

    async def _run_scan_locked(self, record: Download) -> None:
        download_id = record.id
        tenant_id = record.tenant_id

        temp_ref: StorageRef | None = None
        if record.storage_ref:
            try:
                temp_ref = StorageRef.parse(record.storage_ref)
            except ValueError:
                await self._fail(download_id, tenant_id, DownloadState.FAILED,
                                 "Invalid storage_ref in database.")
                return

        # DOWNLOADED → VERIFYING
        try:
            record = await self._repo.update_state(
                download_id=download_id,
                tenant_id=tenant_id,
                target_state=DownloadState.VERIFYING,
            )
        except Exception as exc:
            logger.error("state_update_failed", extra={"stage": "VERIFYING", "error_type": type(exc).__name__})
            return

        # Verify checksum matches what was stored.
        if temp_ref and record.file_sha256:
            try:
                actual_sha = self._storage.compute_sha256(temp_ref)
            except Exception as exc:
                logger.error(
                    "checksum_computation_failed",
                    extra={
                        "download_id": download_id,
                        "error_type": type(exc).__name__,
                    },
                )
                await self._fail_if_active(
                    download_id, tenant_id, _REASON_INTERNAL_FAILURE
                )
                return
            if actual_sha != record.file_sha256:
                logger.warning(
                    "checksum_mismatch",
                    extra={
                        "download_id": download_id,
                        "tenant_id": tenant_id,
                    },
                )
                await self._fail_if_active(
                    download_id,
                    tenant_id,
                    _REASON_CHECKSUM_MISMATCH,
                    target=DownloadState.REJECTED,
                )
                return

        # VERIFYING → SCANNING
        try:
            record = await self._repo.update_state(
                download_id=download_id,
                tenant_id=tenant_id,
                target_state=DownloadState.SCANNING,
            )
        except Exception as exc:
            logger.error("state_update_failed", extra={"stage": "SCANNING", "error_type": type(exc).__name__})
            return

        # Run ClamAV scan.
        scan_result = None
        if temp_ref and temp_ref.zone == StorageZone.TEMPORARY:
            try:
                scan_path = self._storage.temporary_path(temp_ref)
            except Exception as exc:
                logger.error(
                    "scan_path_resolution_failed",
                    extra={
                        "download_id": download_id,
                        "error_type": type(exc).__name__,
                    },
                )
                scan_path = None
            if scan_path and scan_path.exists():
                try:
                    scan_result = await self._scanner.scan(scan_path)
                except Exception as exc:
                    # ScannerUnavailableError (fail-closed) or any other
                    # scanner failure: nothing is approved and the reason the
                    # caller sees is fixed text, never the exception.
                    logger.error(
                        "scanner_unavailable",
                        extra={
                            "download_id": download_id,
                            "error_type": type(exc).__name__,
                        },
                    )
                    try:
                        await self._repo.update_scan_result(
                            download_id=download_id,
                            tenant_id=tenant_id,
                            scan_result="ERROR",
                            scan_detail=_REASON_SCAN_FAILED,
                        )
                    except Exception as update_exc:
                        logger.error(
                            "scan_result_update_failed",
                            extra={
                                "download_id": download_id,
                                "error_type": type(update_exc).__name__,
                            },
                        )
                    await self._fail_if_active(
                        download_id, tenant_id, _REASON_SCAN_FAILED
                    )
                    return

        if scan_result is None:
            await self._fail_if_active(
                download_id, tenant_id, _REASON_SCAN_FAILED
            )
            return

        await self._repo.update_scan_result(
            download_id=download_id,
            tenant_id=tenant_id,
            scan_result=scan_result.verdict.value,
            scan_detail=scan_result.detail,
        )

        stored_ref: StorageRef | None = None
        try:
            if scan_result.verdict == ScanVerdict.CLEAN:
                # SCANNING → APPROVED: move to approved storage.
                if temp_ref and temp_ref.zone == StorageZone.TEMPORARY:
                    stored_ref = self._storage.move_to_approved(temp_ref)
                    expires_at = datetime.now(tz=timezone.utc) + timedelta(
                        seconds=self._approved_ttl
                    )
                    await self._repo.update_file_metadata(
                        download_id=download_id,
                        tenant_id=tenant_id,
                        sha256=record.file_sha256 or "",
                        file_size=record.file_size or 0,
                        detected_mime=record.detected_mime_type or "",
                        original_filename=record.original_filename,
                        storage_ref=stored_ref.ref_string,
                    )
                    await self._repo.set_expiry(
                        download_id=download_id,
                        tenant_id=tenant_id,
                        expires_at=expires_at,
                    )
                await self._repo.update_state(
                    download_id=download_id,
                    tenant_id=tenant_id,
                    target_state=DownloadState.APPROVED,
                )
                logger.info(
                    "download_approved",
                    extra={
                        "download_id": download_id,
                        "tenant_id": tenant_id,
                        "file_size": record.file_size,
                    },
                )
            else:
                # Any non-CLEAN verdict → QUARANTINED.
                if temp_ref and temp_ref.zone == StorageZone.TEMPORARY:
                    stored_ref = self._storage.move_to_quarantine(temp_ref)
                    await self._repo.update_file_metadata(
                        download_id=download_id,
                        tenant_id=tenant_id,
                        sha256=record.file_sha256 or "",
                        file_size=record.file_size or 0,
                        detected_mime=record.detected_mime_type or "",
                        original_filename=record.original_filename,
                        storage_ref=stored_ref.ref_string,
                    )
                await self._repo.update_state(
                    download_id=download_id,
                    tenant_id=tenant_id,
                    target_state=DownloadState.QUARANTINED,
                    reason=(
                        f"Scan verdict: {scan_result.verdict.value} — "
                        f"{scan_result.detail}"
                    ),
                )
                logger.warning(
                    "download_quarantined",
                    extra={
                        "download_id": download_id,
                        "tenant_id": tenant_id,
                        "verdict": scan_result.verdict.value,
                    },
                )
        except Exception as exc:
            # A failed move or metadata write must not leave a file in an
            # ambiguous zone or a record stuck in SCANNING.
            logger.error(
                "download_store_failed",
                extra={
                    "download_id": download_id,
                    "tenant_id": tenant_id,
                    "error_type": type(exc).__name__,
                },
            )
            if stored_ref is not None:
                self._storage.delete(stored_ref)
            if temp_ref is not None:
                self._storage.delete(temp_ref)
            await self._fail(
                download_id, tenant_id, DownloadState.FAILED, _REASON_STORAGE_FAILED
            )

    async def _fail_if_active(
        self,
        download_id: str,
        tenant_id: str,
        reason: str,
        *,
        target: DownloadState = DownloadState.FAILED,
    ) -> None:
        """
        Fail a non-terminal record and remove its stored file.

        Re-reads the record first so an already-terminal record (for example
        one another path just failed) is not transitioned twice.
        """
        try:
            current = await self._repo.get(
                download_id=download_id, tenant_id=tenant_id
            )
            if current.state not in _ACTIVE_STATES:
                return
            if current.storage_ref:
                self._cleanup_storage(current.storage_ref)
            await self._fail(download_id, tenant_id, target, reason)
        except Exception as exc:
            logger.error(
                "fail_if_active_error",
                extra={
                    "download_id": download_id,
                    "error_type": type(exc).__name__,
                },
            )

    def _cleanup_storage(self, storage_ref: str) -> None:
        try:
            self._storage.delete(StorageRef.parse(storage_ref))
        except ValueError:
            pass

    async def _fail(
        self,
        download_id: str,
        tenant_id: str,
        target_state: DownloadState,
        reason: str,
    ) -> None:
        try:
            await self._repo.update_state(
                download_id=download_id,
                tenant_id=tenant_id,
                target_state=target_state,
                reason=reason,
            )
        except Exception as exc:
            logger.error(
                "fail_state_update_error",
                extra={"download_id": download_id, "error_type": type(exc).__name__},
            )
