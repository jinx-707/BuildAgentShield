"""
Document-analysis orchestration.

Pipeline (fail-closed at every step)
------------------------------------
    job PENDING → RUNNING
      → download record must still be APPROVED
      → approved-zone gate (existence + recorded SHA-256)   [handoff.verify]
      → read bytes from the approved zone only
      → re-hash the bytes actually read and compare to the recorded hash
      → local bounded PDF processing                        [PdfDocumentProcessor]
      → provider analysis with bounded retries/timeout      [adapter]
      → validate + sanitize the provider response           [analysis_models]
      → persist normalized result, mark handoff_completed
      → job COMPLETED
    Any failure → job FAILED with a fixed, content-free reason (retryable flag
    per the failure class).  Quarantined, rejected, unscanned or temporary
    files are unreachable: the record must be APPROVED and the storage ref
    must resolve inside the approved zone.

Concurrency
-----------
One job per download (DB unique constraint).  Execution additionally takes a
reference-counted per-download asyncio lock; under the lock the job is re-read
and anything not PENDING is a no-op, so a duplicate enqueue, a retry click and
a worker retry can never run the same job twice.  Different downloads analyze
concurrently.  The lock is never a global lock.

Long-running work is not spawned with unbounded ``asyncio.create_task``:
AnalysisRunner owns a fixed worker pool consuming a queue, and recovery
re-enqueues persisted PENDING/RUNNING jobs at startup.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from typing import Callable

from integrations.analysis_models import build_normalized_result
from integrations.handoff import (
    DocumentHandoffService,
    HandoffError,
    VerifiedDocument,
)
from models.analysis import AnalysisState, DocumentAnalysis
from models.download import DownloadState
from security.errors import (
    ANALYSIS_DISABLED,
    ANALYSIS_JOB_TIMEOUT,
    ANALYSIS_NOT_RETRYABLE,
    ANALYSIS_PAYLOAD_TOO_LARGE,
    CHECKSUM_MISMATCH,
    INVALID_STATE,
    DownloadSecurityError,
)
from services.analysis_repository import AnalysisRepository
from services.document_processor import DocumentProcessingError, PdfDocumentProcessor
from services.repository import DownloadRepository
from storage.manager import StorageManager, StorageRef

logger = logging.getLogger(__name__)


class AnalysisService:
    def __init__(
        self,
        *,
        downloads: DownloadRepository,
        analyses: AnalysisRepository,
        handoff: DocumentHandoffService,
        processor: PdfDocumentProcessor,
        storage: StorageManager,
        enabled: bool,
        max_payload_bytes: int,
        job_timeout_seconds: float,
        max_attempts: int,
    ) -> None:
        self._downloads = downloads
        self._analyses = analyses
        self._handoff = handoff
        self._processor = processor
        self._storage = storage
        self._enabled = enabled
        self._max_payload = max_payload_bytes
        self._job_timeout = job_timeout_seconds
        self._max_attempts = max_attempts
        self._enqueue: Callable[[str], None] | None = None
        # Per-download execution locks (reference-counted, reclaimed at zero).
        self._locks: dict[str, asyncio.Lock] = {}
        self._lock_users: dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def provider_name(self) -> str:
        return self._handoff.provider_name

    def set_enqueue(self, enqueue: Callable[[str], None]) -> None:
        self._enqueue = enqueue

    # ── Public API operations ────────────────────────────────────────────────

    async def request(
        self, *, download_id: str, tenant_id: str
    ) -> DocumentAnalysis:
        """Create (or re-enqueue) the analysis job for an APPROVED download."""
        if not self._enabled:
            raise DownloadSecurityError(
                ANALYSIS_DISABLED,
                "Document analysis is disabled by configuration.",
                http_status=409,
            )

        record = await self._downloads.get(
            download_id=download_id, tenant_id=tenant_id
        )
        if record.state != DownloadState.APPROVED:
            raise DownloadSecurityError(
                INVALID_STATE,
                f"Only APPROVED downloads can be analyzed. "
                f"Current state: {record.state.value}.",
                http_status=409,
            )

        job, created = await self._analyses.create_or_get(
            job_id=str(uuid.uuid4()),
            download_id=record.id,
            tenant_id=record.tenant_id,
            provider=self.provider_name,
            correlation_id=str(uuid.uuid4()),
        )
        if created:
            logger.info(
                "analysis_job_created",
                extra={"download_id": record.id, "tenant_id": record.tenant_id},
            )
        if created or job.state is AnalysisState.PENDING:
            self._enqueue_job(job.id)
        return job

    async def get_job(
        self, *, download_id: str, tenant_id: str
    ) -> DocumentAnalysis:
        return await self._analyses.get(
            download_id=download_id, tenant_id=tenant_id
        )

    async def get_job_optional(
        self, *, download_id: str, tenant_id: str
    ) -> DocumentAnalysis | None:
        return await self._analyses.get_optional(
            download_id=download_id, tenant_id=tenant_id
        )

    async def retry(self, *, download_id: str, tenant_id: str) -> DocumentAnalysis:
        """Re-enqueue a FAILED job that is retryable and still has attempts left."""
        if not self._enabled:
            raise DownloadSecurityError(
                ANALYSIS_DISABLED,
                "Document analysis is disabled by configuration.",
                http_status=409,
            )
        job = await self._analyses.get(
            download_id=download_id, tenant_id=tenant_id
        )
        if job.state is not AnalysisState.FAILED:
            raise DownloadSecurityError(
                INVALID_STATE,
                f"Only FAILED analyses can be retried. "
                f"Current state: {job.state.value}.",
                http_status=409,
            )
        if not job.retryable:
            raise DownloadSecurityError(
                ANALYSIS_NOT_RETRYABLE,
                "This failure is not retryable; re-analyze only after the "
                "document or provider configuration changes.",
                http_status=409,
            )
        if job.attempts >= self._max_attempts:
            raise DownloadSecurityError(
                ANALYSIS_NOT_RETRYABLE,
                f"The analysis attempt limit ({self._max_attempts}) has been "
                "reached.",
                http_status=409,
            )
        job = await self._analyses.reset_to_pending(job.id)
        self._enqueue_job(job.id)
        return job

    async def recover(self) -> int:
        """
        Re-enqueue persisted work after a restart.

        RUNNING jobs are reset to PENDING: their worker died, so no one is
        executing them.  (This assumes a single writer instance, which matches
        the SQLite deployment model.)
        """
        jobs = await self._analyses.list_recoverable()
        for job in jobs:
            if job.state is AnalysisState.RUNNING:
                job = await self._analyses.reset_to_pending(job.id)
            self._enqueue_job(job.id)
        if jobs:
            logger.info("analysis_jobs_recovered", extra={"count": len(jobs)})
        return len(jobs)

    # ── Worker entry point ───────────────────────────────────────────────────

    async def run_job(self, job_id: str) -> DocumentAnalysis | None:
        job = await self._analyses.get_by_id(job_id)
        lock = self._enter_lock(job.download_id)
        try:
            async with lock:
                job = await self._analyses.get_by_id(job_id)
                if job.state is not AnalysisState.PENDING:
                    return job
                job = await self._analyses.mark_running(job.id)
                try:
                    async with asyncio.timeout(self._job_timeout):
                        return await self._execute(job)
                except TimeoutError:
                    return await self._fail(
                        job,
                        ANALYSIS_JOB_TIMEOUT,
                        f"The analysis job exceeded its {self._job_timeout:g}s deadline.",
                        retryable=True,
                    )
                except DocumentProcessingError as exc:
                    return await self._fail(
                        job, exc.code, exc.message, retryable=False
                    )
                except DownloadSecurityError as exc:
                    return await self._fail(
                        job, exc.code, exc.message, retryable=False
                    )
                except HandoffError as exc:
                    return await self._fail(
                        job, exc.code, exc.message, retryable=exc.retriable
                    )
                except asyncio.CancelledError:
                    await self._requeue_after_cancel(job.id)
                    raise
                except Exception as exc:
                    logger.error(
                        "analysis_job_unexpected_error",
                        extra={
                            "download_id": job.download_id,
                            "error_type": type(exc).__name__,
                        },
                    )
                    return await self._fail(
                        job,
                        "ANALYSIS_INTERNAL_ERROR",
                        "An unexpected error occurred during analysis.",
                        retryable=True,
                    )
        finally:
            self._leave_lock(job.download_id)

    # ── Pipeline ─────────────────────────────────────────────────────────────

    async def _execute(self, job: DocumentAnalysis) -> DocumentAnalysis:
        record = await self._downloads.get(
            download_id=job.download_id, tenant_id=job.tenant_id
        )
        if record.state != DownloadState.APPROVED:
            raise DownloadSecurityError(
                INVALID_STATE,
                f"The download left APPROVED state ({record.state.value}) "
                "before analysis.",
                http_status=409,
            )

        verified: VerifiedDocument = await self._handoff.verify(
            download_id=job.download_id, tenant_id=job.tenant_id
        )

        ref = StorageRef.parse(verified.storage_ref)
        path = self._storage.get_approved_path(ref)   # approved-zone-only accessor
        # Check the on-disk size before reading: a too-large approved file
        # must not be pulled into memory only to be rejected.
        size_on_disk = await asyncio.to_thread(lambda: path.stat().st_size)
        if size_on_disk > self._max_payload:
            raise HandoffError(
                "The approved document exceeds the analysis payload limit.",
                code=ANALYSIS_PAYLOAD_TOO_LARGE,
                retriable=False,
            )
        content = await asyncio.to_thread(path.read_bytes)

        if len(content) > self._max_payload:
            raise HandoffError(
                "The approved document exceeds the analysis payload limit.",
                code=ANALYSIS_PAYLOAD_TOO_LARGE,
                retriable=False,
            )
        actual_sha = hashlib.sha256(content).hexdigest()
        if actual_sha != verified.file_sha256:
            raise DownloadSecurityError(
                CHECKSUM_MISMATCH,
                "The approved bytes no longer match the recorded checksum.",
                http_status=500,
            )

        processed = await self._processor.process(content)

        response = await self._handoff.submit(
            verified,
            content=content,
            processed=processed,
            correlation_id=job.correlation_id,
        )

        normalized = build_normalized_result(
            download_id=job.download_id,
            analysis_id=job.id,
            provider=self.provider_name,
            document_type=processed.document_type,
            page_count=processed.page_count,
            extracted_text=processed.text,
            text_truncated=processed.text_truncated,
            sha256=verified.file_sha256,
            response=response,
            local_warnings=processed.warnings,
        )

        completed = await self._analyses.mark_completed(
            job.id,
            result_json=normalized.model_dump_json(),
            provider_analysis_id=response.analysis_id,
        )
        # Only now — after a validated provider response has been stored — is
        # the handoff considered complete.
        await self._handoff.complete(verified)
        logger.info(
            "analysis_completed",
            extra={
                "download_id": job.download_id,
                "tenant_id": job.tenant_id,
                "provider": self.provider_name,
            },
        )
        return completed

    # ── Helpers ──────────────────────────────────────────────────────────────

    async def _fail(
        self,
        job: DocumentAnalysis,
        code: str,
        detail: str,
        *,
        retryable: bool,
    ) -> DocumentAnalysis:
        logger.warning(
            "analysis_job_failed",
            extra={
                "download_id": job.download_id,
                "tenant_id": job.tenant_id,
                "code": code,
                "retryable": retryable,
            },
        )
        return await self._analyses.mark_failed(
            job.id, code=code, detail=detail, retryable=retryable
        )

    async def _requeue_after_cancel(self, job_id: str) -> None:
        """Put an interrupted job back to PENDING, shielded from cancellation."""

        async def _requeue() -> None:
            try:
                current = await self._analyses.get_by_id(job_id)
                if current.state is AnalysisState.RUNNING:
                    await self._analyses.reset_to_pending(
                        job_id, clear_error=True
                    )
            except Exception as exc:
                logger.error(
                    "analysis_cancel_requeue_failed",
                    extra={"error_type": type(exc).__name__},
                )

        recovery = asyncio.create_task(_requeue(), name=f"analysis-requeue-{job_id}")
        try:
            await asyncio.shield(recovery)
        except asyncio.CancelledError:
            # The shielded task keeps running to completion.
            pass

    def _enqueue_job(self, job_id: str) -> None:
        if self._enqueue is None:
            logger.debug("analysis_enqueue_unavailable", extra={"job_id": job_id})
            return
        self._enqueue(job_id)

    def _enter_lock(self, download_id: str) -> asyncio.Lock:
        lock = self._locks.get(download_id)
        if lock is None:
            lock = self._locks[download_id] = asyncio.Lock()
        self._lock_users[download_id] = self._lock_users.get(download_id, 0) + 1
        return lock

    def _leave_lock(self, download_id: str) -> None:
        remaining = self._lock_users.get(download_id, 0) - 1
        if remaining <= 0:
            self._lock_users.pop(download_id, None)
            self._locks.pop(download_id, None)
        else:
            self._lock_users[download_id] = remaining


class AnalysisRunner:
    """
    Fixed-size worker pool over an in-process queue.

    Durable state lives in the database: every job exists as a row before it
    is queued, and recovery re-enqueues PENDING/RUNNING rows at startup.
    """

    def __init__(self, *, service: AnalysisService, concurrency: int = 2) -> None:
        self._service = service
        self._concurrency = concurrency
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._workers: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        self._service.set_enqueue(self.enqueue)
        await self._service.recover()
        for index in range(self._concurrency):
            self._workers.append(
                asyncio.create_task(self._worker(index), name=f"analysis-worker-{index}")
            )

    async def stop(self) -> None:
        for worker in self._workers:
            worker.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    def enqueue(self, job_id: str) -> None:
        self._queue.put_nowait(job_id)

    async def join(self) -> None:
        """Wait until every queued job has been processed (tests/admin use)."""
        await self._queue.join()

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    async def _worker(self, index: int) -> None:
        while True:
            job_id = await self._queue.get()
            try:
                await self._service.run_job(job_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "analysis_worker_error",
                    extra={
                        "worker": index,
                        "job_id": job_id,
                        "error_type": type(exc).__name__,
                    },
                )
            finally:
                self._queue.task_done()
