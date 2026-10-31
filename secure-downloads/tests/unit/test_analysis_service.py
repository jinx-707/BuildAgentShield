"""
Lifecycle, concurrency and failure-handling tests for AnalysisService.

Real file-backed SQLite, real storage zones and a real PDF processor are used;
only the provider adapter is substituted.  These tests cover the guarantees the
API relies on: approved-only handoff, one job per download, safe retries,
cancellation, restart recovery, job deadlines and bounded payloads.
"""
from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace

import pytest

from integrations.handoff import DocumentHandoffService, MockDocumentAnalysisAdapter
from models.analysis import AnalysisState, DocumentAnalysis
from models.database import Base, get_async_engine, get_async_session
from models.download import Download, DownloadState
from security.errors import (
    ANALYSIS_DISABLED,
    ANALYSIS_JOB_TIMEOUT,
    ANALYSIS_NOT_RETRYABLE,
    ANALYSIS_PAYLOAD_TOO_LARGE,
    CHECKSUM_MISMATCH,
    HANDOFF_ERROR,
    INVALID_STATE,
    DownloadSecurityError,
)
from services.analysis_repository import AnalysisRepository
from services.analysis_service import AnalysisRunner, AnalysisService
from services.document_processor import PdfDocumentProcessor
from services.repository import DownloadRepository
from storage.manager import StorageManager
from tests.pdf_fixtures import make_pdf


PDF_BYTES = make_pdf(("Approved document text",))
TENANT = "tenant-x"


class Env(SimpleNamespace):
    pass


@pytest.fixture
async def env(tmp_path):
    engine = get_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'service.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = get_async_session(engine)
    storage = StorageManager(str(tmp_path / "storage"))
    storage.initialize()
    adapter = MockDocumentAnalysisAdapter()
    namespace = Env(
        engine=engine,
        session=session_factory,
        storage=storage,
        adapter=adapter,
        downloads=DownloadRepository(session_factory),
        analyses=AnalysisRepository(session_factory),
        tmp_path=tmp_path,
    )
    yield namespace
    await engine.dispose()


def build_service(
    env: Env,
    adapter=None,
    *,
    max_payload: int = 10_485_760,
    job_timeout: float = 5.0,
    max_attempts: int = 3,
    enabled: bool = True,
    processor: PdfDocumentProcessor | None = None,
) -> AnalysisService:
    handoff = DocumentHandoffService(
        adapter=adapter or env.adapter,
        storage_manager=env.storage,
        repository=env.downloads,
    )
    return AnalysisService(
        downloads=env.downloads,
        analyses=env.analyses,
        handoff=handoff,
        processor=processor or PdfDocumentProcessor(),
        storage=env.storage,
        enabled=enabled,
        max_payload_bytes=max_payload,
        job_timeout_seconds=job_timeout,
        max_attempts=max_attempts,
    )


async def seed_download(
    env: Env,
    *,
    download_id: str = "dl-1",
    state: DownloadState = DownloadState.APPROVED,
    data: bytes = PDF_BYTES,
    tenant_id: str = TENANT,
) -> tuple[str, bytes]:
    """Persist a download row and its file in the matching storage zone."""
    path, temp_ref = env.storage.allocate_temp_path()
    path.write_bytes(data)
    if state is DownloadState.QUARANTINED:
        ref = env.storage.move_to_quarantine(temp_ref)
    else:
        ref = env.storage.move_to_approved(temp_ref)

    record = Download(
        id=download_id,
        tenant_id=tenant_id,
        agent_id="agent-1",
        original_url="https://example.com/report.pdf",
        state=state,
        storage_ref=ref.ref_string,
        file_sha256=hashlib.sha256(data).hexdigest(),
        file_size=len(data),
        detected_mime_type="application/pdf",
        handoff_completed=False,
    )
    async with env.session() as session:
        session.add(record)
        await session.commit()
    return ref.ref_string, hashlib.sha256(data).hexdigest()


async def wait_for_state(
    env: Env,
    *,
    download_id: str = "dl-1",
    states: set[AnalysisState],
    timeout: float = 5.0,
) -> DocumentAnalysis:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        job = await env.analyses.get(download_id=download_id, tenant_id=TENANT)
        if job.state in states:
            return job
        await asyncio.sleep(0.02)
    raise AssertionError(f"job did not reach {states}; last state {job.state}")


class BlockingAdapter:
    provider_name = "blocking"

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def analyze(self, document, *, correlation_id):  # noqa: ANN001
        self.entered.set()
        await self.release.wait()
        raise AssertionError("released adapter should not be used")


class FailingAdapter:
    provider_name = "failing"

    def __init__(self, *, retriable: bool = True, code: str = "ANALYSIS_UNAVAILABLE"):
        self.retriable = retriable
        self.code = code
        self.calls = 0

    async def analyze(self, document, *, correlation_id):  # noqa: ANN001
        self.calls += 1
        from integrations.handoff import HandoffError

        raise HandoffError("provider unavailable", code=self.code, retriable=self.retriable)


class FailOnceAdapter:
    provider_name = "fail-once"

    def __init__(self) -> None:
        self.calls = 0

    async def analyze(self, document, *, correlation_id):  # noqa: ANN001
        self.calls += 1
        if self.calls == 1:
            from integrations.handoff import HandoffError

            raise HandoffError("temporary outage", retriable=True)
        from integrations.analysis_models import ProviderAnalysisResponse

        return ProviderAnalysisResponse(
            analysis_id=f"ok-{self.calls}",
            correlation_id=correlation_id,
            status="completed",
        )


class SlowAdapter:
    provider_name = "slow"

    async def analyze(self, document, *, correlation_id):  # noqa: ANN001
        await asyncio.sleep(5)
        raise AssertionError("timeout should fire first")


class TestHappyPath:
    async def test_request_runs_to_completion(self, env):
        await seed_download(env)
        service = build_service(env)
        runner = AnalysisRunner(service=service, concurrency=2)
        await runner.start()
        try:
            job = await service.request(download_id="dl-1", tenant_id=TENANT)
            assert job.state is AnalysisState.PENDING
            await runner.join()
        finally:
            await runner.stop()

        done = await wait_for_state(env, states={AnalysisState.COMPLETED})
        assert done.provider_analysis_id
        assert done.result_json is not None
        assert len(env.adapter.submissions) == 1
        assert env.adapter.submissions[0].content == PDF_BYTES
        assert env.adapter.submissions[0].payload.file_ref.startswith("approved/")

    async def test_duplicate_request_does_not_duplicate_work(self, env):
        await seed_download(env)
        service = build_service(env)
        runner = AnalysisRunner(service=service, concurrency=2)
        await runner.start()
        try:
            first = await service.request(download_id="dl-1", tenant_id=TENANT)
            second = await service.request(download_id="dl-1", tenant_id=TENANT)
            assert first.id == second.id
            await runner.join()
            # A completed job is returned as-is and not re-enqueued.
            third = await service.request(download_id="dl-1", tenant_id=TENANT)
            assert third.id == first.id
            await asyncio.sleep(0.05)
        finally:
            await runner.stop()

        assert len(env.adapter.submissions) == 1

    async def test_concurrent_requests_create_one_job(self, env):
        await seed_download(env)
        service = build_service(env)
        jobs = await asyncio.gather(
            service.request(download_id="dl-1", tenant_id=TENANT),
            service.request(download_id="dl-1", tenant_id=TENANT),
        )
        assert jobs[0].id == jobs[1].id

    async def test_concurrent_execution_of_same_job_runs_once(self, env):
        await seed_download(env)
        service = build_service(env)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)

        await asyncio.gather(service.run_job(job.id), service.run_job(job.id))

        done = await wait_for_state(env, states={AnalysisState.COMPLETED})
        assert done.attempts == 1
        assert len(env.adapter.submissions) == 1


class TestApprovedOnlyGate:
    async def test_quarantined_download_cannot_be_analyzed(self, env):
        await seed_download(env, state=DownloadState.QUARANTINED)
        service = build_service(env)

        with pytest.raises(DownloadSecurityError) as exc:
            await service.request(download_id="dl-1", tenant_id=TENANT)
        assert exc.value.code == INVALID_STATE
        assert env.adapter.submissions == []

    async def test_missing_approved_file_fails_the_job(self, env):
        ref_string, _ = await seed_download(env)
        from storage.manager import StorageRef

        env.storage.delete(StorageRef.parse(ref_string))
        service = build_service(env)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)

        result = await service.run_job(job.id)

        assert result.state is AnalysisState.FAILED
        assert result.error_code == HANDOFF_ERROR
        assert result.retryable is False
        assert env.adapter.submissions == []

    async def test_tampered_bytes_fail_checksum(self, env, monkeypatch, tmp_path):
        _, recorded_sha = await seed_download(env)
        tampered = tmp_path / "tampered.pdf"
        tampered.write_bytes(make_pdf(("tampered",)))

        # Verify() still hashes the real approved file; the execution path
        # reads through the accessor, which now returns different bytes.
        monkeypatch.setattr(env.storage, "get_approved_path", lambda ref: tampered)
        service = build_service(env)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)

        result = await service.run_job(job.id)

        assert result.state is AnalysisState.FAILED
        assert result.error_code == CHECKSUM_MISMATCH
        assert recorded_sha != hashlib.sha256(tampered.read_bytes()).hexdigest()
        assert env.adapter.submissions == []

    async def test_disabled_analysis_refuses_requests(self, env):
        await seed_download(env)
        service = build_service(env, enabled=False)
        with pytest.raises(DownloadSecurityError) as exc:
            await service.request(download_id="dl-1", tenant_id=TENANT)
        assert exc.value.code == ANALYSIS_DISABLED


class TestRetriesAndFailures:
    async def test_retriable_failure_then_retry_succeeds(self, env):
        await seed_download(env)
        adapter = FailOnceAdapter()
        service = build_service(env, adapter=adapter)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)

        failed = await service.run_job(job.id)
        assert failed.state is AnalysisState.FAILED
        assert failed.retryable is True

        retried = await service.retry(download_id="dl-1", tenant_id=TENANT)
        assert retried.state is AnalysisState.PENDING

        completed = await service.run_job(retried.id)
        assert completed.state is AnalysisState.COMPLETED
        assert completed.attempts == 2
        assert adapter.calls == 2

    async def test_non_retriable_failure_cannot_be_retried(self, env):
        await seed_download(env)
        service = build_service(env, adapter=FailingAdapter(retriable=False))
        job = await service.request(download_id="dl-1", tenant_id=TENANT)
        await service.run_job(job.id)

        with pytest.raises(DownloadSecurityError) as exc:
            await service.retry(download_id="dl-1", tenant_id=TENANT)
        assert exc.value.code == ANALYSIS_NOT_RETRYABLE

    async def test_attempt_limit_blocks_retry(self, env):
        await seed_download(env)
        adapter = FailingAdapter(retriable=True)
        service = build_service(env, adapter=adapter, max_attempts=1)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)
        await service.run_job(job.id)

        with pytest.raises(DownloadSecurityError) as exc:
            await service.retry(download_id="dl-1", tenant_id=TENANT)
        assert exc.value.code == ANALYSIS_NOT_RETRYABLE

    async def test_retry_requires_failed_state(self, env):
        await seed_download(env)
        service = build_service(env)
        await service.request(download_id="dl-1", tenant_id=TENANT)
        with pytest.raises(DownloadSecurityError) as exc:
            await service.retry(download_id="dl-1", tenant_id=TENANT)
        assert exc.value.code == INVALID_STATE

    async def test_job_timeout_marks_failed(self, env):
        await seed_download(env)
        service = build_service(env, adapter=SlowAdapter(), job_timeout=0.05)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)

        result = await service.run_job(job.id)

        assert result.state is AnalysisState.FAILED
        assert result.error_code == ANALYSIS_JOB_TIMEOUT
        assert result.retryable is True

    async def test_payload_limit_marks_failed_before_provider(self, env):
        await seed_download(env)
        service = build_service(env, max_payload=32)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)

        result = await service.run_job(job.id)

        assert result.state is AnalysisState.FAILED
        assert result.error_code == ANALYSIS_PAYLOAD_TOO_LARGE
        assert result.retryable is False
        assert env.adapter.submissions == []

    async def test_failure_detail_contains_no_document_content(self, env):
        await seed_download(env)
        service = build_service(env, adapter=FailingAdapter())
        job = await service.request(download_id="dl-1", tenant_id=TENANT)
        failed = await service.run_job(job.id)

        assert "Approved document text" not in (failed.error_detail or "")


class TestCancellation:
    async def test_cancelled_job_is_requeued(self, env):
        await seed_download(env)
        adapter = BlockingAdapter()
        service = build_service(env, adapter=adapter)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)

        task = asyncio.create_task(service.run_job(job.id))
        await asyncio.wait_for(adapter.entered.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        requeued = await wait_for_state(env, states={AnalysisState.PENDING})
        assert requeued.error_code is None
        adapter.release.set()


class TestRestartRecovery:
    async def test_pending_job_is_recovered_on_start(self, env):
        await seed_download(env)
        service = build_service(env)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)
        assert job.state is AnalysisState.PENDING  # no enqueue target yet

        runner = AnalysisRunner(service=service, concurrency=1)
        await runner.start()  # recover() enqueues the persisted job
        try:
            await runner.join()
        finally:
            await runner.stop()

        done = await wait_for_state(env, states={AnalysisState.COMPLETED})
        assert done.id == job.id

    async def test_running_job_is_reset_and_recovered(self, env):
        await seed_download(env)
        service = build_service(env)
        job = await service.request(download_id="dl-1", tenant_id=TENANT)
        # Simulate a worker that died after claiming the job.
        await env.analyses.mark_running(job.id)

        runner = AnalysisRunner(service=service, concurrency=1)
        await runner.start()
        try:
            await runner.join()
        finally:
            await runner.stop()

        done = await wait_for_state(env, states={AnalysisState.COMPLETED})
        assert done.id == job.id
