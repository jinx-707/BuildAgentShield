"""Tests for the durable analysis-job repository."""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.exc import IntegrityError

from models.analysis import AnalysisState, AnalysisStateError, DocumentAnalysis
from models.database import Base, get_async_engine, get_async_session
from models.download import Download  # noqa: F401 - registers the table
from security.errors import NOT_FOUND, DownloadSecurityError
from services.analysis_repository import AnalysisRepository


@pytest.fixture
async def repo(tmp_path):
    engine = get_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'analysis.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield AnalysisRepository(get_async_session(engine))
    await engine.dispose()


async def create_job(repo: AnalysisRepository, *, download_id="dl-1", tenant_id="t1"):
    return await repo.create_or_get(
        job_id=f"job-{download_id}",
        download_id=download_id,
        tenant_id=tenant_id,
        provider="mock",
        correlation_id=f"corr-{download_id}",
    )


class TestCreation:
    async def test_creates_pending_job(self, repo):
        job, created = await create_job(repo)
        assert created is True
        assert job.state is AnalysisState.PENDING
        assert job.attempts == 0
        assert job.download_id == "dl-1"

    async def test_second_request_returns_existing_job(self, repo):
        first, created = await create_job(repo)
        second, created_again = await repo.create_or_get(
            job_id="job-2",
            download_id="dl-1",
            tenant_id="t1",
            provider="mock",
            correlation_id="corr-2",
        )
        assert created is True
        assert created_again is False
        assert second.id == first.id

    async def test_concurrent_creation_yields_one_job(self, repo):
        results = await asyncio.gather(
            repo.create_or_get(
                job_id="job-a",
                download_id="dl-race",
                tenant_id="t1",
                provider="mock",
                correlation_id="c1",
            ),
            repo.create_or_get(
                job_id="job-b",
                download_id="dl-race",
                tenant_id="t1",
                provider="mock",
                correlation_id="c2",
            ),
        )
        ids = {job.id for job, _ in results}
        created_flags = sorted(created for _, created in results)
        assert len(ids) == 1
        assert created_flags == [False, True]

    async def test_cross_tenant_collision_is_not_found(self, repo):
        await create_job(repo, download_id="dl-shared", tenant_id="t1")
        with pytest.raises(DownloadSecurityError) as exc:
            await repo.create_or_get(
                job_id="job-other",
                download_id="dl-shared",
                tenant_id="t2",
                provider="mock",
                correlation_id="c-other",
            )
        assert exc.value.code == NOT_FOUND


class TestTenantScoping:
    async def test_get_other_tenant_is_not_found(self, repo):
        await create_job(repo, tenant_id="t1")
        with pytest.raises(DownloadSecurityError) as exc:
            await repo.get(download_id="dl-1", tenant_id="t2")
        assert exc.value.code == NOT_FOUND

    async def test_get_optional_returns_none_for_other_tenant(self, repo):
        await create_job(repo, tenant_id="t1")
        assert await repo.get_optional(download_id="dl-1", tenant_id="t2") is None
        job = await repo.get_optional(download_id="dl-1", tenant_id="t1")
        assert job is not None

    async def test_get_missing_job_is_not_found(self, repo):
        with pytest.raises(DownloadSecurityError):
            await repo.get(download_id="nope", tenant_id="t1")


class TestTransitions:
    async def test_full_success_path(self, repo):
        job, _ = await create_job(repo)
        running = await repo.mark_running(job.id)
        assert running.state is AnalysisState.RUNNING
        assert running.attempts == 1

        completed = await repo.mark_completed(
            job.id, result_json='{"ok": true}', provider_analysis_id="prov-1"
        )
        assert completed.state is AnalysisState.COMPLETED
        assert completed.result_json == '{"ok": true}'
        assert completed.provider_analysis_id == "prov-1"
        assert completed.completed_at is not None

    async def test_failure_then_retry_resets_error(self, repo):
        job, _ = await create_job(repo)
        await repo.mark_running(job.id)
        failed = await repo.mark_failed(
            job.id, code="ANALYSIS_UNAVAILABLE", detail="down", retryable=True
        )
        assert failed.state is AnalysisState.FAILED
        assert failed.error_code == "ANALYSIS_UNAVAILABLE"
        assert failed.retryable is True

        pending = await repo.reset_to_pending(job.id)
        assert pending.state is AnalysisState.PENDING
        assert pending.error_code is None
        assert pending.error_detail is None
        assert pending.retryable is None

    async def test_invalid_transition_is_rejected(self, repo):
        job, _ = await create_job(repo)
        await repo.mark_running(job.id)
        await repo.mark_completed(
            job.id, result_json="{}", provider_analysis_id="p"
        )
        with pytest.raises(AnalysisStateError):
            await repo.mark_running(job.id)

    async def test_cancel_from_pending(self, repo):
        job, _ = await create_job(repo)
        cancelled = await repo.mark_cancelled(job.id)
        assert cancelled.state is AnalysisState.CANCELLED


class TestRecovery:
    async def test_lists_pending_and_running_only(self, repo):
        pending, _ = await create_job(repo, download_id="dl-pending")
        running, _ = await create_job(repo, download_id="dl-running")
        await repo.mark_running(running.id)
        done, _ = await create_job(repo, download_id="dl-done")
        await repo.mark_running(done.id)
        await repo.mark_completed(done.id, result_json="{}", provider_analysis_id="p")

        recoverable = await repo.list_recoverable()
        ids = {job.id for job in recoverable}
        assert pending.id in ids
        assert running.id in ids
        assert done.id not in ids

    async def test_running_job_can_be_reset_for_recovery(self, repo):
        job, _ = await create_job(repo)
        await repo.mark_running(job.id)
        recovered = await repo.reset_to_pending(job.id)
        assert recovered.state is AnalysisState.PENDING
        assert recovered.attempts == 1
