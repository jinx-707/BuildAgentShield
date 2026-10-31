"""
Persistence for document-analysis jobs.

Every query that serves an API caller is tenant-scoped and returns NOT_FOUND
(not PERMISSION_DENIED) for another tenant's job, matching the download
repository's behaviour.  Worker-side lookups use get_by_id() because the job
already carries the tenant that created it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from models.analysis import AnalysisState, DocumentAnalysis
from security.errors import NOT_FOUND, DownloadSecurityError

logger = logging.getLogger(__name__)


class AnalysisRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    # ── Creation ─────────────────────────────────────────────────────────────

    async def create_or_get(
        self,
        *,
        job_id: str,
        download_id: str,
        tenant_id: str,
        provider: str,
        correlation_id: str,
    ) -> tuple[DocumentAnalysis, bool]:
        """
        Create the job for a download, or return the existing one.

        The UNIQUE(download_id) index makes this safe under concurrent
        requests: the loser of the insert race re-reads the winner's row.
        """
        async with self._factory() as session:
            record = DocumentAnalysis(
                id=job_id,
                download_id=download_id,
                tenant_id=tenant_id,
                provider=provider,
                correlation_id=correlation_id,
                state=AnalysisState.PENDING,
            )
            session.add(record)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                existing = await self._fetch_by_download(
                    session, download_id=download_id
                )
                if existing is None:
                    raise
                if existing.tenant_id != tenant_id:
                    # The unique constraint is global to the download; a
                    # cross-tenant collision must not leak the row.
                    raise DownloadSecurityError(
                        NOT_FOUND, "Download not found.", http_status=404
                    )
                return existing, False
            await session.refresh(record)
            return record, True

    # ── Reads ────────────────────────────────────────────────────────────────

    async def get(
        self, *, download_id: str, tenant_id: str
    ) -> DocumentAnalysis:
        async with self._factory() as session:
            record = await self._fetch_by_download(session, download_id=download_id)
            self._check_tenant(record, download_id=download_id, tenant_id=tenant_id)
            return record

    async def get_optional(
        self, *, download_id: str, tenant_id: str
    ) -> DocumentAnalysis | None:
        async with self._factory() as session:
            record = await self._fetch_by_download(session, download_id=download_id)
            if record is None or record.tenant_id != tenant_id:
                return None
            return record

    async def get_by_id(self, job_id: str) -> DocumentAnalysis:
        async with self._factory() as session:
            record = await session.get(DocumentAnalysis, job_id)
            if record is None:
                raise DownloadSecurityError(
                    NOT_FOUND, "Analysis job not found.", http_status=404
                )
            return record

    async def list_recoverable(self) -> list[DocumentAnalysis]:
        """Jobs a restarted worker should pick up (PENDING or RUNNING)."""
        async with self._factory() as session:
            stmt = select(DocumentAnalysis).where(
                DocumentAnalysis.state.in_(
                    [AnalysisState.PENDING, AnalysisState.RUNNING]
                )
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    # ── Transitions ──────────────────────────────────────────────────────────

    async def mark_running(self, job_id: str) -> DocumentAnalysis:
        async with self._factory() as session:
            record = await self._require(session, job_id)
            record.transition_to(AnalysisState.RUNNING)
            record.attempts += 1
            await session.commit()
            await session.refresh(record)
            return record

    async def mark_completed(
        self,
        job_id: str,
        *,
        result_json: str,
        provider_analysis_id: str,
    ) -> DocumentAnalysis:
        async with self._factory() as session:
            record = await self._require(session, job_id)
            record.transition_to(AnalysisState.COMPLETED)
            record.result_json = result_json
            record.provider_analysis_id = provider_analysis_id
            record.error_code = None
            record.error_detail = None
            record.retryable = None
            record.completed_at = datetime.now(tz=timezone.utc)
            await session.commit()
            await session.refresh(record)
            return record

    async def mark_failed(
        self,
        job_id: str,
        *,
        code: str,
        detail: str,
        retryable: bool,
    ) -> DocumentAnalysis:
        async with self._factory() as session:
            record = await self._require(session, job_id)
            record.transition_to(AnalysisState.FAILED)
            record.error_code = code
            record.error_detail = detail
            record.retryable = retryable
            await session.commit()
            await session.refresh(record)
            return record

    async def reset_to_pending(
        self, job_id: str, *, clear_error: bool = True
    ) -> DocumentAnalysis:
        async with self._factory() as session:
            record = await self._require(session, job_id)
            record.transition_to(AnalysisState.PENDING)
            if clear_error:
                record.error_code = None
                record.error_detail = None
                record.retryable = None
            record.completed_at = None
            await session.commit()
            await session.refresh(record)
            return record

    async def mark_cancelled(self, job_id: str) -> DocumentAnalysis:
        async with self._factory() as session:
            record = await self._require(session, job_id)
            record.transition_to(AnalysisState.CANCELLED)
            await session.commit()
            await session.refresh(record)
            return record

    # ── Internals ────────────────────────────────────────────────────────────

    @staticmethod
    async def _fetch_by_download(
        session: AsyncSession, *, download_id: str
    ) -> DocumentAnalysis | None:
        stmt = select(DocumentAnalysis).where(
            DocumentAnalysis.download_id == download_id
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    def _check_tenant(
        record: DocumentAnalysis | None, *, download_id: str, tenant_id: str
    ) -> None:
        if record is None or record.tenant_id != tenant_id:
            raise DownloadSecurityError(
                NOT_FOUND,
                f"Analysis for download {download_id!r} not found.",
                http_status=404,
            )

    @staticmethod
    async def _require(session: AsyncSession, job_id: str) -> DocumentAnalysis:
        record = await session.get(DocumentAnalysis, job_id)
        if record is None:
            raise DownloadSecurityError(
                NOT_FOUND, "Analysis job not found.", http_status=404
            )
        return record
