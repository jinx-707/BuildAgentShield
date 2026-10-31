"""
Download metadata repository (database access layer).

All database operations are tenant-scoped.  Every query that accepts a
download_id also requires a tenant_id to prevent cross-tenant access.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from models.download import Download, DownloadState
from security.errors import NOT_FOUND, PERMISSION_DENIED, DownloadSecurityError

logger = logging.getLogger(__name__)


class DownloadRepository:
    """
    CRUD operations for Download records.

    All methods are tenant-scoped: passing the wrong tenant_id for a given
    download_id returns NOT_FOUND rather than PERMISSION_DENIED to avoid
    leaking the existence of downloads belonging to other tenants.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    async def create(
        self,
        *,
        download_id: str,
        tenant_id: str,
        agent_id: str,
        original_url: str,
    ) -> Download:
        async with self._factory() as session:
            record = Download(
                id=download_id,
                tenant_id=tenant_id,
                agent_id=agent_id,
                original_url=original_url,
                state=DownloadState.PENDING,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info(
                "download_created",
                extra={
                    "download_id": download_id,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                },
            )
            return record

    async def get(self, *, download_id: str, tenant_id: str) -> Download:
        """Fetch a download record, scoped to tenant_id."""
        async with self._factory() as session:
            record = await self._fetch(session, download_id=download_id, tenant_id=tenant_id)
            return record

    async def update_state(
        self,
        *,
        download_id: str,
        tenant_id: str,
        target_state: DownloadState,
        reason: str | None = None,
    ) -> Download:
        async with self._factory() as session:
            record = await self._fetch(session, download_id=download_id, tenant_id=tenant_id)
            record.transition_to(target_state, reason=reason)
            await session.commit()
            await session.refresh(record)
            logger.info(
                "download_state_changed",
                extra={
                    "download_id": download_id,
                    "state": target_state.value,
                    "tenant_id": tenant_id,
                },
            )
            return record

    async def update_file_metadata(
        self,
        *,
        download_id: str,
        tenant_id: str,
        sha256: str,
        file_size: int,
        detected_mime: str,
        original_filename: str | None,
        storage_ref: str,
    ) -> Download:
        async with self._factory() as session:
            record = await self._fetch(session, download_id=download_id, tenant_id=tenant_id)
            record.file_sha256 = sha256
            record.file_size = file_size
            record.detected_mime_type = detected_mime
            record.original_filename = original_filename
            record.storage_ref = storage_ref
            record.updated_at = datetime.now(tz=timezone.utc)
            await session.commit()
            await session.refresh(record)
            return record

    async def update_scan_result(
        self,
        *,
        download_id: str,
        tenant_id: str,
        scan_result: str,
        scan_detail: str | None,
    ) -> Download:
        async with self._factory() as session:
            record = await self._fetch(session, download_id=download_id, tenant_id=tenant_id)
            record.scan_result = scan_result
            record.scan_detail = scan_detail
            record.updated_at = datetime.now(tz=timezone.utc)
            await session.commit()
            await session.refresh(record)
            return record

    async def mark_handoff_completed(
        self, *, download_id: str, tenant_id: str
    ) -> Download:
        async with self._factory() as session:
            record = await self._fetch(session, download_id=download_id, tenant_id=tenant_id)
            record.handoff_completed = True
            record.updated_at = datetime.now(tz=timezone.utc)
            await session.commit()
            await session.refresh(record)
            return record

    async def set_expiry(
        self,
        *,
        download_id: str,
        tenant_id: str,
        expires_at: datetime,
    ) -> Download:
        async with self._factory() as session:
            record = await self._fetch(session, download_id=download_id, tenant_id=tenant_id)
            record.expires_at = expires_at
            record.updated_at = datetime.now(tz=timezone.utc)
            await session.commit()
            await session.refresh(record)
            return record

    async def list_expired(self, *, before: datetime) -> list[Download]:
        """Return all records whose expires_at is set and has passed."""
        async with self._factory() as session:
            stmt = select(Download).where(
                Download.expires_at != None,  # noqa: E711
                Download.expires_at <= before,
                Download.state != DownloadState.EXPIRED,
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def list_active(self) -> list[Download]:
        """Return records in a non-terminal state (startup recovery)."""
        async with self._factory() as session:
            stmt = select(Download).where(
                Download.state.in_(
                    [
                        DownloadState.PENDING,
                        DownloadState.VALIDATING,
                        DownloadState.DOWNLOADING,
                        DownloadState.DOWNLOADED,
                        DownloadState.VERIFYING,
                        DownloadState.SCANNING,
                    ]
                )
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    async def _fetch(
        session: AsyncSession,
        *,
        download_id: str,
        tenant_id: str,
    ) -> Download:
        stmt = select(Download).where(Download.id == download_id)
        result = await session.execute(stmt)
        record: Download | None = result.scalar_one_or_none()

        if record is None:
            raise DownloadSecurityError(
                NOT_FOUND,
                f"Download {download_id!r} not found.",
                http_status=404,
            )
        # Scope check: return NOT_FOUND (not PERMISSION_DENIED) to avoid
        # leaking the existence of downloads belonging to other tenants.
        if record.tenant_id != tenant_id:
            raise DownloadSecurityError(
                NOT_FOUND,
                f"Download {download_id!r} not found.",
                http_status=404,
            )
        return record
