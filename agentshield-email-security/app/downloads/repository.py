"""Tenant-scoped persistence for secure downloads.

Every read and mutation requires tenant_id (and agent_id). Cross-tenant
lookups return None rather than leaking records.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlsplit

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.downloads.config import DownloadSettings, get_download_settings
from app.downloads.enums import DownloadStatus, HandoffStatus, PolicyDecision, StorageZone
from app.downloads.exceptions import TenantIsolationError
from app.downloads.models import SecureDownload, redact_url_credentials


class SecureDownloadRepository:
    def __init__(
        self,
        session: AsyncSession,
        settings: Optional[DownloadSettings] = None,
    ):
        self.session = session
        self.settings = settings or get_download_settings()

    async def create(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        original_url: str,
        original_filename: Optional[str] = None,
        expected_type: Optional[str] = None,
    ) -> SecureDownload:
        tenant_id = _require_scope(tenant_id, "tenant_id")
        agent_id = _require_scope(agent_id, "agent_id")
        stored_url = redact_url_credentials(original_url)
        hostname = urlsplit(stored_url).hostname or ""
        if not hostname:
            hostname = "unknown"
        expires = datetime.now(timezone.utc) + timedelta(
            hours=self.settings.DOWNLOAD_EXPIRATION_HOURS
        )
        record = SecureDownload(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            agent_id=agent_id,
            original_url=stored_url,
            source_hostname=hostname,
            status=DownloadStatus.PENDING.value,
            storage_zone=StorageZone.NONE.value,
            original_filename=original_filename,
            expected_type=expected_type,
            findings_json={},
            policy_decision=PolicyDecision.DENY.value,
            handoff_status=HandoffStatus.NONE.value,
            expires_at=expires,
        )
        self.session.add(record)
        await self.session.flush()
        return record

    async def get(
        self,
        download_id: uuid.UUID,
        tenant_id: str,
        agent_id: str,
    ) -> Optional[SecureDownload]:
        tenant_id = _require_scope(tenant_id, "tenant_id")
        agent_id = _require_scope(agent_id, "agent_id")
        stmt = select(SecureDownload).where(
            and_(
                SecureDownload.id == download_id,
                SecureDownload.tenant_id == tenant_id,
                SecureDownload.agent_id == agent_id,
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_for_tenant(
        self,
        download_id: uuid.UUID,
        tenant_id: str,
    ) -> Optional[SecureDownload]:
        """Tenant-wide fetch still refuses cross-tenant ids."""
        tenant_id = _require_scope(tenant_id, "tenant_id")
        stmt = select(SecureDownload).where(
            and_(
                SecureDownload.id == download_id,
                SecureDownload.tenant_id == tenant_id,
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()


def _require_scope(value: str, name: str) -> str:
    if not value or not str(value).strip():
        raise TenantIsolationError(f"{name} is required")
    return str(value).strip()
