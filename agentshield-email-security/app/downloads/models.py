"""SQLAlchemy download model.

Never stores file contents, OAuth credentials, or raw filesystem paths.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.sqlite import JSON as SQLITE_JSON
from sqlalchemy.orm import Mapped, mapped_column, validates
from sqlalchemy.types import JSON

from app.database.models import Base, utcnow
from app.downloads.enums import (
    DownloadStatus,
    HandoffStatus,
    PolicyDecision,
    StorageZone,
    assert_status_zone_consistency,
    assert_transition,
)
from app.downloads.exceptions import InvalidStateTransitionError
from app.downloads.storage import sanitize_filename


def _json_type():
    return JSON().with_variant(SQLITE_JSON(), "sqlite")


def redact_url_credentials(url: str) -> str:
    """Persist the original URL without userinfo credentials."""
    if not url or not str(url).strip():
        raise InvalidStateTransitionError("original_url is required")
    raw = str(url).strip()
    parts = urlsplit(raw)
    hostname = parts.hostname or ""
    if not hostname:
        return raw
    netloc = hostname
    if parts.port:
        netloc = f"{hostname}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


class SecureDownload(Base):
    """Persisted download lifecycle, scan outcome, and opaque storage reference."""

    __tablename__ = "secure_downloads"
    __table_args__ = (
        CheckConstraint(
            "status IN ("
            "'pending','validating','downloading','downloaded',"
            "'scanning','quarantined','approved',"
            "'rejected','failed','expired'"
            ")",
            name="ck_secure_downloads_status",
        ),
        CheckConstraint(
            "storage_zone IN ('none','temp','quarantine','approved')",
            name="ck_secure_downloads_storage_zone",
        ),
        CheckConstraint(
            "status != 'approved' OR storage_zone = 'approved'",
            name="ck_secure_downloads_approved_status_zone",
        ),
        CheckConstraint(
            "storage_zone != 'approved' OR status = 'approved'",
            name="ck_secure_downloads_approved_zone_status",
        ),
        CheckConstraint(
            "status != 'quarantined' OR storage_zone = 'quarantine'",
            name="ck_secure_downloads_quarantined_status_zone",
        ),
        CheckConstraint(
            "storage_zone != 'quarantine' OR status != 'approved'",
            name="ck_secure_downloads_quarantine_not_approved",
        ),
        CheckConstraint(
            "policy_decision IN ('DENY','ALLOW')",
            name="ck_secure_downloads_policy_decision",
        ),
        CheckConstraint(
            "handoff_status IN ('none','completed','rejected')",
            name="ck_secure_downloads_handoff_status",
        ),
        CheckConstraint(
            "handoff_status != 'completed' OR status = 'approved'",
            name="ck_secure_downloads_handoff_approved_only",
        ),
        CheckConstraint(
            "sha256 IS NULL OR length(sha256) = 64",
            name="ck_secure_downloads_sha256_len",
        ),
        UniqueConstraint("storage_ref", name="uq_secure_downloads_storage_ref"),
        Index("ix_secure_downloads_tenant_id", "tenant_id"),
        Index("ix_secure_downloads_agent_id", "agent_id"),
        Index("ix_secure_downloads_status", "status"),
        Index("ix_secure_downloads_sha256", "sha256"),
        Index("ix_secure_downloads_created_at", "created_at"),
        Index("ix_secure_downloads_expires_at", "expires_at"),
        Index("ix_secure_downloads_tenant_agent", "tenant_id", "agent_id"),
        Index("ix_secure_downloads_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)

    original_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    source_hostname: Mapped[str] = mapped_column(String(255), nullable=False)

    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=DownloadStatus.PENDING.value
    )
    storage_zone: Mapped[str] = mapped_column(
        String(32), nullable=False, default=StorageZone.NONE.value
    )
    storage_ref: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    expected_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    detected_mime: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    original_filename: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    redirect_count: Mapped[int] = mapped_column(default=0, nullable=False)

    scan_verdict: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scanner_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    threat_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    scan_in_progress: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    findings_json: Mapped[Dict[str, Any]] = mapped_column(
        _json_type(), nullable=False, default=dict
    )
    policy_decision: Mapped[str] = mapped_column(
        String(16), nullable=False, default=PolicyDecision.DENY.value
    )

    handoff_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=HandoffStatus.NONE.value
    )
    handoff_idempotency_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    failure_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        DownloadStatus(value)
        return value

    @validates("storage_zone")
    def _validate_storage_zone(self, _key: str, value: str) -> str:
        StorageZone(value)
        return value

    @validates("policy_decision")
    def _validate_policy_decision(self, _key: str, value: str) -> str:
        PolicyDecision(value)
        return value

    @validates("handoff_status")
    def _validate_handoff_status(self, _key: str, value: str) -> str:
        HandoffStatus(value)
        return value

    @validates("original_url")
    def _validate_original_url(self, _key: str, value: str) -> str:
        return redact_url_credentials(value)

    @validates("original_filename")
    def _validate_original_filename(self, _key: str, value: Optional[str]) -> Optional[str]:
        return sanitize_filename(value)

    def transition_to(
        self,
        new_status: DownloadStatus | str,
        *,
        storage_zone: StorageZone | str | None = None,
    ) -> None:
        """Apply a lifecycle transition. Approval and quarantine require dedicated methods."""
        target = (
            new_status
            if isinstance(new_status, DownloadStatus)
            else DownloadStatus(new_status)
        )
        assert_transition(self.status, target)
        if target is DownloadStatus.APPROVED:
            raise InvalidStateTransitionError(
                "Use mark_approved() to move a file into approved storage"
            )
        if target is DownloadStatus.QUARANTINED:
            raise InvalidStateTransitionError(
                "Use mark_quarantined() to move a file into quarantine storage"
            )
        next_zone = self.storage_zone if storage_zone is None else (
            storage_zone.value if isinstance(storage_zone, StorageZone) else storage_zone
        )
        assert_status_zone_consistency(target, next_zone)
        self.policy_decision = PolicyDecision.DENY.value
        self.status = target.value
        self.storage_zone = next_zone if isinstance(next_zone, str) else next_zone
        self.updated_at = datetime.now(timezone.utc)

    def mark_downloaded(self, storage_ref: str) -> None:
        """Record that bytes landed in temp. This is not approval."""
        assert_transition(self.status, DownloadStatus.DOWNLOADED)
        if not storage_ref:
            raise InvalidStateTransitionError("Downloaded files require a storage_ref")
        assert_status_zone_consistency(DownloadStatus.DOWNLOADED, StorageZone.TEMP)
        self.status = DownloadStatus.DOWNLOADED.value
        self.storage_zone = StorageZone.TEMP.value
        self.storage_ref = storage_ref
        self.policy_decision = PolicyDecision.DENY.value
        self.updated_at = datetime.now(timezone.utc)

    def mark_approved(self, storage_ref: str) -> None:
        assert_transition(self.status, DownloadStatus.APPROVED)
        assert_status_zone_consistency(DownloadStatus.APPROVED, StorageZone.APPROVED)
        if not storage_ref:
            raise InvalidStateTransitionError("Approved downloads require a storage_ref")
        self.status = DownloadStatus.APPROVED.value
        self.storage_zone = StorageZone.APPROVED.value
        self.storage_ref = storage_ref
        self.policy_decision = PolicyDecision.ALLOW.value
        self.updated_at = datetime.now(timezone.utc)

    def mark_quarantined(self, storage_ref: str, *, reason: str) -> None:
        assert_transition(self.status, DownloadStatus.QUARANTINED)
        assert_status_zone_consistency(DownloadStatus.QUARANTINED, StorageZone.QUARANTINE)
        self.status = DownloadStatus.QUARANTINED.value
        self.storage_zone = StorageZone.QUARANTINE.value
        self.storage_ref = storage_ref
        self.policy_decision = PolicyDecision.DENY.value
        self.failure_reason = reason
        self.updated_at = datetime.now(timezone.utc)

    def assert_eligible_for_handoff(self) -> None:
        if self.status != DownloadStatus.APPROVED.value:
            raise InvalidStateTransitionError(
                "Handoff is allowed only for approved downloads"
            )
        if self.storage_zone != StorageZone.APPROVED.value:
            raise InvalidStateTransitionError(
                "Handoff is allowed only from the approved storage zone"
            )
        if self.policy_decision != PolicyDecision.ALLOW.value:
            raise InvalidStateTransitionError("Handoff requires an ALLOW policy decision")
        if not self.sha256 or not self.storage_ref:
            raise InvalidStateTransitionError("Handoff requires sha256 and storage_ref")
        if self.scan_verdict not in ("CLEAN",):
            raise InvalidStateTransitionError("Handoff requires a CLEAN scan verdict")
