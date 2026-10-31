"""
Download ORM model and lifecycle state machine.

State transitions are explicit and validated here.  Any code that attempts
an invalid transition receives a DownloadStateError rather than silently
corrupting the record.

File contents are NEVER stored in this model or in any database column.
The storage_ref column holds an opaque internal reference (storage zone +
generated filename) that the StorageManager resolves.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.database import Base


class DownloadState(str, enum.Enum):
    PENDING = "PENDING"
    VALIDATING = "VALIDATING"
    DOWNLOADING = "DOWNLOADING"
    DOWNLOADED = "DOWNLOADED"
    VERIFYING = "VERIFYING"
    SCANNING = "SCANNING"
    APPROVED = "APPROVED"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


# Every valid (from_state → to_state) transition.
# Transitions not listed here are forbidden.
_VALID_TRANSITIONS: frozenset[tuple[DownloadState, DownloadState]] = frozenset(
    [
        (DownloadState.PENDING,      DownloadState.VALIDATING),
        (DownloadState.PENDING,      DownloadState.REJECTED),   # URL validation failure
        (DownloadState.VALIDATING,   DownloadState.DOWNLOADING),
        (DownloadState.VALIDATING,   DownloadState.REJECTED),
        (DownloadState.VALIDATING,   DownloadState.FAILED),
        (DownloadState.DOWNLOADING,  DownloadState.DOWNLOADED),
        (DownloadState.DOWNLOADING,  DownloadState.FAILED),
        (DownloadState.DOWNLOADING,  DownloadState.REJECTED),   # size limit exceeded
        (DownloadState.DOWNLOADED,   DownloadState.VERIFYING),
        (DownloadState.DOWNLOADED,   DownloadState.FAILED),
        (DownloadState.VERIFYING,    DownloadState.SCANNING),
        (DownloadState.VERIFYING,    DownloadState.REJECTED),   # MIME / magic mismatch
        (DownloadState.VERIFYING,    DownloadState.FAILED),
        (DownloadState.SCANNING,     DownloadState.APPROVED),
        (DownloadState.SCANNING,     DownloadState.QUARANTINED),
        (DownloadState.SCANNING,     DownloadState.FAILED),
        # Terminal states may transition to EXPIRED (TTL cleanup)
        (DownloadState.APPROVED,     DownloadState.EXPIRED),
        (DownloadState.QUARANTINED,  DownloadState.EXPIRED),
        (DownloadState.REJECTED,     DownloadState.EXPIRED),
        (DownloadState.FAILED,       DownloadState.EXPIRED),
    ]
)


class DownloadStateError(Exception):
    """Raised when an invalid state transition is attempted."""

    def __init__(self, current: DownloadState, requested: DownloadState) -> None:
        super().__init__(
            f"Invalid transition: {current.value} → {requested.value}"
        )
        self.current = current
        self.requested = requested


def assert_valid_transition(current: DownloadState, target: DownloadState) -> None:
    """Raise DownloadStateError if (current → target) is not a valid transition."""
    if (current, target) not in _VALID_TRANSITIONS:
        raise DownloadStateError(current, target)


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class Download(Base):
    """
    Persists download metadata for the entire lifecycle of one download job.

    Invariants:
    - file_sha256 is set once (at DOWNLOADED state) and never modified.
    - storage_ref is set when the file moves to approved storage and cleared
      on expiry.
    - scan_result is set when scanning completes; "unknown" is treated as
      QUARANTINED (never APPROVED).
    - The file_size column reflects the actual streamed byte count, not the
      Content-Length header.
    - Columns holding optional text are nullable; missing values are None,
      not empty strings, so callers can distinguish "not yet known" from "empty".
    """

    __tablename__ = "downloads"

    # ── Identity ─────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    # ── URL ───────────────────────────────────────────────────────────────
    original_url: Mapped[str] = mapped_column(Text, nullable=False)

    # ── Lifecycle ─────────────────────────────────────────────────────────
    state: Mapped[DownloadState] = mapped_column(
        Enum(DownloadState, name="download_state"),
        nullable=False,
        default=DownloadState.PENDING,
        index=True,
    )

    # ── File metadata (populated as the download progresses) ──────────────
    original_filename: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_mime_type: Mapped[str | None] = mapped_column(String(256), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # ── Storage reference (opaque; never a raw filesystem path) ───────────
    storage_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # ── Scan result ───────────────────────────────────────────────────────
    scan_result: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scan_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Rejection / failure reason ────────────────────────────────────────
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Timestamps ────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    # ── Handoff tracking ──────────────────────────────────────────────────
    # Set to True once an APPROVED file has been successfully handed off to
    # the document-analysis layer.  Never reset; handoff is idempotent.
    handoff_completed: Mapped[bool] = mapped_column(
        nullable=False, default=False
    )

    def transition_to(self, target: DownloadState, *, reason: str | None = None) -> None:
        """
        Validate and apply a state transition.

        Sets failure_reason when transitioning to a terminal error state.
        Updates updated_at.
        """
        assert_valid_transition(self.state, target)
        self.state = target
        self.updated_at = _utcnow()
        if target in {
            DownloadState.REJECTED,
            DownloadState.FAILED,
            DownloadState.QUARANTINED,
        } and reason:
            self.failure_reason = reason

    def __repr__(self) -> str:
        return (
            f"<Download id={self.id!r} state={self.state.value!r} "
            f"tenant={self.tenant_id!r}>"
        )
