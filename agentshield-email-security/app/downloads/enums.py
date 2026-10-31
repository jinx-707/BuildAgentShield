"""Download lifecycle states, storage zones, and explicit transition rules.

Invalid transitions are rejected. A successful download is not an approval.
Quarantined files cannot be promoted to approved storage.
"""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet, Mapping

from app.downloads.exceptions import InvalidStateTransitionError, StatusZoneConstraintError


class DownloadStatus(str, Enum):
    PENDING = "pending"
    VALIDATING = "validating"
    DOWNLOADING = "downloading"
    DOWNLOADED = "downloaded"
    SCANNING = "scanning"
    APPROVED = "approved"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"
    FAILED = "failed"
    EXPIRED = "expired"


class StorageZone(str, Enum):
    NONE = "none"
    TEMP = "temp"
    QUARANTINE = "quarantine"
    APPROVED = "approved"


class HandoffStatus(str, Enum):
    NONE = "none"
    COMPLETED = "completed"
    REJECTED = "rejected"


class PolicyDecision(str, Enum):
    DENY = "DENY"
    ALLOW = "ALLOW"


TERMINAL_STATUSES: FrozenSet[DownloadStatus] = frozenset(
    {
        DownloadStatus.QUARANTINED,
        DownloadStatus.APPROVED,
        DownloadStatus.REJECTED,
        DownloadStatus.FAILED,
        DownloadStatus.EXPIRED,
    }
)

# Explicit allow-list. Anything not listed is denied.
ALLOWED_TRANSITIONS: Mapping[DownloadStatus, FrozenSet[DownloadStatus]] = {
    DownloadStatus.PENDING: frozenset(
        {
            DownloadStatus.VALIDATING,
            DownloadStatus.REJECTED,
            DownloadStatus.FAILED,
            DownloadStatus.EXPIRED,
        }
    ),
    DownloadStatus.VALIDATING: frozenset(
        {
            DownloadStatus.DOWNLOADING,
            DownloadStatus.REJECTED,
            DownloadStatus.FAILED,
            DownloadStatus.EXPIRED,
        }
    ),
    DownloadStatus.DOWNLOADING: frozenset(
        {
            DownloadStatus.DOWNLOADED,
            DownloadStatus.REJECTED,
            DownloadStatus.FAILED,
            DownloadStatus.EXPIRED,
        }
    ),
    DownloadStatus.DOWNLOADED: frozenset(
        {
            DownloadStatus.SCANNING,
            DownloadStatus.QUARANTINED,
            DownloadStatus.REJECTED,
            DownloadStatus.FAILED,
            DownloadStatus.EXPIRED,
        }
    ),
    DownloadStatus.SCANNING: frozenset(
        {
            DownloadStatus.QUARANTINED,
            DownloadStatus.APPROVED,
            DownloadStatus.REJECTED,
            DownloadStatus.FAILED,
            DownloadStatus.EXPIRED,
        }
    ),
    # Quarantine is sticky: no release to approved.
    DownloadStatus.QUARANTINED: frozenset(
        {
            DownloadStatus.REJECTED,
            DownloadStatus.EXPIRED,
        }
    ),
    DownloadStatus.APPROVED: frozenset({DownloadStatus.EXPIRED}),
    DownloadStatus.REJECTED: frozenset(),
    DownloadStatus.FAILED: frozenset(),
    DownloadStatus.EXPIRED: frozenset(),
}

# Filesystem zone moves. Approved is never a source of further promotion.
# TEMP -> APPROVED is allowed only through promote_to_approved (scan path).
ALLOWED_ZONE_MOVES: Mapping[StorageZone, FrozenSet[StorageZone]] = {
    StorageZone.NONE: frozenset({StorageZone.TEMP}),
    StorageZone.TEMP: frozenset({StorageZone.QUARANTINE, StorageZone.APPROVED}),
    StorageZone.QUARANTINE: frozenset(),
    StorageZone.APPROVED: frozenset(),
}


def parse_status(value: str | DownloadStatus) -> DownloadStatus:
    if isinstance(value, DownloadStatus):
        return value
    try:
        return DownloadStatus(value)
    except ValueError as exc:
        raise InvalidStateTransitionError(f"Unknown download status: {value}") from exc


def parse_zone(value: str | StorageZone) -> StorageZone:
    if isinstance(value, StorageZone):
        return value
    try:
        return StorageZone(value)
    except ValueError as exc:
        raise StatusZoneConstraintError(f"Unknown storage zone: {value}") from exc


def can_transition(current: str | DownloadStatus, target: str | DownloadStatus) -> bool:
    src = parse_status(current)
    dst = parse_status(target)
    if src == dst:
        return True
    return dst in ALLOWED_TRANSITIONS.get(src, frozenset())


def assert_transition(current: str | DownloadStatus, target: str | DownloadStatus) -> None:
    src = parse_status(current)
    dst = parse_status(target)
    if not can_transition(src, dst):
        raise InvalidStateTransitionError(
            f"Invalid download status transition: {src.value} -> {dst.value}"
        )


def assert_status_zone_consistency(
    status: str | DownloadStatus,
    zone: str | StorageZone,
) -> None:
    """Only approved files live in approved storage.

    - approved status <=> approved zone
    - quarantined status => quarantine zone
    - quarantine zone cannot hold approved files
    - approved zone cannot hold any non-approved status
    """
    st = parse_status(status)
    zn = parse_zone(zone)

    if st is DownloadStatus.APPROVED and zn is not StorageZone.APPROVED:
        raise StatusZoneConstraintError(
            "Approved downloads must be stored in the approved zone"
        )
    if zn is StorageZone.APPROVED and st is not DownloadStatus.APPROVED:
        raise StatusZoneConstraintError(
            "Approved storage may only contain approved downloads"
        )
    if st is DownloadStatus.QUARANTINED and zn is not StorageZone.QUARANTINE:
        raise StatusZoneConstraintError(
            "Quarantined downloads must be stored in the quarantine zone"
        )
    if zn is StorageZone.QUARANTINE and st is DownloadStatus.APPROVED:
        raise StatusZoneConstraintError(
            "Quarantine storage must never contain approved downloads"
        )


def zone_allowed_for_status(status: str | DownloadStatus, zone: str | StorageZone) -> bool:
    try:
        assert_status_zone_consistency(status, zone)
        return True
    except (InvalidStateTransitionError, StatusZoneConstraintError):
        return False


def assert_zone_move(source: str | StorageZone, dest: str | StorageZone) -> None:
    src = parse_zone(source)
    dst = parse_zone(dest)
    if src == dst:
        return
    if dst not in ALLOWED_ZONE_MOVES.get(src, frozenset()):
        raise StatusZoneConstraintError(
            f"Invalid storage-zone move: {src.value} -> {dst.value}"
        )
