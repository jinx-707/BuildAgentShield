"""Lifecycle transition and status/zone constraint tests."""

import pytest

from app.downloads.enums import (
    DownloadStatus,
    StorageZone,
    assert_status_zone_consistency,
    assert_transition,
    assert_zone_move,
    can_transition,
    zone_allowed_for_status,
)
from app.downloads.exceptions import InvalidStateTransitionError, StatusZoneConstraintError


class TestLifecycleTransitions:
    def test_all_required_states_exist(self):
        names = {s.name for s in DownloadStatus}
        assert names == {
            "PENDING",
            "VALIDATING",
            "DOWNLOADING",
            "DOWNLOADED",
            "SCANNING",
            "APPROVED",
            "QUARANTINED",
            "REJECTED",
            "FAILED",
            "EXPIRED",
        }

    def test_happy_path_to_scanning(self):
        path = [
            DownloadStatus.PENDING,
            DownloadStatus.VALIDATING,
            DownloadStatus.DOWNLOADING,
            DownloadStatus.DOWNLOADED,
            DownloadStatus.SCANNING,
        ]
        for src, dst in zip(path, path[1:]):
            assert can_transition(src, dst)
            assert_transition(src, dst)

    def test_scanning_may_approve_or_quarantine(self):
        assert can_transition(DownloadStatus.SCANNING, DownloadStatus.APPROVED)
        assert can_transition(DownloadStatus.SCANNING, DownloadStatus.QUARANTINED)
        assert can_transition(DownloadStatus.SCANNING, DownloadStatus.FAILED)

    def test_quarantine_cannot_become_approved(self):
        assert not can_transition(DownloadStatus.QUARANTINED, DownloadStatus.APPROVED)
        with pytest.raises(InvalidStateTransitionError):
            assert_transition(DownloadStatus.QUARANTINED, DownloadStatus.APPROVED)

    def test_downloaded_is_not_approved(self):
        assert not can_transition(DownloadStatus.DOWNLOADED, DownloadStatus.APPROVED)
        with pytest.raises(InvalidStateTransitionError):
            assert_transition(DownloadStatus.DOWNLOADED, DownloadStatus.APPROVED)

    def test_pending_cannot_skip_to_approved(self):
        with pytest.raises(InvalidStateTransitionError):
            assert_transition(DownloadStatus.PENDING, DownloadStatus.APPROVED)

    def test_rejected_and_failed_are_terminal(self):
        for terminal in (DownloadStatus.REJECTED, DownloadStatus.FAILED, DownloadStatus.EXPIRED):
            for target in DownloadStatus:
                if target is terminal:
                    assert can_transition(terminal, target)
                else:
                    assert not can_transition(terminal, target)

    def test_unknown_status_rejected(self):
        with pytest.raises(InvalidStateTransitionError):
            can_transition("pending", "totally-invalid")


class TestStatusZoneConstraints:
    def test_approved_requires_approved_zone(self):
        with pytest.raises(StatusZoneConstraintError):
            assert_status_zone_consistency(DownloadStatus.APPROVED, StorageZone.TEMP)
        with pytest.raises(StatusZoneConstraintError):
            assert_status_zone_consistency(DownloadStatus.APPROVED, StorageZone.QUARANTINE)
        assert_status_zone_consistency(DownloadStatus.APPROVED, StorageZone.APPROVED)

    def test_approved_zone_rejects_other_statuses(self):
        for status in (
            DownloadStatus.PENDING,
            DownloadStatus.DOWNLOADED,
            DownloadStatus.SCANNING,
            DownloadStatus.QUARANTINED,
            DownloadStatus.FAILED,
        ):
            with pytest.raises(StatusZoneConstraintError):
                assert_status_zone_consistency(status, StorageZone.APPROVED)

    def test_quarantined_requires_quarantine_zone(self):
        with pytest.raises(StatusZoneConstraintError):
            assert_status_zone_consistency(DownloadStatus.QUARANTINED, StorageZone.TEMP)
        assert_status_zone_consistency(DownloadStatus.QUARANTINED, StorageZone.QUARANTINE)

    def test_temp_zone_cannot_be_approved(self):
        assert zone_allowed_for_status(DownloadStatus.DOWNLOADING, StorageZone.TEMP)
        assert zone_allowed_for_status(DownloadStatus.DOWNLOADED, StorageZone.TEMP)
        assert not zone_allowed_for_status(DownloadStatus.APPROVED, StorageZone.TEMP)
        assert not zone_allowed_for_status(DownloadStatus.APPROVED, StorageZone.QUARANTINE)

    def test_quarantine_cannot_move_to_approved_zone(self):
        with pytest.raises(StatusZoneConstraintError):
            assert_zone_move(StorageZone.QUARANTINE, StorageZone.APPROVED)
