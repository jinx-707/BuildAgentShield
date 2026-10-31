"""Tests for storage zone isolation, path traversal protection, and expiry."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from storage.manager import PathTraversalError, StorageManager, StorageRef, StorageZone


@pytest.fixture
def storage(tmp_path):
    sm = StorageManager(str(tmp_path / "secure-storage"))
    sm.initialize()
    return sm


def write_test_file(path: Path, content: bytes = b"test-content") -> None:
    path.write_bytes(content)


class TestZoneInitialization:
    def test_creates_all_zones(self, tmp_path):
        sm = StorageManager(str(tmp_path / "store"))
        sm.initialize()
        for zone in StorageZone:
            assert (tmp_path / "store" / zone.value).is_dir()

    def test_initialize_is_idempotent(self, tmp_path):
        sm = StorageManager(str(tmp_path / "store"))
        sm.initialize()
        sm.initialize()  # Should not raise


class TestZoneTransitions:
    def test_allocate_temp_path(self, storage):
        path, ref = storage.allocate_temp_path()
        assert ref.zone == StorageZone.TEMPORARY
        assert not path.exists()  # Not created yet

    def test_move_to_approved(self, storage):
        path, ref = storage.allocate_temp_path()
        path.write_bytes(b"approved-content")
        approved_ref = storage.move_to_approved(ref)
        assert approved_ref.zone == StorageZone.APPROVED
        assert storage.exists(approved_ref)
        # Original temporary file should be gone
        assert not storage.exists(ref)

    def test_move_to_quarantine(self, storage):
        path, ref = storage.allocate_temp_path()
        path.write_bytes(b"malware-content")
        quarantine_ref = storage.move_to_quarantine(ref)
        assert quarantine_ref.zone == StorageZone.QUARANTINE
        assert storage.exists(quarantine_ref)
        assert not storage.exists(ref)

    def test_cannot_move_approved_to_quarantine(self, storage):
        """Files cannot jump directly from approved to quarantine."""
        path, temp_ref = storage.allocate_temp_path()
        path.write_bytes(b"content")
        approved_ref = storage.move_to_approved(temp_ref)
        with pytest.raises(ValueError, match="TEMPORARY"):
            storage.move_to_quarantine(approved_ref)

    def test_cannot_move_quarantine_to_approved(self, storage):
        """Quarantined files can never become approved through the storage API."""
        path, temp_ref = storage.allocate_temp_path()
        path.write_bytes(b"infected")
        quarantine_ref = storage.move_to_quarantine(temp_ref)
        with pytest.raises(ValueError, match="TEMPORARY"):
            storage.move_to_approved(quarantine_ref)


class TestApprovedAccess:
    def test_get_approved_path_works_for_approved_file(self, storage):
        path, ref = storage.allocate_temp_path()
        path.write_bytes(b"approved")
        approved_ref = storage.move_to_approved(ref)
        result_path = storage.get_approved_path(approved_ref)
        assert result_path.exists()
        assert result_path.read_bytes() == b"approved"

    def test_get_approved_path_denied_for_quarantine(self, storage):
        """Quarantined files cannot be read through the approved-file interface."""
        path, ref = storage.allocate_temp_path()
        path.write_bytes(b"infected")
        quarantine_ref = storage.move_to_quarantine(ref)
        with pytest.raises(ValueError, match="approved"):
            storage.get_approved_path(quarantine_ref)

    def test_get_approved_path_denied_for_temporary(self, storage):
        path, ref = storage.allocate_temp_path()
        path.write_bytes(b"temp")
        with pytest.raises(ValueError, match="approved"):
            storage.get_approved_path(ref)


class TestPathTraversalProtection:
    def test_dotdot_in_filename_blocked(self, storage):
        """Path traversal via .. in filename must be rejected by _resolve_ref."""
        bad_ref = StorageRef(zone=StorageZone.APPROVED, filename="../../../etc/passwd")
        with pytest.raises(PathTraversalError):
            storage._resolve_ref(bad_ref)

    def test_slash_in_filename_blocked(self, storage):
        bad_ref = StorageRef(zone=StorageZone.APPROVED, filename="approved/../../etc/passwd")
        with pytest.raises(PathTraversalError):
            storage._resolve_ref(bad_ref)

    def test_dotdot_exists_returns_false(self, storage):
        """exists() must return False for path-traversal attempts (never raise)."""
        bad_ref = StorageRef(zone=StorageZone.APPROVED, filename="../../../etc/passwd")
        assert storage.exists(bad_ref) is False

    def test_slash_exists_returns_false(self, storage):
        bad_ref = StorageRef(zone=StorageZone.APPROVED, filename="approved/../../etc/passwd")
        assert storage.exists(bad_ref) is False

    def test_ref_parse_invalid_format(self):
        with pytest.raises(ValueError):
            StorageRef.parse("nozone")

    def test_ref_parse_unknown_zone(self):
        with pytest.raises(ValueError, match="Unknown storage zone"):
            StorageRef.parse("badzone/filename")

    def test_ref_parse_valid(self):
        ref = StorageRef.parse("approved/abc123")
        assert ref.zone == StorageZone.APPROVED
        assert ref.filename == "abc123"


class TestSha256Checksum:
    def test_checksum_computed_correctly(self, storage):
        content = b"Hello, World! This is a test file."
        path, ref = storage.allocate_temp_path()
        path.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        actual = storage.compute_sha256(ref)
        assert actual == expected

    def test_approved_file_checksum_stable(self, storage):
        content = b"pdf-content"
        path, temp_ref = storage.allocate_temp_path()
        path.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        approved_ref = storage.move_to_approved(temp_ref)
        assert storage.compute_sha256(approved_ref) == expected


class TestDelete:
    def test_delete_removes_file(self, storage):
        path, ref = storage.allocate_temp_path()
        path.write_bytes(b"to-delete")
        assert path.exists()
        storage.delete(ref)
        assert not path.exists()

    def test_delete_nonexistent_is_noop(self, storage):
        _, ref = storage.allocate_temp_path()
        storage.delete(ref)  # Should not raise

    def test_file_size(self, storage):
        content = b"exactly this content"
        path, ref = storage.allocate_temp_path()
        path.write_bytes(content)
        assert storage.file_size(ref) == len(content)
