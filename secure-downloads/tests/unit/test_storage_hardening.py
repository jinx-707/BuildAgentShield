"""
Storage-manager hardening tests (Prompt 3, Phase 3C).

Complements test_storage_isolation.py with the properties that matter when
the filesystem misbehaves or an attacker influences names: restrictive
permissions, symlink escape, interrupted moves, concurrent allocation, and
cleanup failures that must never crash the caller.
"""
from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

import pytest

from storage.manager import (
    PathTraversalError,
    StorageManager,
    StorageRef,
    StorageZone,
)


@pytest.fixture
def storage(tmp_path):
    sm = StorageManager(str(tmp_path / "secure-storage"))
    sm.initialize()
    return sm


def make_temp_file(storage: StorageManager, content: bytes = b"payload") -> tuple[Path, StorageRef]:
    path, ref = storage.allocate_temp_path()
    path.write_bytes(content)
    return path, ref


class TestPermissions:
    def test_root_and_zone_directories_are_owner_only(self, storage):
        root = storage._root
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        for zone in StorageZone:
            zone_dir = root / zone.value
            assert stat.S_IMODE(zone_dir.stat().st_mode) == 0o700, zone

    def test_move_rewrites_loose_source_mode_to_0600(self, storage):
        path, ref = make_temp_file(storage)
        os.chmod(path, 0o666)
        approved = storage.move_to_approved(ref)
        target = storage.get_approved_path(approved)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_chmod_failure_does_not_lose_the_file(self, storage, monkeypatch):
        path, ref = make_temp_file(storage)
        real_chmod = os.chmod

        def fail_chmod(target, mode, *args, **kwargs):
            if Path(target) == Path(target).parent / ref.filename:
                raise PermissionError("chmod denied")
            return real_chmod(target, mode, *args, **kwargs)

        monkeypatch.setattr(os, "chmod", fail_chmod)
        approved = storage.move_to_approved(ref)
        assert storage.exists(approved)


class TestTraversalAndSymlinks:
    @pytest.mark.parametrize(
        "filename",
        [
            "../escape",
            "../../etc/passwd",
            "approved/../../etc/passwd",
            "/etc/passwd",
            "..\\..\\windows\\system32",
            "subdir/file",
        ],
    )
    def test_traversal_shaped_names_are_rejected(self, storage, filename):
        ref = StorageRef(zone=StorageZone.APPROVED, filename=filename)
        with pytest.raises(PathTraversalError):
            storage.get_approved_path(ref)

    def test_symlink_escaping_the_zone_is_rejected(self, storage, tmp_path):
        outside = tmp_path / "outside-secret.txt"
        outside.write_bytes(b"secret")
        link = storage._root / "approved" / "link-to-outside"
        link.symlink_to(outside)

        ref = StorageRef(zone=StorageZone.APPROVED, filename="link-to-outside")
        with pytest.raises(PathTraversalError):
            storage.get_approved_path(ref)
        assert storage.exists(ref) is False

    def test_symlink_inside_zone_is_still_not_listed_as_temporary(self, storage):
        target = storage._root / "temporary" / "real-file"
        target.write_bytes(b"data")
        link = storage._root / "temporary" / "link"
        link.symlink_to(target)

        listed = [p.name for p in storage.list_temporary_files()]
        assert "real-file" in listed
        assert "link" not in listed

    def test_sweep_never_deletes_symlinks(self, storage):
        target = storage._root / "temporary" / "real-file"
        target.write_bytes(b"data")
        link = storage._root / "temporary" / "link"
        link.symlink_to(target)
        os.utime(link, (0, 0))

        removed = storage.sweep_temporary(older_than_seconds=0)
        assert removed == 1
        assert not target.exists()
        assert link.is_symlink()


class TestAtomicMoves:
    def test_missing_source_raises_and_creates_nothing(self, storage):
        _, ref = storage.allocate_temp_path()
        with pytest.raises(FileNotFoundError):
            storage.move_to_approved(ref)
        assert not (storage._root / "approved" / ref.filename).exists()

    def test_failed_replace_leaves_source_intact(self, storage, monkeypatch):
        path, ref = make_temp_file(storage)

        def fail_replace(src, dst):
            raise OSError("simulated rename failure")

        monkeypatch.setattr(os, "replace", fail_replace)
        with pytest.raises(OSError):
            storage.move_to_approved(ref)
        assert path.exists()
        assert path.read_bytes() == b"payload"
        assert not (storage._root / "approved" / ref.filename).exists()

    def test_second_move_of_same_ref_fails(self, storage):
        _, ref = make_temp_file(storage)
        storage.move_to_approved(ref)
        with pytest.raises(FileNotFoundError):
            storage.move_to_approved(ref)

    def test_concurrent_moves_to_distinct_targets(self, storage):
        pairs = []
        for i in range(32):
            content = f"file-{i}".encode()
            _, ref = make_temp_file(storage, content=content)
            pairs.append((ref, content))
        errors: list[BaseException] = []

        def move(item):
            ref, content = item
            try:
                target_ref = storage.move_to_approved(ref)
                assert storage.get_approved_path(target_ref).read_bytes() == content
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=move, args=(pair,)) for pair in pairs]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        if errors:
            import traceback
            raise AssertionError("".join(traceback.format_exception(errors[0])))

    def test_move_preserves_exact_bytes(self, storage):
        payload = bytes(range(256)) * 4
        _, ref = make_temp_file(storage, payload)
        approved = storage.move_to_approved(ref)
        assert storage.get_approved_path(approved).read_bytes() == payload


class TestAllocation:
    def test_allocations_are_unique_and_uuid_shaped(self, storage):
        names = {storage.allocate_temp_path()[1].filename for _ in range(500)}
        assert len(names) == 500
        for name in names:
            assert len(name) == 36
            assert name.count("-") == 4

    def test_allocated_path_is_inside_temporary_zone(self, storage):
        path, _ = storage.allocate_temp_path()
        assert path.parent == (storage._root / "temporary").resolve()

    def test_allocations_do_not_create_files(self, storage):
        path, _ = storage.allocate_temp_path()
        assert not path.exists()


class TestCleanup:
    def test_sweep_removes_only_files_older_than_threshold(self, storage):
        old_path, _ = make_temp_file(storage)
        new_path, _ = make_temp_file(storage)
        os.utime(old_path, (0, 0))

        removed = storage.sweep_temporary(older_than_seconds=60)
        assert removed == 1
        assert not old_path.exists()
        assert new_path.exists()

    def test_sweep_swallows_unlink_failure(self, storage, monkeypatch):
        path, _ = make_temp_file(storage)
        os.utime(path, (0, 0))

        def fail_unlink(self, *args, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr(Path, "unlink", fail_unlink)
        assert storage.sweep_temporary(older_than_seconds=0) == 0
        assert path.exists()

    def test_delete_swallows_unlink_failure(self, storage, monkeypatch):
        path, ref = make_temp_file(storage)

        def fail_unlink(self, *args, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr(Path, "unlink", fail_unlink)
        storage.delete(ref)
        assert path.exists()

    def test_sweep_on_missing_zone_is_a_noop(self, tmp_path):
        sm = StorageManager(str(tmp_path / "never-initialized"))
        assert sm.sweep_temporary(older_than_seconds=0) == 0
        assert sm.list_temporary_files() == []


class TestApprovedOnlyReads:
    def test_quarantined_file_cannot_be_read_as_approved(self, storage):
        _, ref = make_temp_file(storage, b"infected")
        quarantine = storage.move_to_quarantine(ref)
        with pytest.raises(ValueError):
            storage.get_approved_path(quarantine)

    def test_temporary_file_cannot_be_read_as_approved(self, storage):
        _, ref = make_temp_file(storage, b"partial")
        with pytest.raises(ValueError):
            storage.get_approved_path(ref)

    def test_approved_checksum_matches_written_bytes(self, storage):
        payload = b"%PDF-1.7\nbody"
        _, ref = make_temp_file(storage, payload)
        approved = storage.move_to_approved(ref)
        import hashlib

        assert storage.compute_sha256(approved) == hashlib.sha256(payload).hexdigest()
        assert storage.file_size(approved) == len(payload)
