"""Storage isolation, permissions, path-traversal, and atomic zone-move tests."""

import os
import stat
from pathlib import Path

import pytest

from app.downloads.config import DownloadSettings
from app.downloads.enums import StorageZone
from app.downloads.exceptions import FilenameError, StorageError
from app.downloads.storage import StorageZones, ensure_storage_zones, sanitize_filename


def _zones(tmp_path: Path) -> StorageZones:
    return StorageZones(
        tmp_path / "temp",
        tmp_path / "quarantine",
        tmp_path / "approved",
        create=True,
    )


class TestStorageZoneCreation:
    def test_creates_three_distinct_directories(self, tmp_path: Path):
        zones = _zones(tmp_path)
        assert zones.temp_root.is_dir()
        assert zones.quarantine_root.is_dir()
        assert zones.approved_root.is_dir()
        assert len({zones.temp_root, zones.quarantine_root, zones.approved_root}) == 3

    def test_directories_are_mode_0700(self, tmp_path: Path):
        zones = _zones(tmp_path)
        for root in (zones.temp_root, zones.quarantine_root, zones.approved_root):
            mode = stat.S_IMODE(root.stat().st_mode)
            assert mode == 0o700

    def test_tightens_overly_permissive_existing_root(self, tmp_path: Path):
        loose = tmp_path / "temp"
        loose.mkdir()
        os.chmod(loose, 0o777)
        zones = StorageZones(
            loose, tmp_path / "quarantine", tmp_path / "approved", create=True
        )
        assert stat.S_IMODE(zones.temp_root.stat().st_mode) == 0o700

    def test_from_settings(self, tmp_path: Path):
        settings = DownloadSettings(
            _env_file=None,
            DOWNLOAD_STORAGE_ROOT=str(tmp_path / "downloads"),
        )
        zones = ensure_storage_zones(settings)
        assert zones.temp_root == (tmp_path / "downloads" / "temp").resolve()
        assert zones.quarantine_root == (tmp_path / "downloads" / "quarantine").resolve()
        assert zones.approved_root == (tmp_path / "downloads" / "approved").resolve()

    def test_rejects_weaker_dir_mode(self, tmp_path: Path):
        with pytest.raises(StorageError):
            StorageZones(
                tmp_path / "temp",
                tmp_path / "quarantine",
                tmp_path / "approved",
                dir_mode=0o755,
            )


class TestStorageIsolation:
    def test_ref_resolves_inside_requested_zone_only(self, tmp_path: Path):
        zones = _zones(tmp_path)
        ref = zones.new_storage_ref()
        temp_path = zones.path_for(StorageZone.TEMP, ref)
        quar_path = zones.path_for(StorageZone.QUARANTINE, ref)
        appr_path = zones.path_for(StorageZone.APPROVED, ref)
        assert temp_path.parent == zones.temp_root
        assert quar_path.parent == zones.quarantine_root
        assert appr_path.parent == zones.approved_root
        assert temp_path != quar_path != appr_path

    def test_write_temp_does_not_enter_approved(self, tmp_path: Path):
        zones = _zones(tmp_path)
        ref = zones.write_temp(b"untrusted")
        temp_path = zones.path_for(StorageZone.TEMP, ref)
        assert temp_path.exists()
        assert not zones.path_for(StorageZone.APPROVED, ref).exists()
        assert not zones.path_for(StorageZone.QUARANTINE, ref).exists()
        assert stat.S_IMODE(temp_path.stat().st_mode) == 0o600

    def test_quarantine_file_is_not_in_approved_zone(self, tmp_path: Path):
        zones = _zones(tmp_path)
        ref = zones.write_temp(b"quarantined")
        qpath = zones.move_to_quarantine(ref)
        assert zones.contains(StorageZone.QUARANTINE, qpath)
        assert not zones.contains(StorageZone.APPROVED, qpath)
        assert not zones.contains(StorageZone.TEMP, qpath)
        assert not zones.path_for(StorageZone.TEMP, ref).exists()
        assert stat.S_IMODE(qpath.stat().st_mode) == 0o600

    def test_atomic_promote_temp_to_approved(self, tmp_path: Path):
        zones = _zones(tmp_path)
        ref = zones.write_temp(b"scanned-clean")
        dest = zones.promote_to_approved(ref)
        assert dest.exists()
        assert dest.read_bytes() == b"scanned-clean"
        assert not zones.path_for(StorageZone.TEMP, ref).exists()
        assert zones.contains(StorageZone.APPROVED, dest)

    def test_quarantine_cannot_be_promoted(self, tmp_path: Path):
        zones = _zones(tmp_path)
        ref = zones.write_temp(b"bad")
        zones.move_to_quarantine(ref)
        with pytest.raises(StorageError):
            zones.promote_to_approved(ref)
        assert zones.path_for(StorageZone.QUARANTINE, ref).exists()
        assert not zones.path_for(StorageZone.APPROVED, ref).exists()

    def test_refuses_overwrite_on_promote(self, tmp_path: Path):
        zones = _zones(tmp_path)
        ref = zones.write_temp(b"first")
        zones.promote_to_approved(ref)
        # Recreate the same ref in temp (direct write of existing dest name).
        temp_again = zones.path_for(StorageZone.TEMP, ref)
        temp_again.write_bytes(b"second")
        with pytest.raises(StorageError):
            zones.promote_to_approved(ref)

    def test_rejects_path_traversal_refs(self, tmp_path: Path):
        zones = _zones(tmp_path)
        for bad in (
            "../approved/ab",
            "..",
            "/tmp/evil",
            "abcd/efgh",
            "aabbccdd" * 2,
            "../" + "ab" * 32,
            "report.pdf",
        ):
            with pytest.raises(StorageError):
                zones.path_for(StorageZone.TEMP, bad)

    def test_user_filename_is_not_a_storage_path(self, tmp_path: Path):
        zones = _zones(tmp_path)
        with pytest.raises(StorageError):
            zones.path_for(StorageZone.TEMP, "../../approved/payload.pdf")
        with pytest.raises(StorageError):
            zones.path_for(StorageZone.APPROVED, "invoice.pdf")

    def test_rejects_none_zone_paths(self, tmp_path: Path):
        zones = _zones(tmp_path)
        with pytest.raises(StorageError):
            zones.path_for(StorageZone.NONE, zones.new_storage_ref())

    def test_rejects_symlink_root(self, tmp_path: Path):
        real = tmp_path / "real-temp"
        real.mkdir()
        link = tmp_path / "temp-link"
        link.symlink_to(real)
        with pytest.raises(StorageError):
            StorageZones(link, tmp_path / "quarantine", tmp_path / "approved", create=True)

    def test_rejects_identical_roots(self, tmp_path: Path):
        shared = tmp_path / "shared"
        shared.mkdir()
        with pytest.raises(StorageError):
            StorageZones(shared, shared, tmp_path / "approved", create=True)

    def test_rejects_nested_roots(self, tmp_path: Path):
        parent = tmp_path / "downloads"
        parent.mkdir()
        with pytest.raises(StorageError):
            StorageZones(parent, parent / "quarantine", tmp_path / "approved", create=True)

    def test_rejects_public_web_root_name(self, tmp_path: Path):
        with pytest.raises(StorageError):
            StorageZones(
                tmp_path / "public",
                tmp_path / "quarantine",
                tmp_path / "approved",
                create=True,
            )


class TestFilenameSanitization:
    def test_strips_path_components(self):
        assert sanitize_filename("../../etc/passwd") == "passwd"
        assert sanitize_filename("C:\\\\Windows\\\\report.pdf") == "report.pdf"

    def test_rejects_traversal_tokens(self):
        with pytest.raises(FilenameError):
            sanitize_filename("..")
        with pytest.raises(FilenameError):
            sanitize_filename(".")
        with pytest.raises(FilenameError):
            sanitize_filename("")

    def test_rejects_nul(self):
        with pytest.raises(FilenameError):
            sanitize_filename("ok\x00.pdf")

    def test_replaces_unsafe_characters(self):
        assert sanitize_filename("my report (1).pdf") == "my_report_1_.pdf"
