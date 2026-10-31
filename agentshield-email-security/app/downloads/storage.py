"""Three physically isolated storage zones: temporary, quarantine, and approved.

Files are addressed only by opaque random refs. User-supplied names are never
used as filesystem paths. Zone directories are created with mode 0o700.

A file cannot enter the approved zone merely because it was written to temp.
Approved promotion is an explicit, atomic move from temp only.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from pathlib import Path
from typing import Optional

from app.downloads.config import DownloadSettings, get_download_settings
from app.downloads.enums import StorageZone, assert_zone_move
from app.downloads.exceptions import FilenameError, StorageError, StatusZoneConstraintError

_REF_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_FILE_SUFFIX = ".bin"
_ZONE_MODE = 0o700
_FILE_MODE = 0o600
_WEB_ROOT_MARKERS = frozenset({"static", "public", "www", "htdocs", "webroot"})
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_FILENAME_LEN = 255


class StorageZones:
    """Logical and physical isolation of temp, quarantine, and approved files."""

    def __init__(
        self,
        temp_root: Path | str,
        quarantine_root: Path | str,
        approved_root: Path | str,
        *,
        create: bool = True,
        dir_mode: int = _ZONE_MODE,
        file_mode: int = _FILE_MODE,
    ):
        if dir_mode != _ZONE_MODE:
            raise StorageError("Storage directory mode must be 0o700")
        if file_mode != _FILE_MODE:
            raise StorageError("Stored file mode must be 0o600")
        self._dir_mode = dir_mode
        self._file_mode = file_mode
        self.temp_root = _prepare_root(Path(temp_root), create=create, mode=dir_mode)
        self.quarantine_root = _prepare_root(
            Path(quarantine_root), create=create, mode=dir_mode
        )
        self.approved_root = _prepare_root(Path(approved_root), create=create, mode=dir_mode)
        self.assert_isolated()

    @classmethod
    def from_settings(
        cls, settings: Optional[DownloadSettings] = None, *, create: bool = True
    ) -> "StorageZones":
        cfg = settings or get_download_settings()
        return cls(
            cfg.resolved_temp_root(),
            cfg.resolved_quarantine_root(),
            cfg.resolved_approved_root(),
            create=create,
            dir_mode=cfg.DOWNLOAD_DIR_MODE,
            file_mode=cfg.DOWNLOAD_FILE_MODE,
        )

    def root_for(self, zone: StorageZone | str) -> Path:
        zn = zone if isinstance(zone, StorageZone) else StorageZone(zone)
        if zn is StorageZone.TEMP:
            return self.temp_root
        if zn is StorageZone.QUARANTINE:
            return self.quarantine_root
        if zn is StorageZone.APPROVED:
            return self.approved_root
        raise StorageError(f"No filesystem root for storage zone {zn.value}")

    def new_storage_ref(self) -> str:
        return secrets.token_hex(32)

    def path_for(self, zone: StorageZone | str, storage_ref: str) -> Path:
        zn = zone if isinstance(zone, StorageZone) else StorageZone(zone)
        if zn is StorageZone.NONE:
            raise StorageError("Cannot resolve a path in the none zone")
        ref = _validate_ref(storage_ref)
        root = self.root_for(zn)
        candidate = (root / f"{ref}{_FILE_SUFFIX}").resolve()
        _assert_inside(root, candidate)
        return candidate

    def assert_isolated(self) -> None:
        roots = {
            StorageZone.TEMP: self.temp_root,
            StorageZone.QUARANTINE: self.quarantine_root,
            StorageZone.APPROVED: self.approved_root,
        }
        real = {zone: path.resolve() for zone, path in roots.items()}
        if len(set(real.values())) != 3:
            raise StorageError("Storage zone roots must be distinct real paths")
        for zone, path in real.items():
            if path.is_symlink() or os.path.islink(path):
                raise StorageError(f"Storage root must not be a symlink: {zone.value}")
            _assert_not_web_root(path)
            _assert_mode_restricted(path, self._dir_mode)
        items = list(real.items())
        for i, (za, pa) in enumerate(items):
            for zb, pb in items[i + 1 :]:
                if _is_nested(pa, pb) or _is_nested(pb, pa):
                    raise StorageError(
                        f"Storage roots must not nest: {za.value} and {zb.value}"
                    )

    def contains(self, zone: StorageZone | str, path: Path | str) -> bool:
        root = self.root_for(zone)
        try:
            _assert_inside(root, Path(path).resolve())
            return True
        except StorageError:
            return False

    def write_temp(self, data: bytes = b"") -> str:
        """Create a new object exclusively in the temporary zone."""
        ref = self.new_storage_ref()
        dest = self.path_for(StorageZone.TEMP, ref)
        _write_exclusive(dest, data, mode=self._file_mode)
        return ref

    def move_to_quarantine(self, storage_ref: str) -> Path:
        """Atomic temp -> quarantine move. Never writes into approved."""
        return self._atomic_move(storage_ref, StorageZone.TEMP, StorageZone.QUARANTINE)

    def promote_to_approved(self, storage_ref: str) -> Path:
        """Atomic temp -> approved move.

        This is an explicit promotion API. Writing or downloading into temp does
        not place a file in approved storage. Quarantine cannot be promoted.
        """
        return self._atomic_move(storage_ref, StorageZone.TEMP, StorageZone.APPROVED)

    def _atomic_move(
        self,
        storage_ref: str,
        source_zone: StorageZone,
        dest_zone: StorageZone,
    ) -> Path:
        try:
            assert_zone_move(source_zone, dest_zone)
        except StatusZoneConstraintError as exc:
            raise StorageError(str(exc)) from exc
        if dest_zone is StorageZone.APPROVED and source_zone is not StorageZone.TEMP:
            raise StorageError("Approved promotion is allowed only from the temporary zone")
        if dest_zone is StorageZone.APPROVED and source_zone is StorageZone.QUARANTINE:
            raise StorageError("Quarantined files cannot enter the approved zone")

        src = self.path_for(source_zone, storage_ref)
        dst = self.path_for(dest_zone, storage_ref)
        if not src.exists() or not src.is_file():
            raise StorageError(f"Source object is missing from {source_zone.value}")
        if src.is_symlink() or os.path.islink(src):
            raise StorageError("Refusing to move a symlink")
        if dst.exists():
            raise StorageError("Refusing to overwrite an existing destination object")
        if not self.contains(source_zone, src):
            raise StorageError("Source path is outside the source zone")
        if not self.contains(dest_zone, dst):
            raise StorageError("Destination path is outside the destination zone")

        os.replace(src, dst)
        os.chmod(dst, self._file_mode)
        if not dst.exists() or src.exists():
            raise StorageError("Zone transition did not complete atomically")
        return dst

    def file_mode(self) -> int:
        return self._file_mode


def ensure_storage_zones(settings: Optional[DownloadSettings] = None) -> StorageZones:
    return StorageZones.from_settings(settings, create=True)


def sanitize_filename(name: Optional[str]) -> Optional[str]:
    """Retain a display name only. Never use the result as a filesystem path."""
    if name is None:
        return None
    if not isinstance(name, str):
        raise FilenameError("Filename must be a string")
    if "\x00" in name:
        raise FilenameError("Filename must not contain NUL")
    base = Path(name.replace("\\", "/")).name
    if not base or base in {".", ".."}:
        raise FilenameError("Filename is empty or a path traversal token")
    cleaned = _SAFE_FILENAME_RE.sub("_", base)
    cleaned = re.sub(r"_+", "_", cleaned).strip(" ._")
    if not cleaned:
        raise FilenameError("Filename has no safe characters")
    if len(cleaned) > _MAX_FILENAME_LEN:
        cleaned = cleaned[:_MAX_FILENAME_LEN]
    return cleaned


def _prepare_root(path: Path, *, create: bool, mode: int) -> Path:
    if path.exists() and path.is_symlink():
        raise StorageError(f"Refusing symlink storage root: {path}")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=mode)
        if path.is_symlink():
            raise StorageError(f"Storage root became a symlink: {path}")
        os.chmod(path, mode)
    resolved = path.resolve()
    if resolved.exists() and not resolved.is_dir():
        raise StorageError(f"Storage root is not a directory: {resolved}")
    if resolved.exists() and resolved.is_symlink():
        raise StorageError(f"Resolved storage root is a symlink: {resolved}")
    return resolved


def _validate_ref(storage_ref: str) -> str:
    if not storage_ref or not isinstance(storage_ref, str):
        raise StorageError("storage_ref is required")
    if "/" in storage_ref or "\\" in storage_ref or ".." in storage_ref:
        raise StorageError("storage_ref must not contain path separators or '..'")
    if os.path.isabs(storage_ref):
        raise StorageError("storage_ref must not be an absolute path")
    if not _REF_PATTERN.fullmatch(storage_ref):
        raise StorageError("storage_ref must be a 64-character hex token")
    return storage_ref


def _write_exclusive(path: Path, data: bytes, *, mode: int) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(path, flags, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def _assert_inside(root: Path, candidate: Path) -> None:
    root_real = root.resolve()
    cand_real = candidate.resolve()
    try:
        cand_real.relative_to(root_real)
    except ValueError as exc:
        raise StorageError("Path escapes storage zone root") from exc
    if cand_real == root_real:
        raise StorageError("Refusing to use the zone root as a file path")


def _is_nested(a: Path, b: Path) -> bool:
    try:
        a.relative_to(b)
        return a != b
    except ValueError:
        return False


def _assert_not_web_root(path: Path) -> None:
    parts = {part.lower() for part in path.parts}
    if parts & _WEB_ROOT_MARKERS:
        raise StorageError(
            "Download storage must not live under a public web root "
            f"(rejected path: {path})"
        )


def _assert_mode_restricted(path: Path, expected: int) -> None:
    if not path.exists():
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & stat.S_IWOTH:
        raise StorageError(f"Storage root must not be world-writable: {path}")
    if mode & stat.S_IROTH:
        raise StorageError(f"Storage root must not be world-readable: {path}")
    if mode != expected:
        os.chmod(path, expected)
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode != expected:
            raise StorageError(
                f"Unable to restrict storage root permissions to {oct(expected)}: {path}"
            )
