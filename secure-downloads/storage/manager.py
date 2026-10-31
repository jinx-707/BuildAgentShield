"""
Secure file storage manager.

Storage layout
--------------
<storage_root>/
  temporary/    — files being streamed from the network
  quarantine/   — files that failed malware scanning
  approved/     — files that passed all checks and are available for handoff

Security properties
-------------------
- All filenames are generated UUIDs.  The original filename is never used
  as a path component.
- Path traversal is prevented by asserting that every resolved path is
  inside the expected zone directory.
- Zone transitions are atomic where possible (os.replace).
- Quarantined files can never be read through the approved-file interface.
- File contents are never read back through the database.
- Tenant isolation: tenant_id is stored in the storage_ref but never
  used as a path prefix — it is metadata only, not a filesystem namespace.
  (A future release can add per-tenant subdirectories; for now, generated
  UUIDs provide sufficient isolation.)

StorageRef format
-----------------
"<zone>/<uuid>" — e.g. "approved/3f2a1b4c-…"
This is an opaque string; callers must not parse or construct it by hand.
Use StorageManager.parse_ref() to decompose it.
"""
from __future__ import annotations

import enum
import hashlib
import logging
import os
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


class StorageZone(str, enum.Enum):
    TEMPORARY = "temporary"
    QUARANTINE = "quarantine"
    APPROVED = "approved"


@dataclass(frozen=True)
class StorageRef:
    zone: StorageZone
    filename: str   # UUID basename, no extension

    @property
    def ref_string(self) -> str:
        return f"{self.zone.value}/{self.filename}"

    @classmethod
    def parse(cls, ref_string: str) -> "StorageRef":
        parts = ref_string.split("/", 1)
        if len(parts) != 2 or not parts[1]:
            raise ValueError(f"Invalid storage ref: {ref_string!r}")
        try:
            zone = StorageZone(parts[0])
        except ValueError:
            raise ValueError(f"Unknown storage zone in ref: {parts[0]!r}")
        return cls(zone=zone, filename=parts[1])


class PathTraversalError(Exception):
    """Raised when a constructed path would escape its storage zone."""


class StorageManager:
    """
    Manages file movement across storage zones.

    Parameters
    ----------
    storage_root: Absolute path to the base storage directory.
    """

    def __init__(self, storage_root: str) -> None:
        self._root = Path(storage_root).resolve()

    def initialize(self) -> None:
        """
        Create zone directories with restrictive permissions.

        Should be called once at application startup.  Safe to call multiple times.
        """
        for zone in StorageZone:
            zone_dir = self._root / zone.value
            zone_dir.mkdir(parents=True, exist_ok=True)
            # owner rwx, group ---, other ---
            os.chmod(zone_dir, stat.S_IRWXU)
        # Also restrict the root
        os.chmod(self._root, stat.S_IRWXU)

    def allocate_temp_path(self) -> tuple[Path, StorageRef]:
        """
        Return a (path, ref) pair for a new temporary file.

        The file does not yet exist.  The caller is responsible for
        creating and writing it via the path.
        """
        filename = str(uuid.uuid4())
        ref = StorageRef(zone=StorageZone.TEMPORARY, filename=filename)
        path = self._resolve_ref(ref)
        return path, ref

    def temporary_path(self, ref: StorageRef) -> Path:
        """Resolve a temporary-zone ref to its filesystem path (caller only)."""
        if ref.zone != StorageZone.TEMPORARY:
            raise ValueError(
                f"Access denied: file is in zone {ref.zone.value!r}, not 'temporary'."
            )
        return self._resolve_ref(ref)

    def list_temporary_files(self) -> list[Path]:
        """Return regular temporarily-stored files (never symlinks)."""
        zone_dir = self._zone_dir(StorageZone.TEMPORARY)
        if not zone_dir.is_dir():
            return []
        return [
            entry
            for entry in zone_dir.iterdir()
            if entry.is_file() and not entry.is_symlink()
        ]

    def sweep_temporary(self, *, older_than_seconds: float = 0.0) -> int:
        """
        Delete temporary files older than the threshold; return the count.

        At startup every temporary file is an orphan (no download is running
        yet), so the application calls this with a zero threshold.  Symlinks
        are never followed or deleted.
        """
        cutoff = time.time() - older_than_seconds
        removed = 0
        for entry in self.list_temporary_files():
            try:
                if entry.stat().st_mtime > cutoff:
                    continue
                entry.unlink()
                removed += 1
            except OSError as exc:
                logger.warning(
                    "temporary_sweep_failed",
                    extra={"error_type": type(exc).__name__},
                )
        return removed

    def move_to_quarantine(self, temp_ref: StorageRef) -> StorageRef:
        """Move a file from temporary to quarantine."""
        if temp_ref.zone != StorageZone.TEMPORARY:
            raise ValueError("Can only move from TEMPORARY to quarantine.")
        return self._move_zone(temp_ref, StorageZone.QUARANTINE)

    def move_to_approved(self, temp_ref: StorageRef) -> StorageRef:
        """Move a file from temporary to approved."""
        if temp_ref.zone != StorageZone.TEMPORARY:
            raise ValueError("Can only move from TEMPORARY to approved.")
        return self._move_zone(temp_ref, StorageZone.APPROVED)

    def delete(self, ref: StorageRef) -> None:
        """Delete a file in any zone.  Silently ignores missing files."""
        try:
            path = self._resolve_ref(ref)
            path.unlink(missing_ok=True)
        except (PathTraversalError, ValueError):
            pass
        except OSError as exc:
            logger.warning(
                "storage_delete_failed", extra={"error_type": type(exc).__name__}
            )

    def exists(self, ref: StorageRef) -> bool:
        """Return True if the file exists in its declared zone."""
        try:
            return self._resolve_ref(ref).exists()
        except PathTraversalError:
            return False

    def get_approved_path(self, ref: StorageRef) -> Path:
        """
        Resolve a ref to its filesystem path, asserting it is in the approved zone.

        This is the ONLY way to read an approved file.  Quarantined files
        cannot be retrieved through this method.
        """
        if ref.zone != StorageZone.APPROVED:
            raise ValueError(
                f"Access denied: file is in zone {ref.zone.value!r}, not 'approved'."
            )
        return self._resolve_ref(ref)

    def compute_sha256(self, ref: StorageRef) -> str:
        """Compute SHA-256 of a file in any zone."""
        path = self._resolve_ref(ref)
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def file_size(self, ref: StorageRef) -> int:
        """Return the byte size of a file in any zone."""
        path = self._resolve_ref(ref)
        return path.stat().st_size

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _zone_dir(self, zone: StorageZone) -> Path:
        return self._root / zone.value

    def _resolve_ref(self, ref: StorageRef) -> Path:
        zone_dir = self._zone_dir(ref.zone)
        # Prevent path traversal: filename must be a plain basename with no slashes.
        if "/" in ref.filename or "\\" in ref.filename or ".." in ref.filename:
            raise PathTraversalError(
                f"Filename contains path separators: {ref.filename!r}"
            )
        path = (zone_dir / ref.filename).resolve()
        # The resolved path must still be inside the zone directory.
        try:
            path.relative_to(zone_dir.resolve())
        except ValueError:
            raise PathTraversalError(
                f"Resolved path {path!r} escapes zone directory {zone_dir!r}."
            )
        return path

    def _move_zone(self, source_ref: StorageRef, target_zone: StorageZone) -> StorageRef:
        source_path = self._resolve_ref(source_ref)
        if not source_path.is_file():
            raise FileNotFoundError(
                f"Source file for zone move is missing: {source_ref.zone.value}."
            )
        target_ref = StorageRef(zone=target_zone, filename=source_ref.filename)
        target_path = self._resolve_ref(target_ref)
        os.replace(source_path, target_path)  # atomic on POSIX
        try:
            # Files are created 0600; enforce it again so a loosened mode on an
            # existing file cannot follow the file into approved/quarantine.
            os.chmod(target_path, 0o600)
        except OSError as exc:
            logger.warning(
                "storage_chmod_failed", extra={"error_type": type(exc).__name__}
            )
        return target_ref
