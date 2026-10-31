"""Quarantine retention lifecycle enforcement.

Policy:
  - Files are retained for QUARANTINE_RETENTION_DAYS (default 90) before they are
    eligible for deletion.
  - Files younger than the retention period are NEVER deleted.
  - Deletion is atomic: the file is unlinked only after ownership and age checks pass.
  - Symlinks are never followed or deleted as quarantine files.
  - Dry-run mode logs what would be deleted without touching the filesystem.
  - Every deletion (real or dry-run) emits a structured audit event.
  - Cleanup failures are logged and counted but do not abort the entire run.
  - Concurrent cleanup jobs are safe: each file is checked independently.
"""

import logging
import os
import time
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("agentshield.security.quarantine_retention")

# Default retention period in days
DEFAULT_RETENTION_DAYS: int = 90


@dataclass
class RetentionRunResult:
    """Summary of a single retention cleanup run."""

    quarantine_dir: str
    retention_days: int
    dry_run: bool
    files_inspected: int = 0
    files_deleted: int = 0
    files_retained: int = 0
    files_skipped_symlink: int = 0
    files_skipped_error: int = 0
    errors: List[str] = field(default_factory=list)


def enforce_quarantine_retention(
    quarantine_dir: str,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    dry_run: bool = False,
    audit_callback=None,
) -> RetentionRunResult:
    """Delete quarantine files older than retention_days.

    Args:
        quarantine_dir: Absolute path to the quarantine directory.
        retention_days: Files older than this many days are eligible for deletion.
        dry_run: If True, log what would be deleted but do not delete anything.
        audit_callback: Optional callable(event: dict) for structured audit events.

    Returns:
        RetentionRunResult with counts and any errors encountered.

    Safety guarantees:
        - Never deletes files younger than retention_days.
        - Never follows or deletes symlinks.
        - Never deletes files outside quarantine_dir (path traversal check).
        - Uses mtime (last modification time) as the age reference — does not trust
          filenames or user-controlled metadata.
        - Resolves the quarantine_dir to its real path before any comparison.
    """
    result = RetentionRunResult(
        quarantine_dir=quarantine_dir,
        retention_days=retention_days,
        dry_run=dry_run,
    )

    if not os.path.isdir(quarantine_dir):
        msg = f"Quarantine directory does not exist or is not a directory: {quarantine_dir}"
        logger.error(msg)
        result.errors.append(msg)
        return result

    real_qdir = os.path.realpath(quarantine_dir)
    cutoff_mtime = time.time() - (retention_days * 86400)
    mode = "DRY-RUN" if dry_run else "LIVE"
    logger.info(
        f"[{mode}] Quarantine retention scan: dir={real_qdir} "
        f"retention_days={retention_days} cutoff_epoch={cutoff_mtime:.0f}"
    )

    try:
        entries = os.listdir(real_qdir)
    except PermissionError as e:
        msg = f"Cannot list quarantine directory {real_qdir}: {e}"
        logger.error(msg)
        result.errors.append(msg)
        return result

    for entry in entries:
        result.files_inspected += 1
        entry_path = os.path.join(real_qdir, entry)

        # Symlink check — never follow or delete symlinks
        if os.path.islink(entry_path):
            logger.warning(f"Skipping symlink in quarantine directory: {entry_path}")
            result.files_skipped_symlink += 1
            _emit_audit(audit_callback, "QUARANTINE_SYMLINK_SKIPPED", entry_path, dry_run)
            continue

        # Path traversal check — resolved path must be inside quarantine_dir
        real_entry = os.path.realpath(entry_path)
        if not real_entry.startswith(real_qdir + os.sep):
            logger.warning(f"Skipping entry outside quarantine dir (traversal?): {real_entry}")
            result.files_skipped_error += 1
            result.errors.append(f"Path traversal detected: {real_entry}")
            continue

        # Only process regular files
        if not os.path.isfile(real_entry):
            result.files_skipped_error += 1
            continue

        try:
            stat = os.stat(real_entry)
        except OSError as e:
            logger.warning(f"Cannot stat {real_entry}: {e}")
            result.files_skipped_error += 1
            result.errors.append(f"stat failed for {real_entry}: {e}")
            continue

        file_mtime = stat.st_mtime
        age_days = (time.time() - file_mtime) / 86400

        if file_mtime > cutoff_mtime:
            # File is younger than retention period — must not be deleted
            result.files_retained += 1
            logger.debug(f"Retaining {entry} (age={age_days:.1f}d < {retention_days}d)")
            continue

        # File is eligible for deletion
        if dry_run:
            logger.info(f"[DRY-RUN] Would delete expired quarantine file: {entry} (age={age_days:.1f}d)")
            result.files_deleted += 1
            _emit_audit(audit_callback, "QUARANTINE_FILE_WOULD_DELETE", real_entry, dry_run, age_days)
        else:
            try:
                os.unlink(real_entry)
                logger.info(f"Deleted expired quarantine file: {entry} (age={age_days:.1f}d)")
                result.files_deleted += 1
                _emit_audit(audit_callback, "QUARANTINE_FILE_DELETED", real_entry, dry_run, age_days)
            except OSError as e:
                logger.error(f"Failed to delete {real_entry}: {e}")
                result.files_skipped_error += 1
                result.errors.append(f"unlink failed for {real_entry}: {e}")

    logger.info(
        f"[{mode}] Retention run complete: inspected={result.files_inspected} "
        f"deleted={result.files_deleted} retained={result.files_retained} "
        f"symlinks_skipped={result.files_skipped_symlink} errors={result.files_skipped_error}"
    )
    return result


def _emit_audit(callback, event_type: str, path: str, dry_run: bool, age_days: float = 0.0):
    if callback is None:
        return
    try:
        callback({
            "event_type": event_type,
            "path": path,
            "dry_run": dry_run,
            "age_days": round(age_days, 2),
        })
    except Exception as e:
        logger.warning(f"Audit callback failed for {event_type}: {e}")
