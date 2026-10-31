"""
AgentShield Offline — Safe atomic file operations.

All file I/O passes through these wrappers to ensure:
- Atomic writes (write to temp file, then rename).
- No unintended side effects.
- Proper resource cleanup.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Optional

import aiofiles
import aiofiles.os
import structlog

log = structlog.get_logger(__name__)


async def safe_read_file(path: Path, encoding: str = "utf-8", max_bytes: Optional[int] = None) -> str:
    """Read a file asynchronously with optional byte limit."""
    async with aiofiles.open(path, "r", encoding=encoding, errors="replace") as f:
        if max_bytes:
            content = await f.read(max_bytes)
        else:
            content = await f.read()
    return content


async def safe_write_file(path: Path, content: str, encoding: str = "utf-8") -> None:
    """
    Atomic write: write to a temp file in the same directory, then rename.
    This prevents partial writes from corrupting the target file.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    tmp_path = parent / f".tmp_{uuid.uuid4().hex}"
    try:
        async with aiofiles.open(tmp_path, "w", encoding=encoding) as f:
            await f.write(content)
        # Atomic rename (same filesystem)
        os.replace(tmp_path, path)
    except Exception:
        # Clean up temp file on failure
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


async def safe_delete_file(path: Path) -> None:
    """Delete a file asynchronously."""
    await aiofiles.os.remove(path)


async def safe_move_file(source: Path, destination: Path) -> None:
    """Move a file atomically if on the same filesystem, otherwise copy+delete."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))


async def safe_copy_file(source: Path, destination: Path) -> None:
    """Copy a file."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(source), str(destination))


def search_files(
    directory: Path,
    pattern: str,
    *,
    recursive: bool = False,
    max_results: int = 100,
) -> list[str]:
    """
    Search for files matching a glob pattern within a directory.
    Returns relative paths (relative to directory) for up to max_results files.
    """
    results: list[str] = []
    if recursive:
        for root, dirs, files in os.walk(directory):
            for fname in files:
                if fnmatch.fnmatch(fname, pattern):
                    rel = os.path.relpath(os.path.join(root, fname), directory)
                    results.append(rel)
                    if len(results) >= max_results:
                        return results
    else:
        for entry in directory.iterdir():
            if entry.is_file() and fnmatch.fnmatch(entry.name, pattern):
                results.append(entry.name)
                if len(results) >= max_results:
                    return results
    return results


def list_directory(directory: Path, max_entries: int = 500) -> list[dict]:
    """List directory contents up to max_entries."""
    entries = []
    for entry in directory.iterdir():
        entries.append(
            {
                "name": entry.name,
                "is_file": entry.is_file(),
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else None,
            }
        )
        if len(entries) >= max_entries:
            break
    return entries
