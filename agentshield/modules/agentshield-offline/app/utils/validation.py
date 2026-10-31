"""
AgentShield Offline — Input validation helpers.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional


_PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]|[/\\]\.\.")
_NULL_BYTE_RE = re.compile(r"\x00")
_SUSPICIOUS_UNICODE_RE = re.compile(
    r"[\u202a-\u202e\u2066-\u2069\ufeff]"  # bidirectional and BOM characters
)


def contains_traversal(path_str: str) -> bool:
    """Return True if a raw path string contains obvious traversal sequences."""
    return bool(_PATH_TRAVERSAL_RE.search(path_str))


def contains_null_byte(s: str) -> bool:
    return bool(_NULL_BYTE_RE.search(s))


def contains_suspicious_unicode(s: str) -> bool:
    return bool(_SUSPICIOUS_UNICODE_RE.search(s))


def is_safe_path_string(path_str: str) -> bool:
    """Lightweight pre-check before performing canonical path validation."""
    if contains_null_byte(path_str):
        return False
    if contains_traversal(path_str):
        return False
    if contains_suspicious_unicode(path_str):
        return False
    return True


def safe_path_within_root(
    candidate: str, root: str, *, allow_symlinks: bool = False
) -> Optional[Path]:
    """
    Resolve *candidate* and verify it is strictly inside *root*.

    Returns the resolved Path on success, None if outside root or if a
    symlink escape is detected (when allow_symlinks=False).

    NOTE: This is a best-effort Python-level check. Container-level
    filesystem isolation provides the actual enforcement boundary.
    """
    root_path = Path(root).resolve()
    try:
        resolved = Path(candidate).resolve()
    except (OSError, ValueError):
        return None

    if not allow_symlinks:
        # Check each component — if any part is a symlink that jumps outside
        # root we reject it.
        try:
            real = Path(os.path.realpath(candidate))
            if not str(real).startswith(str(root_path)):
                return None
        except OSError:
            return None

    try:
        resolved.relative_to(root_path)
        return resolved
    except ValueError:
        return None
