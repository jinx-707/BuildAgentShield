"""
AgentShield Offline — Path Validator for system file access.

Validates that a requested path:
  1. Has no traversal sequences or null bytes.
  2. Has no suspicious Unicode (bidirectional override characters etc).
  3. Resolves to a canonical absolute path.
  4. Does not escape via symlinks (best-effort Python check; container
     isolation provides the actual enforcement boundary).
  5. Is not a protected system path.

NOTE: Do not rely on this module as the sole security boundary.
Container-level filesystem restrictions are the primary enforcement layer.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional, Tuple

import structlog

from app.capabilities.offline.system_files.protected_paths import ProtectedPathRegistry
from app.core.exceptions import (
    PathTraversalError,
    ProtectedPathError,
    SymlinkEscapeError,
)
from app.utils.validation import (
    contains_null_byte,
    contains_suspicious_unicode,
    contains_traversal,
)

log = structlog.get_logger(__name__)


def _contains_url_encoded_traversal(path_str: str) -> bool:
    """Detect URL-encoded traversal sequences like %2F, %5C, %2e, %2E."""
    import re
    # Check for URL-encoded slashes, dots, and common bypass patterns
    patterns = [
        r'%2f',   # /
        r'%5c',   # backslash
        r'%2e',   # .
        r'%252f', # double-encoded /
        r'%252e', # double-encoded .
    ]
    lowered = path_str.lower()
    return any(pat in lowered for pat in patterns)


class PathValidator:
    """
    Validates paths for system file access requests.
    """

    def __init__(self, registry: ProtectedPathRegistry) -> None:
        self._registry = registry

    def validate(self, raw_path: str, agent_id: str = "") -> Path:
        """
        Validate *raw_path* and return the resolved canonical Path.
        Raises a specific exception on any validation failure.
        """
        # --- Pre-checks on the raw string ---
        if contains_null_byte(raw_path):
            raise PathTraversalError(
                "Path contains null byte", attempted_path=raw_path
            )
        if contains_traversal(raw_path):
            raise PathTraversalError(
                "Path contains traversal sequence", attempted_path=raw_path
            )
        if _contains_url_encoded_traversal(raw_path):
            raise PathTraversalError(
                "Path contains URL-encoded traversal sequence", attempted_path=raw_path
            )
        if contains_suspicious_unicode(raw_path):
            raise PathTraversalError(
                "Path contains suspicious Unicode characters", attempted_path=raw_path
            )

        # --- Resolve ---
        try:
            resolved = Path(raw_path).resolve()
        except (OSError, ValueError) as exc:
            raise PathTraversalError(
                f"Cannot resolve path: {exc}", attempted_path=raw_path
            ) from exc

        if not resolved.is_absolute():
            raise PathTraversalError("Resolved path is not absolute", attempted_path=raw_path)

        # --- Symlink check ---
        if resolved.exists() and resolved.is_symlink():
            real = Path(os.path.realpath(raw_path))
            protected, reason = self._registry.is_protected(real, agent_id)
            if protected:
                raise SymlinkEscapeError(
                    f"Symlink target is a protected path: {reason}"
                )

        # --- Protected path check ---
        protected, reason = self._registry.is_protected(resolved, agent_id)
        if protected:
            raise ProtectedPathError(
                f"Access to protected system resource denied: {reason}",
                path=str(resolved),
            )

        log.debug("path_validated", path=str(resolved), agent_id=agent_id)
        return resolved
