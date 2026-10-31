"""
AgentShield Offline — Permission checker for local file operations.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import structlog

from app.capabilities.offline.local_files.directory_scopes import (
    AgentFilesystemConfig,
    DirectoryScopeRegistry,
)
from app.core.contracts import FileOperation
from app.core.exceptions import (
    PathTraversalError,
    SymlinkEscapeError,
    WorkspaceEscapeError,
)
from app.utils.validation import (
    contains_null_byte,
    contains_suspicious_unicode,
    contains_traversal,
)


def _contains_url_encoded_traversal(path_str: str) -> bool:
    lowered = path_str.lower()
    return any(pat in lowered for pat in ["%2f", "%5c", "%2e", "%252f", "%252e"])

log = structlog.get_logger(__name__)


class PermissionChecker:
    """
    Verifies that a resolved path is:
    1. Inside the agent's workspace.
    2. Permitted for the requested operation.
    3. Not escaping via symlinks.
    4. Has an allowed extension (when configured).
    5. Within file size limits (for reads).
    """

    def __init__(self, scope_registry: DirectoryScopeRegistry) -> None:
        self._scopes = scope_registry

    def validate_and_resolve(
        self,
        raw_path: str,
        agent_id: str,
        operation: FileOperation,
    ) -> Path:
        """
        Returns the resolved canonical Path on success.
        Raises a security exception on any violation.
        """
        # String pre-checks
        if contains_null_byte(raw_path):
            raise PathTraversalError("Path contains null byte", attempted_path=raw_path)
        if contains_traversal(raw_path):
            raise PathTraversalError("Path contains traversal sequence", attempted_path=raw_path)
        if _contains_url_encoded_traversal(raw_path):
            raise PathTraversalError("Path contains URL-encoded traversal", attempted_path=raw_path)
        if contains_suspicious_unicode(raw_path):
            raise PathTraversalError("Path contains suspicious Unicode", attempted_path=raw_path)

        cfg = self._scopes.get_config(agent_id)
        workspace = cfg.workspace_path if cfg else Path("/workspace").resolve()

        # Resolve — if file doesn't exist yet (create), use parent
        try:
            candidate = Path(raw_path)
            if candidate.exists():
                resolved = candidate.resolve()
            else:
                resolved = (workspace / candidate).resolve()
        except (OSError, ValueError) as exc:
            raise PathTraversalError(
                f"Cannot resolve path: {exc}", attempted_path=raw_path
            ) from exc

        # Workspace containment
        try:
            resolved.relative_to(workspace)
        except ValueError:
            raise WorkspaceEscapeError(
                f"Path '{resolved}' is outside the agent workspace '{workspace}'"
            )

        # Symlink escape check
        if resolved.exists() and resolved.is_symlink():
            real = Path(os.path.realpath(str(resolved)))
            try:
                real.relative_to(workspace)
            except ValueError:
                raise SymlinkEscapeError(
                    f"Symlink target '{real}' is outside the agent workspace"
                )

        # Permission check
        permitted_dirs = self._scopes.get_permitted_dirs(agent_id, operation)
        if not permitted_dirs:
            raise WorkspaceEscapeError(
                f"No permitted directories configured for agent '{agent_id}' "
                f"operation '{operation.value}'"
            )

        permitted = False
        for pdir in permitted_dirs:
            try:
                resolved.relative_to(pdir)
                permitted = True
                break
            except ValueError:
                continue

        if not permitted:
            raise WorkspaceEscapeError(
                f"Path '{resolved}' is not in a permitted directory for "
                f"operation '{operation.value}' (agent: {agent_id})"
            )

        # Extension check
        if cfg:
            ext = resolved.suffix.lower()
            if cfg.denied_extensions and ext in cfg.denied_extensions:
                raise WorkspaceEscapeError(
                    f"File extension '{ext}' is denied for agent '{agent_id}'"
                )
            if cfg.allowed_extensions and ext not in cfg.allowed_extensions:
                raise WorkspaceEscapeError(
                    f"File extension '{ext}' is not in the allowlist for agent '{agent_id}'"
                )

        return resolved

    def check_file_size(self, path: Path, agent_id: str) -> None:
        """Raise WorkspaceEscapeError if the file exceeds the agent's size limit."""
        cfg = self._scopes.get_config(agent_id)
        if not cfg or not path.exists():
            return
        size = path.stat().st_size
        if size > cfg.max_file_size_bytes:
            raise WorkspaceEscapeError(
                f"File size {size} exceeds agent limit {cfg.max_file_size_bytes}"
            )
