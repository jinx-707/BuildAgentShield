"""
Unit tests — Local file permission checker.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.capabilities.offline.local_files.directory_scopes import (
    AgentFilesystemConfig,
    DirectoryScopeRegistry,
)
from app.capabilities.offline.local_files.permissions import PermissionChecker
from app.core.contracts import FileOperation
from app.core.exceptions import PathTraversalError, SymlinkEscapeError, WorkspaceEscapeError


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "output").mkdir()
    return tmp_path


@pytest.fixture
def registry(workspace):
    reg = DirectoryScopeRegistry.__new__(DirectoryScopeRegistry)
    reg._agents = {
        "agent1": AgentFilesystemConfig(
            agent_id="agent1",
            workspace=str(workspace),
            read_paths=[str(workspace / "docs")],
            write_paths=[str(workspace / "output")],
            delete_paths=[str(workspace / "output")],
            max_file_size_bytes=1024 * 1024,
        ),
        "agent2": AgentFilesystemConfig(
            agent_id="agent2",
            workspace=str(workspace),
            read_paths=[str(workspace / "output")],
            write_paths=[],
            delete_paths=[],
        ),
    }
    return reg


@pytest.fixture
def checker(registry):
    return PermissionChecker(registry)


class TestPermissionChecker:
    def test_allows_read_in_permitted_dir(self, checker, workspace):
        f = workspace / "docs" / "file.txt"
        f.write_text("content")
        result = checker.validate_and_resolve(str(f), "agent1", FileOperation.READ)
        assert result == f.resolve()

    def test_denies_read_outside_permitted_dir(self, checker, workspace):
        f = workspace / "output" / "file.txt"
        f.write_text("content")
        with pytest.raises(WorkspaceEscapeError):
            checker.validate_and_resolve(str(f), "agent1", FileOperation.READ)

    def test_allows_write_in_permitted_dir(self, checker, workspace):
        f = workspace / "output" / "result.txt"
        result = checker.validate_and_resolve(str(f), "agent1", FileOperation.WRITE)
        assert result.parent == (workspace / "output").resolve()

    def test_denies_write_in_read_only_dir(self, checker, workspace):
        f = workspace / "docs" / "file.txt"
        with pytest.raises(WorkspaceEscapeError):
            checker.validate_and_resolve(str(f), "agent1", FileOperation.WRITE)

    def test_denies_cross_agent_access(self, checker, workspace):
        """Agent2 cannot read agent1's docs."""
        f = workspace / "docs" / "secret.txt"
        f.write_text("secret")
        with pytest.raises(WorkspaceEscapeError):
            checker.validate_and_resolve(str(f), "agent2", FileOperation.READ)

    def test_rejects_traversal_attempt(self, checker, workspace):
        malicious = str(workspace / "docs" / ".." / ".." / "etc" / "passwd")
        with pytest.raises((PathTraversalError, WorkspaceEscapeError, ProtectedPathError)):
            checker.validate_and_resolve(malicious, "agent1", FileOperation.READ)

    def test_rejects_null_byte(self, checker, workspace):
        with pytest.raises(PathTraversalError):
            checker.validate_and_resolve(
                str(workspace / "docs") + "/file\x00.txt",
                "agent1",
                FileOperation.READ,
            )

    def test_denies_unknown_agent(self, checker, workspace):
        f = workspace / "docs" / "file.txt"
        with pytest.raises(WorkspaceEscapeError):
            checker.validate_and_resolve(str(f), "unknown-agent", FileOperation.READ)


# Import ProtectedPathError for the traversal test
from app.core.exceptions import ProtectedPathError
