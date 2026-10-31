"""
Unit tests — Protected path registry and path validator.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app.capabilities.offline.system_files.protected_paths import ProtectedPathRegistry
from app.capabilities.offline.system_files.path_validator import PathValidator
from app.core.exceptions import PathTraversalError, ProtectedPathError, SymlinkEscapeError


@pytest.fixture
def registry():
    r = ProtectedPathRegistry.__new__(ProtectedPathRegistry)
    import re
    if sys.platform.startswith("win"):
        from app.capabilities.offline.system_files.protected_paths import (
            _WINDOWS_PROTECTED_DIRS,
            _WINDOWS_SENSITIVE_PATTERNS,
        )
        r._protected_dirs = [Path(d) for d in _WINDOWS_PROTECTED_DIRS if Path(d).exists() or True]
        r._sensitive_patterns = [re.compile(p, re.IGNORECASE) for p in _WINDOWS_SENSITIVE_PATTERNS]
    else:
        from app.capabilities.offline.system_files.protected_paths import (
            _LINUX_PROTECTED_DIRS,
            _LINUX_SENSITIVE_PATTERNS,
        )
        r._protected_dirs = [Path(d) for d in _LINUX_PROTECTED_DIRS]
        r._sensitive_patterns = [re.compile(p, re.IGNORECASE) for p in _LINUX_SENSITIVE_PATTERNS]
    r._agent_exclusions = {}
    return r


@pytest.fixture
def validator(registry):
    return PathValidator(registry)


class TestProtectedPathRegistry:
    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    def test_etc_is_protected(self, registry):
        protected, reason = registry.is_protected(Path("/etc/passwd"))
        assert protected

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    def test_root_home_is_protected(self, registry):
        protected, reason = registry.is_protected(Path("/root/.bashrc"))
        assert protected

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    def test_proc_is_protected(self, registry):
        protected, reason = registry.is_protected(Path("/proc/self/environ"))
        assert protected

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    def test_ssh_key_pattern(self, registry):
        protected, reason = registry.is_protected(Path("/home/user/.ssh/id_rsa"))
        assert protected

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    def test_aws_credentials(self, registry):
        protected, reason = registry.is_protected(Path("/home/user/.aws/credentials"))
        assert protected

    def test_tmp_is_not_protected(self, registry):
        protected, reason = registry.is_protected(Path("/tmp/safe_file.txt"))
        assert not protected

    def test_workspace_not_protected(self, registry):
        protected, reason = registry.is_protected(Path("/workspace/documents/file.txt"))
        assert not protected


class TestPathValidator:
    def test_rejects_null_byte(self, validator):
        with pytest.raises(PathTraversalError):
            validator.validate("/tmp/file\x00.txt")

    def test_rejects_traversal(self, validator):
        with pytest.raises(PathTraversalError):
            validator.validate("../etc/passwd")

    def test_rejects_suspicious_unicode(self, validator):
        with pytest.raises(PathTraversalError):
            validator.validate("/tmp/\u202efile")

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    def test_rejects_etc_passwd(self, validator):
        with pytest.raises(ProtectedPathError):
            validator.validate("/etc/passwd")

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    def test_rejects_ssh_key(self, validator):
        with pytest.raises(ProtectedPathError):
            validator.validate("/root/.ssh/id_rsa")

    def test_accepts_tmp_path(self, validator, tmp_path):
        # /tmp paths should not be in the protected registry
        safe = tmp_path / "workfile.txt"
        safe.write_text("content")
        result = validator.validate(str(safe))
        assert result.exists()
