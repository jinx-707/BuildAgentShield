"""
Unit tests — Path validation utilities.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from app.utils.validation import (
    contains_null_byte,
    contains_suspicious_unicode,
    contains_traversal,
    is_safe_path_string,
    safe_path_within_root,
)


class TestTraversalDetection:
    def test_detects_dotdot_slash(self):
        assert contains_traversal("../etc/passwd") is True

    def test_detects_dotdot_backslash(self):
        assert contains_traversal("..\\windows\\system32") is True

    def test_detects_embedded_traversal(self):
        assert contains_traversal("/workspace/foo/../../../etc") is True

    def test_safe_path(self):
        assert contains_traversal("/workspace/documents/report.txt") is False

    def test_relative_safe_path(self):
        assert contains_traversal("documents/report.txt") is False


class TestNullByteDetection:
    def test_detects_null_byte(self):
        assert contains_null_byte("file\x00name.txt") is True

    def test_safe_string(self):
        assert contains_null_byte("/workspace/file.txt") is False


class TestSuspiciousUnicode:
    def test_detects_bidi_override(self):
        assert contains_suspicious_unicode("file\u202ename") is True

    def test_detects_bom(self):
        assert contains_suspicious_unicode("\ufefffoo") is True

    def test_safe_string(self):
        assert contains_suspicious_unicode("/workspace/normal.txt") is False


class TestSafePathString:
    def test_safe_absolute(self):
        assert is_safe_path_string("/workspace/docs/file.txt") is True

    def test_rejects_traversal(self):
        assert is_safe_path_string("../etc/passwd") is False

    def test_rejects_null_byte(self):
        assert is_safe_path_string("/tmp/file\x00.txt") is False

    def test_rejects_bidi(self):
        assert is_safe_path_string("/tmp/\u202efile") is False


class TestSafePathWithinRoot:
    def test_valid_child(self, tmp_path):
        child = tmp_path / "docs" / "file.txt"
        child.parent.mkdir(parents=True, exist_ok=True)
        child.write_text("content")
        result = safe_path_within_root(str(child), str(tmp_path))
        assert result is not None
        assert result == child.resolve()

    def test_outside_root(self, tmp_path):
        outside = tmp_path.parent / "other_dir" / "file.txt"
        result = safe_path_within_root(str(outside), str(tmp_path))
        assert result is None

    def test_traversal_outside_root(self, tmp_path):
        traversal = str(tmp_path) + "/../../etc/passwd"
        result = safe_path_within_root(traversal, str(tmp_path))
        assert result is None

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks require privileges on Windows")
    def test_symlink_escape(self, tmp_path):
        target_dir = tmp_path / "safe"
        target_dir.mkdir()
        # Create a symlink pointing outside the root
        outside = tmp_path.parent / "outside"
        outside.mkdir(exist_ok=True)
        (outside / "secret.txt").write_text("secret")
        link = target_dir / "escape"
        try:
            link.symlink_to(outside)
            result = safe_path_within_root(str(link / "secret.txt"), str(tmp_path))
            assert result is None
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation not supported in this environment")
