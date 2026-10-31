"""
Adversarial tests — Path traversal and workspace escape attempts.

All tests use disposable temporary directories.
No destructive operations are performed on the host filesystem.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app.core.contracts import (
    FileDeleteRequest,
    FileOperation,
    FileReadRequest,
    SecurityDecision,
    SystemFileInspectRequest,
)


TRAVERSAL_VARIANTS = [
    "../etc/passwd",
    "../../etc/shadow",
    "../../../root/.ssh/id_rsa",
    "..%2Fetc%2Fpasswd",
    "....//etc/passwd",
    "/workspace/../../../etc/passwd",
    "workspace/docs/../../../../etc/passwd",
    "\x00../etc/passwd",
    "../\x00etc/passwd",
]

UNICODE_BYPASS_VARIANTS = [
    "/tmp/\u202e/etc/passwd",  # bidi override
    "/tmp/\ufeff../etc/passwd",  # BOM
]


class TestPathTraversalAdversarial:
    @pytest.mark.adversarial
    @pytest.mark.parametrize("malicious_path", TRAVERSAL_VARIANTS)
    @pytest.mark.asyncio
    async def test_filesystem_gateway_blocks_traversal(
        self, filesystem_gateway, malicious_path
    ):
        req = FileReadRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="read",
            file_path=malicious_path,
        )
        resp = await filesystem_gateway.read_file(req)
        assert resp.decision == SecurityDecision.DENY, (
            f"Expected DENY for path '{malicious_path}' but got {resp.decision}. "
            f"Reason: {resp.reason}"
        )

    @pytest.mark.adversarial
    @pytest.mark.parametrize("malicious_path", UNICODE_BYPASS_VARIANTS)
    @pytest.mark.asyncio
    async def test_filesystem_gateway_blocks_unicode_bypass(
        self, filesystem_gateway, malicious_path
    ):
        req = FileReadRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="read",
            file_path=malicious_path,
        )
        resp = await filesystem_gateway.read_file(req)
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.adversarial
    @pytest.mark.parametrize("malicious_path", TRAVERSAL_VARIANTS[:6])
    @pytest.mark.asyncio
    async def test_system_gateway_blocks_traversal(
        self, system_file_gateway, malicious_path
    ):
        req = SystemFileInspectRequest(
            agent_id="test-agent",
            tool_name="system_file_inspect",
            operation="inspect",
            path=malicious_path,
            access_type=FileOperation.READ,
        )
        resp = await system_file_gateway.inspect(req)
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_cannot_delete_outside_workspace(self, filesystem_gateway, tmp_path):
        """Agent must not be able to delete files outside their workspace."""
        outside = tmp_path.parent / "important_system_file.txt"
        outside.write_text("critical data")
        req = FileDeleteRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="delete",
            file_path=str(outside),
        )
        resp = await filesystem_gateway.delete_file(req)
        assert resp.decision == SecurityDecision.DENY
        assert outside.exists(), "File outside workspace must not have been deleted"
        outside.unlink()

    @pytest.mark.adversarial
    @pytest.mark.skipif(sys.platform == "win32", reason="Symlinks require privileges on Windows")
    @pytest.mark.asyncio
    async def test_symlink_escape_blocked(self, filesystem_gateway, tmp_workspace):
        """A symlink inside the workspace pointing outside must be blocked."""
        outside = tmp_workspace.parent / "outside_secret"
        outside.mkdir(exist_ok=True)
        (outside / "secret.txt").write_text("top secret")
        link = tmp_workspace / "documents" / "escape_link"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported")

        req = FileReadRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="read",
            file_path=str(link / "secret.txt"),
        )
        resp = await filesystem_gateway.read_file(req)
        assert resp.decision == SecurityDecision.DENY, (
            "Symlink escape must be blocked"
        )
        # Cleanup
        link.unlink(missing_ok=True)
        import shutil
        shutil.rmtree(str(outside), ignore_errors=True)
