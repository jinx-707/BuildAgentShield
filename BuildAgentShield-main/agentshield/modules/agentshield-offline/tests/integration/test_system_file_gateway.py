"""
Integration tests — System File Gateway.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app.core.contracts import (
    FileOperation,
    ResponseStatus,
    SecurityDecision,
    SystemFileInspectRequest,
)


def make_req(path: str, agent_id: str = "test-agent") -> SystemFileInspectRequest:
    return SystemFileInspectRequest(
        agent_id=agent_id,
        tool_name="system_file_inspect",
        operation="inspect",
        path=path,
        access_type=FileOperation.READ,
    )


class TestSystemFileGatewayIntegration:
    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    @pytest.mark.asyncio
    async def test_denies_etc_passwd(self, system_file_gateway):
        resp = await system_file_gateway.inspect(make_req("/etc/passwd"))
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    @pytest.mark.asyncio
    async def test_denies_etc_shadow(self, system_file_gateway):
        resp = await system_file_gateway.inspect(make_req("/etc/shadow"))
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    @pytest.mark.asyncio
    async def test_denies_proc_environ(self, system_file_gateway):
        resp = await system_file_gateway.inspect(make_req("/proc/self/environ"))
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    @pytest.mark.asyncio
    async def test_denies_sys_kernel(self, system_file_gateway):
        resp = await system_file_gateway.inspect(make_req("/sys/kernel/debug"))
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    @pytest.mark.asyncio
    async def test_denies_root_home(self, system_file_gateway):
        resp = await system_file_gateway.inspect(make_req("/root/.bashrc"))
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux paths only")
    @pytest.mark.asyncio
    async def test_denies_ssh_key(self, system_file_gateway):
        resp = await system_file_gateway.inspect(make_req("/home/user/.ssh/id_rsa"))
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.asyncio
    async def test_allows_tmp_path(self, system_file_gateway, tmp_path):
        f = tmp_path / "safe.txt"
        f.write_text("safe")
        resp = await system_file_gateway.inspect(make_req(str(f)))
        assert resp.decision == SecurityDecision.ALLOW

    @pytest.mark.asyncio
    async def test_rejects_traversal(self, system_file_gateway, tmp_path):
        traversal = str(tmp_path) + "/../../etc/passwd"
        resp = await system_file_gateway.inspect(make_req(traversal))
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.asyncio
    async def test_rejects_null_byte(self, system_file_gateway, tmp_path):
        resp = await system_file_gateway.inspect(make_req("/tmp/file\x00.txt"))
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.asyncio
    async def test_rejects_bidi_unicode(self, system_file_gateway):
        resp = await system_file_gateway.inspect(make_req("/tmp/\u202efile.txt"))
        assert resp.decision == SecurityDecision.DENY
