"""
Adversarial tests — Cross-agent isolation.

Verifies that one agent cannot access another agent's files or secrets.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.capabilities.offline.local_files.directory_scopes import (
    AgentFilesystemConfig,
    DirectoryScopeRegistry,
)
from app.capabilities.offline.local_files.filesystem_gateway import LocalFilesystemGateway
from app.core.contracts import FileReadRequest, SecurityDecision


@pytest.fixture
def multi_agent_registry(tmp_path):
    """Two agents with separate workspaces under the same tmp_path root."""
    (tmp_path / "agent_a" / "data").mkdir(parents=True)
    (tmp_path / "agent_b" / "data").mkdir(parents=True)
    (tmp_path / "agent_a" / "data" / "a_secret.txt").write_text("Agent A secret data")
    (tmp_path / "agent_b" / "data" / "b_secret.txt").write_text("Agent B secret data")

    reg = DirectoryScopeRegistry.__new__(DirectoryScopeRegistry)
    reg._agents = {
        "agent-a": AgentFilesystemConfig(
            agent_id="agent-a",
            workspace=str(tmp_path / "agent_a"),
            read_paths=[str(tmp_path / "agent_a" / "data")],
            write_paths=[str(tmp_path / "agent_a" / "data")],
            delete_paths=[],
        ),
        "agent-b": AgentFilesystemConfig(
            agent_id="agent-b",
            workspace=str(tmp_path / "agent_b"),
            read_paths=[str(tmp_path / "agent_b" / "data")],
            write_paths=[str(tmp_path / "agent_b" / "data")],
            delete_paths=[],
        ),
    }
    return reg


@pytest.fixture
def isolated_gateway(multi_agent_registry):
    return LocalFilesystemGateway(scope_registry=multi_agent_registry)


class TestCrossAgentIsolation:
    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_agent_a_cannot_read_agent_b_files(self, isolated_gateway, tmp_path):
        b_file = tmp_path / "agent_b" / "data" / "b_secret.txt"
        req = FileReadRequest(
            agent_id="agent-a",
            tool_name="file_access",
            operation="read",
            file_path=str(b_file),
        )
        resp = await isolated_gateway.read_file(req)
        assert resp.decision == SecurityDecision.DENY, (
            "Agent A must not access Agent B's files"
        )

    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_agent_b_cannot_read_agent_a_files(self, isolated_gateway, tmp_path):
        a_file = tmp_path / "agent_a" / "data" / "a_secret.txt"
        req = FileReadRequest(
            agent_id="agent-b",
            tool_name="file_access",
            operation="read",
            file_path=str(a_file),
        )
        resp = await isolated_gateway.read_file(req)
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_agent_can_read_own_files(self, isolated_gateway, tmp_path):
        a_file = tmp_path / "agent_a" / "data" / "a_secret.txt"
        req = FileReadRequest(
            agent_id="agent-a",
            tool_name="file_access",
            operation="read",
            file_path=str(a_file),
        )
        resp = await isolated_gateway.read_file(req)
        assert resp.decision == SecurityDecision.ALLOW

    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_traversal_to_other_agent_blocked(self, isolated_gateway, tmp_path):
        """Agent A tries to use traversal to reach Agent B's workspace."""
        traversal = str(tmp_path / "agent_a" / "data" / ".." / ".." / "agent_b" / "data" / "b_secret.txt")
        req = FileReadRequest(
            agent_id="agent-a",
            tool_name="file_access",
            operation="read",
            file_path=traversal,
        )
        resp = await isolated_gateway.read_file(req)
        assert resp.decision == SecurityDecision.DENY
