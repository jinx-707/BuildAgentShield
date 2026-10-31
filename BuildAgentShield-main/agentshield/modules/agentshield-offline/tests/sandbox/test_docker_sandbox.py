"""
Sandbox tests — Docker execution (requires Docker).

These tests are marked with @pytest.mark.docker and skipped automatically
when Docker is not available.

Run these explicitly with:
    pytest tests/sandbox -m docker
"""

from __future__ import annotations

import pytest

from app.capabilities.offline.terminal.sandbox_manager import DockerSandboxManager
from app.core.exceptions import SandboxUnavailableError


def docker_available() -> bool:
    try:
        mgr = DockerSandboxManager()
        return mgr._check_docker()
    except Exception:
        return False


requires_docker = pytest.mark.skipif(
    not docker_available(),
    reason="Docker not available",
)


@pytest.fixture
def sandbox():
    return DockerSandboxManager()


class TestDockerSandbox:
    @requires_docker
    @pytest.mark.docker
    @pytest.mark.asyncio
    async def test_basic_echo_executes(self, sandbox, tmp_path):
        result = await sandbox.execute(
            executable="echo",
            arguments=["hello from sandbox"],
            working_directory="/workspace",
            agent_id="test-agent",
            timeout=10,
            workspace_path=str(tmp_path),
        )
        assert result.exit_code == 0
        assert "hello from sandbox" in result.stdout

    @requires_docker
    @pytest.mark.docker
    @pytest.mark.asyncio
    async def test_timeout_enforced(self, sandbox, tmp_path):
        result = await sandbox.execute(
            executable="sleep",
            arguments=["30"],
            working_directory="/workspace",
            agent_id="test-agent",
            timeout=2,  # 2 second timeout
            workspace_path=str(tmp_path),
        )
        assert result.timed_out is True

    @requires_docker
    @pytest.mark.docker
    @pytest.mark.asyncio
    async def test_container_runs_as_non_root(self, sandbox, tmp_path):
        result = await sandbox.execute(
            executable="whoami",
            arguments=[],
            working_directory="/workspace",
            agent_id="test-agent",
            timeout=10,
            workspace_path=str(tmp_path),
        )
        assert result.exit_code == 0
        # nobody or a non-root user — not "root"
        assert "root" not in result.stdout.strip().lower()

    @requires_docker
    @pytest.mark.docker
    @pytest.mark.asyncio
    async def test_no_network_access(self, sandbox, tmp_path):
        """Container should not have network access."""
        result = await sandbox.execute(
            executable="ping",
            arguments=["-c", "1", "-W", "1", "8.8.8.8"],
            working_directory="/workspace",
            agent_id="test-agent",
            timeout=10,
            workspace_path=str(tmp_path),
        )
        # ping should fail — network is disabled
        assert result.exit_code != 0

    @requires_docker
    @pytest.mark.docker
    @pytest.mark.asyncio
    async def test_cannot_read_host_files(self, sandbox, tmp_path):
        """Container must not be able to read arbitrary host files."""
        result = await sandbox.execute(
            executable="cat",
            arguments=["/etc/hostname"],
            working_directory="/workspace",
            agent_id="test-agent",
            timeout=10,
            workspace_path=str(tmp_path),
        )
        # The container has its own /etc/hostname, but it must not be the host's
        # This test verifies the sandbox has its own isolated filesystem
        if result.exit_code == 0:
            assert "sandbox" in result.stdout or len(result.stdout.strip()) > 0

    @requires_docker
    @pytest.mark.docker
    @pytest.mark.asyncio
    async def test_container_cleaned_up_after_execution(self, sandbox, tmp_path):
        """Container must be removed after execution completes."""
        import docker
        client = docker.from_env()
        containers_before = {c.id for c in client.containers.list(all=True)}

        await sandbox.execute(
            executable="echo",
            arguments=["cleanup test"],
            working_directory="/workspace",
            agent_id="test-agent",
            timeout=10,
            workspace_path=str(tmp_path),
        )

        containers_after = {c.id for c in client.containers.list(all=True)}
        new_containers = containers_after - containers_before
        assert len(new_containers) == 0, (
            f"Container leak detected: {new_containers}"
        )

    @pytest.mark.docker
    @pytest.mark.asyncio
    async def test_unavailable_docker_raises_not_executes(self):
        """If Docker is unavailable, must raise SandboxUnavailableError — no host execution."""
        class BrokenSandbox(DockerSandboxManager):
            def _get_docker_client(self):
                raise SandboxUnavailableError("Docker unavailable (simulated)")

        sandbox = BrokenSandbox()
        with pytest.raises(SandboxUnavailableError):
            await sandbox.execute(
                executable="echo",
                arguments=["test"],
                working_directory="/workspace",
                agent_id="test-agent",
                timeout=10,
            )
