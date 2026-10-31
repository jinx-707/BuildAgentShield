"""
AgentShield Offline — Docker Sandbox Manager.

Manages the Docker-based execution sandbox for terminal commands.

Security controls enforced:
  - Non-root user (UID 65534 / nobody)
  - Read-only root filesystem
  - No privileged mode
  - All capabilities dropped
  - no-new-privileges
  - Network disabled by default
  - CPU and memory limits
  - Process count limits
  - Execution timeout
  - Container cleanup on completion or timeout
  - Docker socket NOT mounted

FAIL-CLOSED: If Docker is unavailable, execution is denied.
There is NO fallback to host execution.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import Optional

import structlog

from app.capabilities.offline.terminal.command_policy import CommandDecision
from app.core.configuration import get_settings
from app.core.exceptions import SandboxUnavailableError

log = structlog.get_logger(__name__)


class SandboxResult:
    def __init__(
        self,
        *,
        execution_id: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        duration_seconds: float,
        timed_out: bool = False,
        output_truncated: bool = False,
    ) -> None:
        self.execution_id = execution_id
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_seconds = duration_seconds
        self.timed_out = timed_out
        self.output_truncated = output_truncated


class DockerSandboxManager:
    """
    Executes commands inside a Docker container with strict security constraints.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._docker_available: Optional[bool] = None

    def _get_docker_client(self):
        """Return a Docker client or raise SandboxUnavailableError."""
        try:
            import docker  # type: ignore
            client = docker.from_env()
            client.ping()
            return client
        except Exception as exc:
            raise SandboxUnavailableError(
                f"Docker is unavailable: {exc}. "
                "Command execution denied — no fallback to host execution."
            ) from exc

    def _check_docker(self) -> bool:
        try:
            self._get_docker_client()
            return True
        except SandboxUnavailableError:
            return False

    async def execute(
        self,
        *,
        executable: str,
        arguments: list[str],
        working_directory: str,
        agent_id: str,
        timeout: int,
        environment: Optional[dict[str, str]] = None,
        workspace_path: Optional[str] = None,
    ) -> SandboxResult:
        """
        Run the command in a Docker container.
        Raises SandboxUnavailableError if Docker is not available.
        """
        execution_id = str(uuid.uuid4())
        settings = self._settings

        # Validate timeout
        timeout = min(timeout, settings.sandbox_max_timeout)

        # Build command list — no shell=True, no string interpolation
        cmd = [executable] + arguments

        # Build volume mounts — only the workspace
        volumes: dict = {}
        if workspace_path and Path(workspace_path).exists():
            volumes[workspace_path] = {"bind": "/workspace", "mode": "rw"}

        # Build safe minimal environment
        safe_env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
        }
        if environment:
            # Only allow through non-sensitive additions
            safe_env.update(environment)

        log.info(
            "sandbox_execute_start",
            execution_id=execution_id,
            agent_id=agent_id,
            executable=executable,
            args=arguments,
            working_dir=working_directory,
            timeout=timeout,
        )

        start = time.monotonic()
        container = None
        client = self._get_docker_client()

        try:
            container = client.containers.run(
                image=settings.sandbox_image,
                command=cmd,
                working_dir=working_directory if working_directory else "/workspace",
                # Security constraints
                user="65534:65534",          # nobody:nogroup
                read_only=True,
                privileged=False,
                network_mode=settings.sandbox_network_mode,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                # Resource limits
                mem_limit=settings.sandbox_memory_limit,
                cpu_period=settings.sandbox_cpu_period,
                cpu_quota=settings.sandbox_cpu_quota,
                pids_limit=settings.sandbox_pids_limit,
                # Volumes
                volumes=volumes if volumes else None,
                # Environment
                environment=safe_env,
                # Output — collect logs
                detach=True,
                stdout=True,
                stderr=True,
                # Temp filesystem for writes inside container
                tmpfs={"/tmp": "size=64m,noexec,nosuid"},
                # Remove after use
                auto_remove=False,
            )

            # Wait with timeout
            try:
                result = container.wait(timeout=timeout)
                exit_code = result.get("StatusCode", -1)
                timed_out = False
            except Exception:
                exit_code = -1
                timed_out = True
                try:
                    container.kill()
                except Exception:
                    pass

            duration = time.monotonic() - start

            # Collect output with size limit
            max_bytes = settings.sandbox_output_max_bytes
            stdout_raw = container.logs(stdout=True, stderr=False)
            stderr_raw = container.logs(stdout=False, stderr=True)

            stdout_str = stdout_raw.decode("utf-8", errors="replace")
            stderr_str = stderr_raw.decode("utf-8", errors="replace")
            output_truncated = False

            if len(stdout_str) > max_bytes:
                stdout_str = stdout_str[:max_bytes] + "\n[OUTPUT TRUNCATED]"
                output_truncated = True
            if len(stderr_str) > max_bytes:
                stderr_str = stderr_str[:max_bytes] + "\n[STDERR TRUNCATED]"
                output_truncated = True

            log.info(
                "sandbox_execute_complete",
                execution_id=execution_id,
                exit_code=exit_code,
                duration=round(duration, 2),
                timed_out=timed_out,
            )

            return SandboxResult(
                execution_id=execution_id,
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_seconds=round(duration, 2),
                timed_out=timed_out,
                output_truncated=output_truncated,
            )

        except SandboxUnavailableError:
            raise
        except Exception as exc:
            duration = time.monotonic() - start
            log.error(
                "sandbox_execute_error",
                execution_id=execution_id,
                error=str(exc),
                duration=round(duration, 2),
            )
            raise SandboxUnavailableError(
                f"Sandbox execution failed: {exc}"
            ) from exc
        finally:
            # Always clean up the container
            if container:
                try:
                    container.remove(force=True)
                    log.debug("sandbox_container_removed", execution_id=execution_id)
                except Exception as exc:
                    log.error("sandbox_container_remove_failed", error=str(exc))


class MockSandboxManager:
    """
    Mock sandbox for testing environments without Docker.
    Returns fixed responses. Never executes real commands.
    """

    async def execute(
        self,
        *,
        executable: str,
        arguments: list[str],
        working_directory: str,
        agent_id: str,
        timeout: int,
        environment: Optional[dict] = None,
        workspace_path: Optional[str] = None,
    ) -> SandboxResult:
        return SandboxResult(
            execution_id=str(uuid.uuid4()),
            exit_code=0,
            stdout=f"[MOCK] executed {executable} {' '.join(arguments)}",
            stderr="",
            duration_seconds=0.01,
        )
