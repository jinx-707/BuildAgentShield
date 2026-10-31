"""
AgentShield Offline — Execution Worker.

Coordinates the full command execution flow:
  1. Parse and validate the command structure.
  2. Evaluate against command policy.
  3. Execute in sandbox (fail-closed if unavailable).
  4. Inspect and redact output.
  5. Return structured result.
"""

from __future__ import annotations

from typing import Optional

import structlog

from app.capabilities.offline.terminal.command_parser import CommandParser
from app.capabilities.offline.terminal.command_policy import CommandDecision, CommandPolicy
from app.capabilities.offline.terminal.output_inspector import TerminalOutputInspector
from app.capabilities.offline.terminal.sandbox_manager import DockerSandboxManager, SandboxResult
from app.core.exceptions import (
    CommandDeniedError,
    SandboxUnavailableError,
)

log = structlog.get_logger(__name__)


class ExecutionWorker:
    """
    Orchestrates command validation, sandbox execution, and output inspection.
    """

    def __init__(
        self,
        policy: CommandPolicy,
        sandbox: DockerSandboxManager,
        output_inspector: TerminalOutputInspector,
        workspace: str = "/workspace",
    ) -> None:
        self._parser = CommandParser()
        self._policy = policy
        self._sandbox = sandbox
        self._output_inspector = output_inspector
        self._workspace = workspace

    async def run(
        self,
        *,
        executable: str,
        arguments: list[str],
        working_directory: str,
        agent_id: str,
        timeout: int,
        environment: Optional[dict] = None,
    ) -> SandboxResult:
        """
        Validate → evaluate policy → execute in sandbox → inspect output.
        Raises CommandDeniedError or SandboxUnavailableError on failure.
        """
        # Step 1: Structural validation
        self._parser.validate(executable, arguments, working_directory)

        # Step 2: Policy evaluation
        decision, reason = self._policy.evaluate(executable, arguments)
        if decision == CommandDecision.DENY:
            log.warning(
                "command_denied_by_policy",
                executable=executable,
                reason=reason,
                agent_id=agent_id,
            )
            raise CommandDeniedError(
                f"Command denied: {reason}", executable=executable
            )

        log.info(
            "command_policy_decision",
            executable=executable,
            decision=decision.value,
            agent_id=agent_id,
        )

        # Step 3: Sandbox execution
        result = await self._sandbox.execute(
            executable=executable,
            arguments=arguments,
            working_directory=working_directory,
            agent_id=agent_id,
            timeout=timeout,
            environment=environment,
            workspace_path=self._workspace,
        )

        # Step 4: Output inspection and redaction
        clean_stdout, clean_stderr, findings = (
            await self._output_inspector.inspect_and_redact(
                result.stdout,
                result.stderr,
                agent_id=agent_id,
                execution_id=result.execution_id,
            )
        )

        result.stdout = clean_stdout
        result.stderr = clean_stderr

        return result
