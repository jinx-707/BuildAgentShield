"""
AgentShield Offline — Terminal Execution Gateway.
"""

from __future__ import annotations

import structlog

from app.capabilities.offline.terminal.execution_worker import ExecutionWorker
from app.core.contracts import (
    BaseOfflineResponse,
    CommandExecutionResult,
    CommandRequest,
    OfflineModule,
    RiskLevel,
)
from app.core.decisions import allow_response, deny_response, unavailable_response
from app.core.exceptions import (
    CommandDeniedError,
    InspectorUnavailableError,
    SandboxUnavailableError,
)

log = structlog.get_logger(__name__)
_MODULE = OfflineModule.TERMINAL_EXECUTION
_TOOL = "terminal_execute"


class TerminalGateway:
    """
    Single enforcement point for all terminal command execution.
    """

    def __init__(self, worker: ExecutionWorker) -> None:
        self._worker = worker

    async def execute(self, request: CommandRequest) -> BaseOfflineResponse:
        try:
            result = await self._worker.run(
                executable=request.executable,
                arguments=request.arguments,
                working_directory=request.working_directory,
                agent_id=request.agent_id,
                timeout=request.timeout,
                environment=request.environment,
            )

            execution_result = CommandExecutionResult(
                execution_id=result.execution_id,
                executable=request.executable,
                arguments=request.arguments,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_seconds=result.duration_seconds,
                output_truncated=result.output_truncated,
                sandbox_used=True,
                timed_out=result.timed_out,
            )

            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                execution_id=result.execution_id,
                result=execution_result.model_dump(),
                risk_level=RiskLevel.MEDIUM,
            )

        except CommandDeniedError as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )

        except SandboxUnavailableError as exc:
            log.error("sandbox_unavailable", error=str(exc))
            return unavailable_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason="Sandbox unavailable — command execution denied",
            )

        except InspectorUnavailableError as exc:
            log.error("inspector_unavailable", error=str(exc))
            return unavailable_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason="Output inspector unavailable — result withheld",
            )

        except Exception as exc:  # noqa: BLE001
            log.error("terminal_gateway_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason="Terminal execution failed",
                risk_level=RiskLevel.HIGH,
            )
