"""
AgentShield Offline — System File Access Gateway.

Every request to inspect a system path flows through this gateway.
"""

from __future__ import annotations

import structlog

from app.capabilities.offline.system_files.access_monitor import SystemFileAccessMonitor
from app.capabilities.offline.system_files.path_validator import PathValidator
from app.capabilities.offline.system_files.protected_paths import ProtectedPathRegistry
from app.core.contracts import (
    BaseOfflineResponse,
    OfflineModule,
    RiskLevel,
    SecurityDecision,
    SystemFileInspectRequest,
)
from app.core.decisions import allow_response, deny_response
from app.core.exceptions import (
    PathTraversalError,
    ProtectedPathError,
    SymlinkEscapeError,
)

log = structlog.get_logger(__name__)

_MODULE = OfflineModule.SYSTEM_FILE_ACCESS
_TOOL = "system_file_inspect"


class SystemFileGateway:
    """
    Enforces protected-path access controls.
    """

    def __init__(self) -> None:
        self._registry = ProtectedPathRegistry()
        self._validator = PathValidator(self._registry)
        self._monitor = SystemFileAccessMonitor()

    async def inspect(
        self, request: SystemFileInspectRequest
    ) -> BaseOfflineResponse:
        try:
            resolved = self._validator.validate(request.path, request.agent_id)
        except (PathTraversalError, ProtectedPathError, SymlinkEscapeError) as exc:
            self._monitor.record(
                agent_id=request.agent_id,
                resource=request.path,
                access_type=request.access_type,
                decision=SecurityDecision.DENY,
                denial_reason=str(exc),
                request_id=request.request_id,
            )
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("system_file_gateway_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason="Internal validation error",
                risk_level=RiskLevel.HIGH,
            )

        self._monitor.record(
            agent_id=request.agent_id,
            resource=str(resolved),
            access_type=request.access_type,
            decision=SecurityDecision.ALLOW,
            request_id=request.request_id,
        )
        return allow_response(
            request_id=request.request_id,
            module=_MODULE,
            tool=_TOOL,
            result={
                "path": str(resolved),
                "exists": resolved.exists(),
                "is_file": resolved.is_file(),
                "is_dir": resolved.is_dir(),
            },
            risk_level=RiskLevel.LOW,
        )
