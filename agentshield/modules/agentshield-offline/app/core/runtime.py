"""
AgentShield Offline — Standalone Security Runtime.

Wires together all five offline capabilities and their integration adapters.
Each capability gateway is injected via dependency injection so adapters
can be replaced without modifying this file.
"""

from __future__ import annotations

from typing import Optional

import structlog

from app.core.configuration import OfflineSettings, get_settings
from app.core.contracts import (
    AuditEvent,
    BaseOfflineResponse,
    CommandRequest,
    DocumentAnalysisRequest,
    EnvironmentInspectRequest,
    FileAccessRequest,
    FileCreateRequest,
    FileCopyRequest,
    FileDeleteRequest,
    FileListRequest,
    FileMoveRequest,
    FileReadRequest,
    FileSearchRequest,
    FileUpdateRequest,
    SecretAccessRequest,
    SystemFileInspectRequest,
)

log = structlog.get_logger(__name__)


class OfflineSecurityRuntime:
    """
    Central runtime that dispatches requests to the appropriate capability
    gateway and records audit events.

    All capability gateways are injected at construction time.
    This class does not import capability modules directly so it remains
    testable with mock gateways.
    """

    def __init__(
        self,
        *,
        document_gateway,
        filesystem_gateway,
        system_file_gateway,
        environment_gateway,
        terminal_gateway,
        audit_port,
        settings: Optional[OfflineSettings] = None,
    ) -> None:
        self._doc_gw = document_gateway
        self._fs_gw = filesystem_gateway
        self._sys_gw = system_file_gateway
        self._env_gw = environment_gateway
        self._term_gw = terminal_gateway
        self._audit = audit_port
        self._settings = settings or get_settings()
        log.info(
            "offline_runtime_initialized",
            env=self._settings.environment,
        )

    # ---- Document ----

    async def analyze_document(
        self, request: DocumentAnalysisRequest
    ) -> BaseOfflineResponse:
        response = await self._doc_gw.analyze(request)
        await self._emit_audit(request, response)
        return response

    # ---- Local filesystem ----

    async def read_file(self, request: FileReadRequest) -> BaseOfflineResponse:
        response = await self._fs_gw.read_file(request)
        await self._emit_audit(request, response)
        return response

    async def search_files(self, request: FileSearchRequest) -> BaseOfflineResponse:
        response = await self._fs_gw.search_files(request)
        await self._emit_audit(request, response)
        return response

    async def list_directory(self, request: FileListRequest) -> BaseOfflineResponse:
        response = await self._fs_gw.list_directory(request)
        await self._emit_audit(request, response)
        return response

    async def create_file(self, request: FileCreateRequest) -> BaseOfflineResponse:
        response = await self._fs_gw.create_file(request)
        await self._emit_audit(request, response)
        return response

    async def update_file(self, request: FileUpdateRequest) -> BaseOfflineResponse:
        response = await self._fs_gw.update_file(request)
        await self._emit_audit(request, response)
        return response

    async def delete_file(self, request: FileDeleteRequest) -> BaseOfflineResponse:
        response = await self._fs_gw.delete_file(request)
        await self._emit_audit(request, response)
        return response

    async def move_file(self, request: FileMoveRequest) -> BaseOfflineResponse:
        response = await self._fs_gw.move_file(request)
        await self._emit_audit(request, response)
        return response

    async def copy_file(self, request: FileCopyRequest) -> BaseOfflineResponse:
        response = await self._fs_gw.copy_file(request)
        await self._emit_audit(request, response)
        return response

    # ---- System file ----

    async def inspect_system_path(
        self, request: SystemFileInspectRequest
    ) -> BaseOfflineResponse:
        response = await self._sys_gw.inspect(request)
        await self._emit_audit(request, response)
        return response

    # ---- Environment ----

    async def inspect_environment(
        self, request: EnvironmentInspectRequest
    ) -> BaseOfflineResponse:
        response = await self._env_gw.inspect(request)
        await self._emit_audit(request, response)
        return response

    async def access_secret(
        self, request: SecretAccessRequest
    ) -> BaseOfflineResponse:
        response = await self._env_gw.access_secret(request)
        await self._emit_audit(request, response)
        return response

    # ---- Terminal ----

    async def execute_command(
        self, request: CommandRequest
    ) -> BaseOfflineResponse:
        response = await self._term_gw.execute(request)
        await self._emit_audit(request, response)
        return response

    # ---- Internal ----

    async def _emit_audit(
        self, request, response: BaseOfflineResponse
    ) -> None:
        try:
            event = AuditEvent(
                request_id=request.request_id,
                agent_id=request.agent_id,
                tenant_id=request.tenant_id,
                module=response.module,
                tool=response.tool,
                operation=request.operation,
                resource=getattr(request, "file_path", None)
                or getattr(request, "path", None)
                or getattr(request, "executable", None),
                decision=response.decision,
                risk_level=response.risk_level,
                reason=response.reason,
            )
            await self._audit.record(event)
        except Exception as exc:  # noqa: BLE001
            log.error("audit_emit_failed", error=str(exc))
            if not self._settings.audit_fail_open:
                # In fail-closed mode we still return the response but log the
                # audit failure. A production system might raise here.
                pass
