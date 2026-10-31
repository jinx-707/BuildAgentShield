"""
AgentShield Offline — Local Filesystem Gateway.

The single enforcement point for all local file access operations.
Every operation is validated before touching the filesystem.
"""

from __future__ import annotations

import structlog

from app.capabilities.offline.local_files.directory_scopes import DirectoryScopeRegistry
from app.capabilities.offline.local_files.permissions import PermissionChecker
from app.capabilities.offline.local_files import safe_operations as sops
from app.core.contracts import (
    BaseOfflineResponse,
    FileCopyRequest,
    FileCreateRequest,
    FileDeleteRequest,
    FileListRequest,
    FileMoveRequest,
    FileOperation,
    FileReadRequest,
    FileSearchRequest,
    FileUpdateRequest,
    OfflineModule,
    RiskLevel,
)
from app.core.decisions import allow_response, deny_response
from app.core.exceptions import (
    PathTraversalError,
    SymlinkEscapeError,
    WorkspaceEscapeError,
    FileOperationError,
)

log = structlog.get_logger(__name__)
_MODULE = OfflineModule.LOCAL_FILE_ACCESS


class LocalFilesystemGateway:
    """
    Enforces directory-scoped, operation-level file access for agents.
    """

    def __init__(self, scope_registry: DirectoryScopeRegistry) -> None:
        self._checker = PermissionChecker(scope_registry)

    # ---- Read ----

    async def read_file(self, request: FileReadRequest) -> BaseOfflineResponse:
        try:
            resolved = self._checker.validate_and_resolve(
                request.file_path, request.agent_id, FileOperation.READ
            )
            self._checker.check_file_size(resolved, request.agent_id)
            if not resolved.is_file():
                return deny_response(
                    request_id=request.request_id,
                    module=_MODULE,
                    tool=request.tool_name,
                    reason=f"Path is not a file: {resolved}",
                    risk_level=RiskLevel.LOW,
                )
            content = await sops.safe_read_file(
                resolved,
                encoding=request.encoding,
                max_bytes=request.max_bytes,
            )
            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                result={"path": str(resolved), "content": content, "size": len(content)},
            )
        except (PathTraversalError, SymlinkEscapeError, WorkspaceEscapeError) as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("read_file_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason="File read failed",
                risk_level=RiskLevel.MEDIUM,
            )

    # ---- Search ----

    async def search_files(self, request: FileSearchRequest) -> BaseOfflineResponse:
        try:
            resolved_dir = self._checker.validate_and_resolve(
                request.directory, request.agent_id, FileOperation.SEARCH
            )
            if not resolved_dir.is_dir():
                return deny_response(
                    request_id=request.request_id,
                    module=_MODULE,
                    tool=request.tool_name,
                    reason="Search path is not a directory",
                    risk_level=RiskLevel.LOW,
                )
            results = sops.search_files(
                resolved_dir,
                request.pattern,
                recursive=request.recursive,
                max_results=request.max_results,
            )
            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                result={"directory": str(resolved_dir), "matches": results, "count": len(results)},
            )
        except (PathTraversalError, SymlinkEscapeError, WorkspaceEscapeError) as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("search_files_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason="File search failed",
                risk_level=RiskLevel.MEDIUM,
            )

    # ---- List directory ----

    async def list_directory(self, request: FileListRequest) -> BaseOfflineResponse:
        try:
            resolved_dir = self._checker.validate_and_resolve(
                request.directory, request.agent_id, FileOperation.LIST
            )
            if not resolved_dir.is_dir():
                return deny_response(
                    request_id=request.request_id,
                    module=_MODULE,
                    tool=request.tool_name,
                    reason="Path is not a directory",
                    risk_level=RiskLevel.LOW,
                )
            entries = sops.list_directory(resolved_dir)
            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                result={"directory": str(resolved_dir), "entries": entries},
            )
        except (PathTraversalError, SymlinkEscapeError, WorkspaceEscapeError) as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )

    # ---- Create ----

    async def create_file(self, request: FileCreateRequest) -> BaseOfflineResponse:
        try:
            resolved = self._checker.validate_and_resolve(
                request.file_path, request.agent_id, FileOperation.CREATE
            )
            if resolved.exists():
                return deny_response(
                    request_id=request.request_id,
                    module=_MODULE,
                    tool=request.tool_name,
                    reason="File already exists; use update instead",
                    risk_level=RiskLevel.LOW,
                )
            await sops.safe_write_file(resolved, request.content, request.encoding)
            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                result={"path": str(resolved), "created": True},
            )
        except (PathTraversalError, SymlinkEscapeError, WorkspaceEscapeError) as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("create_file_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason="File creation failed",
                risk_level=RiskLevel.MEDIUM,
            )

    # ---- Update ----

    async def update_file(self, request: FileUpdateRequest) -> BaseOfflineResponse:
        try:
            resolved = self._checker.validate_and_resolve(
                request.file_path, request.agent_id, FileOperation.WRITE
            )
            await sops.safe_write_file(resolved, request.content, request.encoding)
            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                result={"path": str(resolved), "updated": True},
            )
        except (PathTraversalError, SymlinkEscapeError, WorkspaceEscapeError) as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("update_file_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason="File update failed",
                risk_level=RiskLevel.MEDIUM,
            )

    # ---- Delete ----

    async def delete_file(self, request: FileDeleteRequest) -> BaseOfflineResponse:
        try:
            resolved = self._checker.validate_and_resolve(
                request.file_path, request.agent_id, FileOperation.DELETE
            )
            if not resolved.exists():
                return deny_response(
                    request_id=request.request_id,
                    module=_MODULE,
                    tool=request.tool_name,
                    reason="File does not exist",
                    risk_level=RiskLevel.LOW,
                )
            await sops.safe_delete_file(resolved)
            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                result={"path": str(resolved), "deleted": True},
            )
        except (PathTraversalError, SymlinkEscapeError, WorkspaceEscapeError) as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("delete_file_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason="File delete failed",
                risk_level=RiskLevel.MEDIUM,
            )

    # ---- Move ----

    async def move_file(self, request: FileMoveRequest) -> BaseOfflineResponse:
        try:
            src = self._checker.validate_and_resolve(
                request.source_path, request.agent_id, FileOperation.MOVE
            )
            dst = self._checker.validate_and_resolve(
                request.destination_path, request.agent_id, FileOperation.CREATE
            )
            await sops.safe_move_file(src, dst)
            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                result={"source": str(src), "destination": str(dst)},
            )
        except (PathTraversalError, SymlinkEscapeError, WorkspaceEscapeError) as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("move_file_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason="File move failed",
                risk_level=RiskLevel.MEDIUM,
            )

    # ---- Copy ----

    async def copy_file(self, request: FileCopyRequest) -> BaseOfflineResponse:
        try:
            src = self._checker.validate_and_resolve(
                request.source_path, request.agent_id, FileOperation.COPY
            )
            dst = self._checker.validate_and_resolve(
                request.destination_path, request.agent_id, FileOperation.CREATE
            )
            await sops.safe_copy_file(src, dst)
            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                result={"source": str(src), "destination": str(dst)},
            )
        except (PathTraversalError, SymlinkEscapeError, WorkspaceEscapeError) as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("copy_file_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason="File copy failed",
                risk_level=RiskLevel.MEDIUM,
            )
