from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

from .adapters import AdapterError, AdapterRegistry
from .config import Settings
from .contracts import AdapterResult, AuthContext, ToolRequest
from .teammate_loader import load_p2


OFFLINE_TOOL_PERMISSIONS = {
    "read_document": "documents.read",
    "read_file": "local_files.read",
    "read_system_file": "system_files.read",
    "read_env_var": "environment.read",
    "run_command": "terminal.run",
    "delete_file": "files.delete",
}

_WORKSPACE_PREFIX = "workspace"
_VIRTUAL_WORKSPACE_PREFIX = "/workspace"
_FORBIDDEN_COMMAND_CHARS = set("\x00\n\r;|&<>`$()")
_DENIED_FILE_EXTENSIONS = [
    ".exe",
    ".dll",
    ".so",
    ".sh",
    ".bat",
    ".cmd",
    ".ps1",
    ".env",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
]


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _map_workspace_path(raw: str, workspace: Path) -> Path:
    text = raw.strip()
    if not text:
        raise AdapterError("path is empty")
    if "\x00" in text:
        raise AdapterError("path contains a null byte")
    if "://" in text:
        raise AdapterError("URL paths are not accepted by the offline gateway")
    normalized = text.replace("\\", "/")
    lower = normalized.lower()
    if lower == _WORKSPACE_PREFIX or lower.startswith(f"{_WORKSPACE_PREFIX}/"):
        relative = normalized[len(_WORKSPACE_PREFIX) :].lstrip("/")
        return workspace / relative
    if lower == _VIRTUAL_WORKSPACE_PREFIX or lower.startswith(
        f"{_VIRTUAL_WORKSPACE_PREFIX}/"
    ):
        relative = normalized[len(_VIRTUAL_WORKSPACE_PREFIX) :].lstrip("/")
        return workspace / relative
    candidate = Path(text)
    if candidate.is_absolute():
        return candidate
    return workspace / candidate


def _authorized_file(raw: str, workspace: Path, roots: list[Path]) -> Path:
    mapped = _map_workspace_path(raw, workspace)
    if any(part == ".." for part in Path(mapped).parts):
        raise AdapterError("path traversal is not permitted")
    resolved = mapped.resolve()
    if not roots or not any(_within(resolved, root) for root in roots):
        raise AdapterError("path is outside the agent's authorized workspace scope")
    return resolved


def _scope_roots(auth: AuthContext, workspace: Path) -> list[Path]:
    configured = auth.scopes.get("allowed_paths")
    if not configured:
        return []
    roots: list[Path] = []
    for item in configured:
        if not isinstance(item, str) or not item.strip():
            continue
        try:
            mapped = _map_workspace_path(item, workspace)
        except AdapterError:
            continue
        if any(part == ".." for part in Path(mapped).parts):
            continue
        resolved = mapped.resolve()
        if _within(resolved, workspace) and resolved not in roots:
            roots.append(resolved)
    return roots


class _ScopeRegistry:
    def __init__(
        self,
        config_cls: Any,
        file_operation: Any,
        *,
        agent_id: str,
        workspace: Path,
        read_roots: list[Path],
        delete_roots: list[Path],
        max_file_size_bytes: int,
    ) -> None:
        self._file_operation = file_operation
        self._config = config_cls(
            agent_id=agent_id,
            workspace=str(workspace),
            read_paths=[str(path) for path in read_roots],
            write_paths=[],
            delete_paths=[str(path) for path in delete_roots],
            allowed_extensions=[],
            denied_extensions=list(_DENIED_FILE_EXTENSIONS),
            max_file_size_bytes=max_file_size_bytes,
        )

    def get_config(self, agent_id: str) -> Any:
        if agent_id == self._config.agent_id:
            return self._config
        return None

    def get_permitted_dirs(self, agent_id: str, operation: Any) -> list[Path]:
        if agent_id != self._config.agent_id:
            return []
        read_ops = {
            self._file_operation.READ,
            self._file_operation.SEARCH,
            self._file_operation.LIST,
            self._file_operation.COPY,
        }
        if operation in read_ops:
            return [Path(path).resolve() for path in self._config.read_paths]
        if operation == self._file_operation.DELETE:
            return [Path(path).resolve() for path in self._config.delete_paths]
        return []


class _DataRedactor:
    _patterns = [
        ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
        (
            "private_key",
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        ),
        (
            "jwt",
            re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        ),
        ("openai_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
        (
            "generic_password",
            re.compile(
                r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*\S{6,}"
            ),
        ),
    ]

    def __init__(self, result_cls: Any) -> None:
        self._result_cls = result_cls

    async def inspect(
        self, content: str, *, context: dict[str, Any] | None = None
    ) -> Any:
        redacted = content
        findings: list[dict[str, Any]] = []
        for category, pattern in self._patterns:
            if pattern.search(redacted):
                findings.append(
                    {
                        "category": category,
                        "description": f"Potential {category} detected in terminal output",
                    }
                )
                redacted = pattern.sub("[REDACTED]", redacted)
        return self._result_cls(
            passed=not findings,
            redacted_content=redacted if findings else None,
            findings=findings,
            inspector="p2_bridge_data_redactor",
        )


class P2OfflineAdapter:
    name = "p2_offline_gateways"
    capability = "offline"
    tool_names = set(OFFLINE_TOOL_PERMISSIONS)

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()
        self._workspace = self._resolve_dir(
            self.settings.p2_workspace_root, Path.cwd() / "workspace"
        )
        self._workspace.mkdir(parents=True, exist_ok=True)
        quarantine = (
            Path(self.settings.p2_quarantine_dir).expanduser()
            if self.settings.p2_quarantine_dir
            else self._workspace.parent / "quarantine"
        )
        if not quarantine.is_absolute():
            quarantine = Path.cwd() / quarantine
        self._quarantine = quarantine.resolve()
        self._quarantine.mkdir(parents=True, exist_ok=True)

        self._modules = load_p2(self.settings)
        self._contracts = self._modules["contracts"]
        self._configure_p2_settings()
        self._build_cached_gateways()
        self._denied_extensions = list(_DENIED_FILE_EXTENSIONS)
        self._max_file_size_bytes = self.settings.p2_max_file_size_bytes
        self._max_read_bytes = self.settings.p2_max_read_bytes

    @staticmethod
    def _resolve_dir(configured: str, default: Path) -> Path:
        path = Path(configured).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        return path.resolve()

    def _configure_p2_settings(self) -> None:
        p2_settings = self._modules["configuration"].get_settings()
        p2_settings.default_workspace = str(self._workspace)
        p2_settings.quarantine_dir = str(self._quarantine)
        p2_settings.clamav_fail_closed = self.settings.p2_clamav_fail_closed

    def _build_cached_gateways(self) -> None:
        inspector = self._modules["document_inspector"].DocumentInspector(
            self._modules["local_content_inspector"].LocalDevelopmentContentInspector(),
            fail_closed=True,
        )
        scanner = self._modules["malware_scanner"].ClamAVScanner(
            fail_closed=self.settings.p2_clamav_fail_closed
        )
        quarantine = self._modules["quarantine"].QuarantineManager(
            quarantine_dir=str(self._quarantine)
        )
        self._document_gateway = self._modules["documents"].DocumentGateway(
            inspector=inspector,
            scanner=scanner,
            quarantine=quarantine,
            fail_closed_on_scan_unavailable=self.settings.p2_clamav_fail_closed,
        )
        self._document_parser = self._modules["document_parser"].DocumentParser()
        self._system_gateway = self._modules["system_files"].SystemFileGateway()

        content_inspector = (
            self._modules["local_content_inspector"].LocalDevelopmentContentInspector()
        )
        data_redactor = _DataRedactor(self._modules["ports"].DataInspectionResult)
        output_inspector = self._modules[
            "terminal_output_inspector"
        ].TerminalOutputInspector(
            content_inspector,
            data_redactor,
            fail_closed=True,
        )
        command_policy = self._modules["command_policy"].CommandPolicy()
        sandbox = self._modules["sandbox_manager"].DockerSandboxManager()
        worker = self._modules["execution_worker"].ExecutionWorker(
            command_policy,
            sandbox,
            output_inspector,
            workspace=str(self._workspace),
        )
        self._terminal_gateway = self._modules["terminal"].TerminalGateway(worker)

    async def healthcheck(self) -> bool:
        return self._workspace.is_dir() and self._quarantine.is_dir()

    @staticmethod
    def _auth_context(auth: AuthContext | None) -> tuple[str, str, set[str]]:
        if auth is None or not auth.agent_id:
            raise AdapterError("authenticated agent identity is required")
        return auth.agent_id, auth.tenant_id, set(auth.permissions)

    def _require_permission(self, tool_name: str, auth: AuthContext | None) -> AuthContext:
        agent_id, _, permissions = self._auth_context(auth)
        required = OFFLINE_TOOL_PERMISSIONS[tool_name]
        if required not in permissions:
            raise AdapterError(
                f"agent {agent_id} lacks the '{required}' permission for {tool_name}"
            )
        assert auth is not None
        return auth

    def _filesystem_gateway(
        self, auth: AuthContext, *, delete: bool = False
    ) -> Any:
        roots = _scope_roots(auth, self._workspace)
        delete_roots = roots if delete and "files.delete" in auth.permissions else []
        registry = _ScopeRegistry(
            self._modules["directory_scopes"].AgentFilesystemConfig,
            self._contracts.FileOperation,
            agent_id=auth.agent_id or "unknown",
            workspace=self._workspace,
            read_roots=roots,
            delete_roots=delete_roots,
            max_file_size_bytes=self._max_file_size_bytes,
        )
        return self._modules["filesystem"].LocalFilesystemGateway(registry)

    def _environment_gateway(self, auth: AuthContext) -> Any:
        policy = self._modules["environment_policy"].EnvironmentPolicy()
        allowed = {
            str(item)
            for item in auth.scopes.get("allowed_env", [])
            if isinstance(item, str)
        }
        policy._global_allowlist = set(policy._global_allowlist) | allowed
        policy._agent_configs.pop(auth.agent_id or "", None)
        guard = self._modules["environment_guard"].EnvironmentGuard(policy)
        provider = self._modules["secret_provider"].MockSecretProvider({})
        broker = self._modules["secret_broker"].SecretBroker(provider, {})
        return self._modules["environment"].EnvironmentGateway(policy, guard, broker)

    @staticmethod
    def _metadata(response: Any) -> dict[str, Any]:
        return {
            "adapter": P2OfflineAdapter.name,
            "p2_decision": response.decision.value,
            "p2_status": response.status.value,
            "p2_risk_level": response.risk_level.value,
            "p2_module": response.module.value,
            "p2_execution_id": response.execution_id,
        }

    @staticmethod
    def _ensure_allowed(response: Any) -> None:
        if not response.is_allowed():
            raise AdapterError(
                response.reason or f"P2 {response.tool} denied the operation"
            )

    @staticmethod
    def _request_id(request: ToolRequest) -> str:
        return request.request_id

    async def precheck(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> None:
        if tool_name not in self.tool_names:
            raise AdapterError("offline adapter cannot handle this tool")
        self._require_permission(tool_name, auth)

    async def execute(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> AdapterResult:
        auth = self._require_permission(tool_name, auth)
        if tool_name == "read_document":
            return await self._read_document(request, arguments, auth)
        if tool_name == "read_file":
            return await self._read_file(request, arguments, auth)
        if tool_name == "read_system_file":
            return await self._read_system_file(request, arguments, auth)
        if tool_name == "read_env_var":
            return await self._read_env_var(request, arguments, auth)
        if tool_name == "run_command":
            return await self._run_command(request, arguments, auth)
        if tool_name == "delete_file":
            return await self._delete_file(request, arguments, auth)
        raise AdapterError("unsupported offline tool")

    async def _read_document(
        self, request: ToolRequest, arguments: dict[str, Any], auth: AuthContext
    ) -> AdapterResult:
        roots = _scope_roots(auth, self._workspace)
        path = _authorized_file(str(arguments["document"]), self._workspace, roots)
        contract = self._contracts.DocumentAnalysisRequest(
            request_id=self._request_id(request),
            agent_id=auth.agent_id or "unknown",
            tenant_id=auth.tenant_id,
            file_path=str(path),
            extract_text=True,
            extract_metadata=True,
            run_malware_scan=self.settings.p2_malware_scan_enabled,
        )
        response = await self._document_gateway.analyze(contract)
        self._ensure_allowed(response)
        result = dict(response.result or {})
        content = ""
        if result.get("extraction_status") == self._contracts.ExtractionStatus.SUCCESS.value:
            fmt = str(result.get("file_format") or path.suffix.lstrip("."))
            parsed = await self._document_parser.parse(path, fmt)
            content = parsed.text[: self.settings.p2_max_document_text]
        output = {
            "document": arguments["document"],
            "path": str(path),
            "content": content,
            "file_format": result.get("file_format"),
            "file_size": result.get("file_size"),
            "content_hash": result.get("content_hash"),
            "extraction_status": result.get("extraction_status"),
            "malware_scan_status": result.get("malware_scan_status"),
            "inspection_status": result.get("inspection_status"),
            "trust_level": result.get("trust_level", "UNTRUSTED"),
            "security_findings": result.get("security_findings", []),
        }
        return AdapterResult(
            success=True,
            output=output,
            metadata=self._metadata(response),
        )

    async def _read_file(
        self, request: ToolRequest, arguments: dict[str, Any], auth: AuthContext
    ) -> AdapterResult:
        roots = _scope_roots(auth, self._workspace)
        path = _authorized_file(str(arguments["path"]), self._workspace, roots)
        gateway = self._filesystem_gateway(auth)
        contract = self._contracts.FileReadRequest(
            request_id=self._request_id(request),
            agent_id=auth.agent_id or "unknown",
            tenant_id=auth.tenant_id,
            file_path=str(path),
            max_bytes=self._max_read_bytes,
        )
        response = await gateway.read_file(contract)
        self._ensure_allowed(response)
        result = dict(response.result or {})
        content = result.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        return AdapterResult(
            success=True,
            output={
                "path": result.get("path", str(path)),
                "content": content,
                "size_bytes": result.get("size", len(content)),
            },
            metadata=self._metadata(response),
        )

    async def _delete_file(
        self, request: ToolRequest, arguments: dict[str, Any], auth: AuthContext
    ) -> AdapterResult:
        if bool(arguments.get("recursive", False)):
            raise AdapterError("recursive delete is not supported by the offline gateway")
        roots = _scope_roots(auth, self._workspace)
        path = _authorized_file(str(arguments["path"]), self._workspace, roots)
        gateway = self._filesystem_gateway(auth, delete=True)
        contract = self._contracts.FileDeleteRequest(
            request_id=self._request_id(request),
            agent_id=auth.agent_id or "unknown",
            tenant_id=auth.tenant_id,
            file_path=str(path),
        )
        response = await gateway.delete_file(contract)
        self._ensure_allowed(response)
        result = dict(response.result or {})
        return AdapterResult(
            success=True,
            output={
                "path": result.get("path", str(path)),
                "deleted": bool(result.get("deleted", False)),
            },
            metadata=self._metadata(response),
        )

    async def _read_system_file(
        self, request: ToolRequest, arguments: dict[str, Any], auth: AuthContext
    ) -> AdapterResult:
        path = str(arguments["path"])
        allowed = {
            str(item)
            for item in auth.scopes.get("allowed_system_paths", [])
            if isinstance(item, str)
        }
        if path not in allowed:
            raise AdapterError("system file is outside the agent's authorized scope")
        contract = self._contracts.SystemFileInspectRequest(
            request_id=self._request_id(request),
            agent_id=auth.agent_id or "unknown",
            tenant_id=auth.tenant_id,
            path=path,
            access_type=self._contracts.FileOperation.READ,
        )
        response = await self._system_gateway.inspect(contract)
        self._ensure_allowed(response)
        result = dict(response.result or {})
        return AdapterResult(
            success=True,
            output={
                "path": result.get("path"),
                "exists": result.get("exists"),
                "is_file": result.get("is_file"),
                "is_dir": result.get("is_dir"),
                "content": "[SYSTEM FILE CONTENT NOT EXPOSED BY P2 GATEWAY]",
            },
            metadata=self._metadata(response),
        )

    async def _read_env_var(
        self, request: ToolRequest, arguments: dict[str, Any], auth: AuthContext
    ) -> AdapterResult:
        name = str(arguments["name"])
        allowed = {
            str(item)
            for item in auth.scopes.get("allowed_env", [])
            if isinstance(item, str)
        }
        if name not in allowed:
            raise AdapterError(
                f"environment variable '{name}' is outside the agent's authorized scope"
            )
        gateway = self._environment_gateway(auth)
        contract = self._contracts.EnvironmentInspectRequest(
            request_id=self._request_id(request),
            agent_id=auth.agent_id or "unknown",
            tenant_id=auth.tenant_id,
            variable_names=[name],
        )
        response = await gateway.inspect(contract)
        result = dict(response.result or {})
        denied = result.get("denied_variables") or {}
        if name in denied:
            raise AdapterError(str(denied[name]))
        return AdapterResult(
            success=True,
            output={
                "name": name,
                "value": "[REDACTED - SECRETS ARE NOT EXPOSED BY P2 GATEWAY]",
                "accessible": name in (result.get("allowed_variables") or []),
            },
            metadata=self._metadata(response),
        )

    async def _run_command(
        self, request: ToolRequest, arguments: dict[str, Any], auth: AuthContext
    ) -> AdapterResult:
        command = str(arguments["command"]).strip()
        if not command:
            raise AdapterError("command is empty")
        if any(char in _FORBIDDEN_COMMAND_CHARS for char in command):
            raise AdapterError("command contains shell metacharacters")
        try:
            parts = shlex.split(command, posix=True)
        except ValueError as exc:
            raise AdapterError(f"command could not be parsed: {exc}") from exc
        if not parts:
            raise AdapterError("command is empty")
        try:
            contract = self._contracts.CommandRequest(
                request_id=self._request_id(request),
                agent_id=auth.agent_id or "unknown",
                tenant_id=auth.tenant_id,
                executable=parts[0],
                arguments=parts[1:],
                working_directory="/workspace",
                timeout=self.settings.p2_terminal_timeout_seconds,
            )
        except Exception as exc:
            raise AdapterError(f"command rejected by P2 contract validation: {exc}") from exc
        response = await self._terminal_gateway.execute(contract)
        self._ensure_allowed(response)
        result = dict(response.result or {})
        return AdapterResult(
            success=True,
            output={
                "command": command,
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "exit_code": result.get("exit_code"),
                "sandbox": "docker-p2-offline",
                "timed_out": result.get("timed_out", False),
                "output_truncated": result.get("output_truncated", False),
            },
            metadata=self._metadata(response),
        )


def create_p2_registry(settings: Settings | None = None) -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(P2OfflineAdapter(settings))
    registry.status = "REAL"
    registry.detail = "P2 offline security gateways (documents, files, env, terminal)"
    return registry
