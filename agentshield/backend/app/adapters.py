from __future__ import annotations

import secrets
from typing import Any, Protocol

from .contracts import AdapterResult, AuthContext, ToolRequest


class AdapterError(RuntimeError):
    pass


class Adapter(Protocol):
    name: str
    capability: str
    tool_names: set[str]

    async def healthcheck(self) -> bool: ...

    async def precheck(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> None: ...

    async def execute(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> AdapterResult: ...


class MockOfflineAdapter:
    name = "mock_offline"
    capability = "offline"
    tool_names = {
        "read_document",
        "read_file",
        "read_system_file",
        "read_env_var",
        "run_command",
        "delete_file",
    }

    async def healthcheck(self) -> bool:
        return True

    async def precheck(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> None:
        if tool_name not in self.tool_names:
            raise AdapterError("offline adapter cannot handle this tool")

    async def execute(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> AdapterResult:
        if tool_name == "read_document":
            return AdapterResult(
                success=True,
                output={
                    "document": arguments["document"],
                    "content": "[MOCK DOCUMENT CONTENT - NO WORKSPACE FILE ACCESSED]",
                },
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "read_file":
            return AdapterResult(
                success=True,
                output={
                    "path": arguments["path"],
                    "content": "[MOCK WORKSPACE FILE - NO HOST FILESYSTEM ACCESSED]",
                    "size_bytes": 0,
                },
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "read_system_file":
            return AdapterResult(
                success=True,
                output={"path": arguments["path"], "content": "[MOCK SYSTEM FILE - REDACTED]"},
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "read_env_var":
            return AdapterResult(
                success=True,
                output={"name": arguments["name"], "value": "[MOCK SECRET - REDACTED]"},
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "run_command":
            return AdapterResult(
                success=True,
                output={
                    "command": arguments["command"],
                    "stdout": "[MOCK SANDBOX OUTPUT - NO COMMAND EXECUTED]",
                    "exit_code": 0,
                    "sandbox": "mock-isolated-worker",
                },
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "delete_file":
            return AdapterResult(
                success=True,
                output={
                    "path": arguments["path"],
                    "recursive": arguments.get("recursive", False),
                    "deleted": True,
                    "mock": True,
                },
                metadata={"adapter": self.name, "mock": True},
            )
        raise AdapterError("unsupported offline tool")


class MockOnlineAdapter:
    name = "mock_online"
    capability = "online"
    tool_names = {
        "browse_url",
        "send_email",
        "export_data",
        "download_file",
        "initiate_payment",
        "call_external_api",
        "mcp_call",
    }

    async def healthcheck(self) -> bool:
        return True

    async def precheck(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> None:
        if tool_name not in self.tool_names:
            raise AdapterError("online adapter cannot handle this tool")

    async def execute(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> AdapterResult:
        token = secrets.token_hex(8)
        if tool_name == "browse_url":
            return AdapterResult(
                success=True,
                output={
                    "url": str(arguments["url"]),
                    "status": 200,
                    "content": "[MOCK WEBPAGE - NO NETWORK REQUEST MADE]",
                    "quarantined": False,
                },
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "send_email":
            return AdapterResult(
                success=True,
                output={
                    "message_id": f"mock-mail-{token}",
                    "recipient": arguments["to"],
                    "accepted": True,
                    "delivered": False,
                },
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "export_data":
            return AdapterResult(
                success=True,
                output={
                    "export_id": f"mock-export-{token}",
                    "destination": arguments["destination"],
                    "document": arguments["document"],
                    "redacted": True,
                    "file": f"mock-{token}.{arguments.get('format', 'csv')}",
                },
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "download_file":
            return AdapterResult(
                success=True,
                output={
                    "download_id": f"mock-download-{token}",
                    "url": str(arguments["url"]),
                    "quarantined": True,
                    "executed": False,
                },
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "initiate_payment":
            return AdapterResult(
                success=True,
                output={
                    "payment_id": f"pay_sandbox_{token}",
                    "amount": arguments["amount"],
                    "currency": arguments.get("currency", "USD"),
                    "merchant": arguments.get("merchant", ""),
                    "status": "sandbox_authorized",
                    "live": False,
                },
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "call_external_api":
            return AdapterResult(
                success=True,
                output={
                    "status_code": 200,
                    "endpoint": str(arguments["endpoint"]),
                    "body": {"mock": True, "data": "[SIMULATED RESPONSE]"},
                },
                metadata={"adapter": self.name, "mock": True},
            )
        if tool_name == "mcp_call":
            return AdapterResult(
                success=True,
                output={
                    "server": arguments["server"],
                    "method": arguments["method"],
                    "result": {"mock": True},
                },
                metadata={"adapter": self.name, "mock": True},
            )
        raise AdapterError("unsupported online tool")


class UnavailableAdapter:
    capability = "unavailable"

    def __init__(self, name: str, tools: set[str]) -> None:
        self.name = name
        self.tool_names = tools

    async def healthcheck(self) -> bool:
        return False

    async def precheck(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> None:
        raise AdapterError(f"adapter {self.name} unavailable")

    async def execute(
        self,
        request: ToolRequest,
        tool_name: str,
        arguments: dict[str, Any],
        auth: AuthContext | None = None,
    ) -> AdapterResult:
        raise AdapterError(f"adapter {self.name} unavailable")


class AdapterRegistry:
    def __init__(self) -> None:
        self.adapters: dict[str, Adapter] = {}
        self.status = "UNAVAILABLE"
        self.detail = ""

    def register(self, adapter: Adapter) -> None:
        self.adapters[adapter.name] = adapter

    def find(self, tool_name: str) -> Adapter | None:
        for adapter in self.adapters.values():
            if tool_name in adapter.tool_names:
                return adapter
        return None

    def list_health(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "detail": self.detail,
            "adapters": sorted(self.adapters.keys()),
        }


def register(registry: AdapterRegistry, *adapters: Adapter) -> AdapterRegistry:
    for adapter in adapters:
        registry.register(adapter)
    return registry


def mock_offline_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(MockOfflineAdapter())
    registry.status = "MOCK"
    registry.detail = "safe offline adapters; no host filesystem or command execution"
    return registry


def mock_online_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(MockOnlineAdapter())
    registry.status = "MOCK"
    registry.detail = "safe online adapters; no network egress, email delivery, or payments"
    return registry
