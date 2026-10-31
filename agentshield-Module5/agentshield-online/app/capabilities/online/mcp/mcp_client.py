"""
MCP Client — connects to MCP servers and invokes tools.
Uses official MCP Python SDK where available; falls back to HTTP transport.
All responses are treated as untrusted.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.capabilities.online.mcp.server_registry import MCPServerConfig
from app.capabilities.online.mcp.tool_validator import sanitize_tool_result
from app.core.exceptions import MCPConnectionError, MCPError

logger = logging.getLogger(__name__)


class MCPHTTPClient:
    """
    MCP client for HTTP transport servers.
    Implements MCP JSON-RPC protocol over HTTP.
    """

    def __init__(
        self,
        server: MCPServerConfig,
        auth_headers: dict[str, str] | None = None,
    ) -> None:
        self._server = server
        self._auth_headers = auth_headers or {}

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            **self._auth_headers,
        }

    async def list_tools(self) -> list[dict[str, Any]]:
        """Discover available tools from the MCP server."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
        try:
            async with httpx.AsyncClient(
                timeout=float(self._server.connection_timeout_seconds),
                verify=True,
            ) as client:
                resp = await client.post(
                    self._server.url,
                    json=payload,
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()

            if "error" in data:
                raise MCPError(
                    f"MCP server {self._server.id} returned error: {data['error']}"
                )

            return data.get("result", {}).get("tools", [])

        except httpx.ConnectError:
            raise MCPConnectionError(
                f"Cannot connect to MCP server '{self._server.name}' at {self._server.url}"
            )
        except httpx.TimeoutException:
            raise MCPConnectionError(
                f"MCP server '{self._server.name}' connection timed out"
            )
        except (MCPError, MCPConnectionError):
            raise
        except Exception as e:
            raise MCPConnectionError(
                f"MCP server '{self._server.name}' error: {type(e).__name__}"
            )

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        """
        Invoke a tool on the MCP server.
        Returns sanitized result — treated as untrusted.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        try:
            async with httpx.AsyncClient(
                timeout=float(self._server.tool_timeout_seconds),
                verify=True,
            ) as client:
                resp = await client.post(
                    self._server.url,
                    json=payload,
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()

            if "error" in data:
                raise MCPError(
                    f"MCP tool '{tool_name}' returned error: "
                    f"{data['error'].get('message', 'unknown error')}"
                )

            # Sanitize result — untrusted
            raw_result = data.get("result", {})
            # MCP spec: content is in result.content[]
            content = raw_result.get("content", raw_result)
            return sanitize_tool_result(content)

        except httpx.ConnectError:
            raise MCPConnectionError(
                f"Cannot connect to MCP server '{self._server.name}'"
            )
        except httpx.TimeoutException:
            raise MCPConnectionError(
                f"MCP tool '{tool_name}' timed out after {self._server.tool_timeout_seconds}s"
            )
        except (MCPError, MCPConnectionError):
            raise
        except Exception as e:
            raise MCPError(
                f"MCP tool call failed: {type(e).__name__}"
            )


class MockMCPClient:
    """
    Mock MCP client for testing.
    Returns synthetic responses. No real server connection.
    """

    MOCK_TOOLS = [
        {
            "name": "echo",
            "description": "Echo the input",
            "inputSchema": {
                "type": "object",
                "properties": {"message": {"type": "string"}},
                "required": ["message"],
            },
        },
        {
            "name": "get_weather",
            "description": "Get weather for a city",
            "inputSchema": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        },
        {
            "name": "execute_code",
            "description": "Execute arbitrary code",
            "inputSchema": {
                "type": "object",
                "properties": {"code": {"type": "string"}},
            },
        },
    ]

    def __init__(self, server: MCPServerConfig) -> None:
        self._server = server

    async def list_tools(self) -> list[dict[str, Any]]:
        return self.MOCK_TOOLS

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        if tool_name == "echo":
            return {"echo": arguments.get("message", "")}
        elif tool_name == "get_weather":
            city = arguments.get("city", "unknown")
            return {"city": city, "temperature": "25°C", "condition": "Sunny"}
        elif tool_name == "execute_code":
            raise MCPError("Tool 'execute_code' returned an error")
        return {"result": f"mock result for {tool_name}"}
