"""
MCP Tool Registry — caches discovered tools from MCP servers.
Tool schemas are validated and treated as untrusted.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ToolSchema:
    server_id: str
    tool_name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    # Original untrusted description from server
    raw_description: str = ""


class ToolRegistry:
    """In-memory cache of discovered MCP tool schemas."""

    def __init__(self) -> None:
        # {server_id: {tool_name: ToolSchema}}
        self._tools: dict[str, dict[str, ToolSchema]] = {}

    def register_tools(
        self,
        server_id: str,
        tools: list[dict[str, Any]],
    ) -> None:
        """Register tools discovered from an MCP server."""
        server_tools: dict[str, ToolSchema] = {}
        for t in tools:
            name = t.get("name", "")
            if not name:
                continue
            raw_desc = t.get("description", "")
            schema = ToolSchema(
                server_id=server_id,
                tool_name=name,
                description=self._sanitize_description(raw_desc),
                input_schema=t.get("inputSchema", {}),
                raw_description=raw_desc,
            )
            server_tools[name] = schema
        self._tools[server_id] = server_tools
        logger.info(
            "ToolRegistry: registered %d tools for server %s",
            len(server_tools), server_id
        )

    def _sanitize_description(self, desc: str) -> str:
        """
        Sanitize tool description — it comes from an untrusted MCP server.
        Truncate excessively long descriptions that could be injection vectors.
        """
        if len(desc) > 500:
            return desc[:500] + "...[TRUNCATED - untrusted server description]"
        return desc

    def get_tool(self, server_id: str, tool_name: str) -> ToolSchema | None:
        return self._tools.get(server_id, {}).get(tool_name)

    def list_tools(self, server_id: str | None = None) -> list[dict[str, Any]]:
        results = []
        servers = [server_id] if server_id else list(self._tools.keys())
        for sid in servers:
            for t in self._tools.get(sid, {}).values():
                results.append({
                    "server_id": t.server_id,
                    "tool_name": t.tool_name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                    "trust_note": "Tool description sourced from untrusted MCP server",
                })
        return results

    def clear_server(self, server_id: str) -> None:
        self._tools.pop(server_id, None)
