"""
MCP Server Registry — maintains approved MCP server definitions.
Unknown servers are DENIED.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parents[5] / "configs" / "mcp_policy.yaml"


@dataclass
class MCPServerConfig:
    id: str
    name: str
    url: str
    transport: str = "http"          # http | stdio | ws
    auth_type: str = "none"          # none | api_key | bearer
    credential_id: str | None = None
    connection_timeout_seconds: int = 30
    tool_timeout_seconds: int = 60
    allowed_tools: list[str] = field(default_factory=list)
    approval_required_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)


class MCPServerRegistry:
    """Loads and provides MCP server configurations."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        self._servers: dict[str, MCPServerConfig] = {}
        self._defaults: dict[str, Any] = {}
        path = Path(config_path or _DEFAULT_CONFIG_PATH)
        self._load(path)

    def _load(self, path: Path) -> None:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            self._defaults = data.get("mcp_defaults", {})
            for raw in data.get("mcp_servers", []):
                cfg = MCPServerConfig(
                    id=raw["id"],
                    name=raw["name"],
                    url=raw["url"],
                    transport=raw.get("transport", "http"),
                    auth_type=raw.get("auth_type", "none"),
                    credential_id=raw.get("credential_id"),
                    connection_timeout_seconds=raw.get(
                        "connection_timeout_seconds",
                        self._defaults.get("connection_timeout_seconds", 30),
                    ),
                    tool_timeout_seconds=raw.get(
                        "tool_timeout_seconds",
                        self._defaults.get("tool_timeout_seconds", 60),
                    ),
                    allowed_tools=raw.get("allowed_tools", []),
                    approval_required_tools=raw.get("approval_required_tools", []),
                    blocked_tools=raw.get("blocked_tools", []),
                )
                self._servers[cfg.id] = cfg
            logger.info(
                "MCPServerRegistry: loaded %d servers from %s",
                len(self._servers), path
            )
        except Exception as e:
            logger.warning("MCPServerRegistry: could not load %s: %s", path, e)

    def get(self, server_id: str) -> MCPServerConfig | None:
        return self._servers.get(server_id)

    def list_servers(self) -> list[dict[str, Any]]:
        return [
            {
                "id": s.id,
                "name": s.name,
                "transport": s.transport,
                "allowed_tools": s.allowed_tools,
            }
            for s in self._servers.values()
        ]

    def is_registered(self, server_id: str) -> bool:
        return server_id in self._servers

    def is_tool_allowed(self, server_id: str, tool_name: str) -> bool:
        cfg = self._servers.get(server_id)
        if not cfg:
            return False
        if tool_name in cfg.blocked_tools:
            return False
        if cfg.allowed_tools and tool_name not in cfg.allowed_tools:
            return False
        return True

    def requires_approval(self, server_id: str, tool_name: str) -> bool:
        cfg = self._servers.get(server_id)
        if not cfg:
            return False
        return tool_name in cfg.approval_required_tools

    def register(self, server: MCPServerConfig) -> None:
        """Register a server at runtime (for testing)."""
        self._servers[server.id] = server
