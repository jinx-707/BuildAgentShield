"""
AgentShield Central Connector & Tool Registry.
Thread-safe catalog for registered external REST APIs and MCP servers/tools.
Enforces endpoint whitelisting, prevents arbitrary endpoints, and tracks tool approval status.
"""

from __future__ import annotations

import re
import threading
from typing import Any
from urllib.parse import urlparse

from core.config import setup_logger
from core.connectors.models import (
    ConnectorRegistration,
    ConnectorType,
    EndpointDefinition,
    HttpMethod,
    McpToolDefinition,
    UnregisteredConnectorError,
    UnregisteredEndpointError,
    UnregisteredToolError,
)

logger = setup_logger("agentshield.connectors.registry")


class ConnectorRegistry:
    """
    Central registration store for external REST APIs and MCP tools.
    Thread-safe and fail-safe: requests to unregistered connectors,
    unregistered endpoints, or unapproved tools are rejected immediately.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._connectors: dict[str, ConnectorRegistration] = {}

    def register_connector(self, connector: ConnectorRegistration) -> ConnectorRegistration:
        """
        Registers an external REST API or MCP server.
        Validates structure and URL schemes.
        """
        with self._lock:
            # Validate URL schemes if present
            if connector.base_url:
                parsed = urlparse(connector.base_url)
                if parsed.scheme.lower() not in ("http", "https"):
                    raise ValueError(f"Invalid base_url scheme '{parsed.scheme}'. Only http/https supported.")
            if connector.mcp_server_url:
                parsed = urlparse(connector.mcp_server_url)
                if parsed.scheme.lower() not in ("http", "https", "stdio", "sse", "ws", "wss"):
                    raise ValueError(f"Invalid mcp_server_url scheme '{parsed.scheme}'.")

            self._connectors[connector.connector_id] = connector
            logger.info(
                "Registered connector '%s' (type: %s, endpoints: %d, tools: %d)",
                connector.connector_id,
                connector.connector_type.value,
                len(connector.allowed_endpoints),
                len(connector.allowed_tools),
            )
            return connector

    def get_connector(self, connector_id: str) -> ConnectorRegistration | None:
        """Retrieves a registered connector by its unique identifier."""
        with self._lock:
            return self._connectors.get(connector_id)

    def list_connectors(
        self,
        connector_type: ConnectorType | None = None,
        enabled_only: bool = False,
    ) -> list[ConnectorRegistration]:
        """Returns all registered connectors, with optional filtering."""
        with self._lock:
            results = list(self._connectors.values())
            if connector_type is not None:
                results = [c for c in results if c.connector_type == connector_type]
            if enabled_only:
                results = [c for c in results if c.enabled]
            return results

    def delete_connector(self, connector_id: str) -> bool:
        """Removes a connector from the registry."""
        with self._lock:
            if connector_id in self._connectors:
                del self._connectors[connector_id]
                logger.info("Deleted connector '%s'", connector_id)
                return True
            return False

    def update_connector_status(self, connector_id: str, enabled: bool) -> bool:
        """Enables or disables a registered connector."""
        with self._lock:
            connector = self._connectors.get(connector_id)
            if not connector:
                return False
            # Recreate with updated enabled status
            self._connectors[connector_id] = connector.model_copy(update={"enabled": enabled})
            return True

    # -----------------------------------------------------------------------
    # Tool Management (MCP)
    # -----------------------------------------------------------------------

    def register_tool(
        self,
        connector_id: str,
        tool: McpToolDefinition,
        auto_approve: bool = False,
    ) -> None:
        """
        Registers an MCP tool under a connector.
        By default, auto_approve=False ensures tools are marked untrusted until approved.
        """
        with self._lock:
            connector = self.get_connector(connector_id)
            if not connector:
                raise UnregisteredConnectorError(f"Connector '{connector_id}' is not registered")

            if auto_approve:
                tool = tool.model_copy(update={"is_approved": True})

            # Replace existing or append
            tools = [t for t in connector.allowed_tools if t.name != tool.name]
            tools.append(tool)
            self._connectors[connector_id] = connector.model_copy(update={"allowed_tools": tools})
            logger.info(
                "Registered tool '%s' on connector '%s' (approved=%s)",
                tool.name,
                connector_id,
                tool.is_approved,
            )

    def approve_tool(self, connector_id: str, tool_name: str) -> bool:
        """Explicitly marks a discovered tool as approved for execution."""
        with self._lock:
            connector = self.get_connector(connector_id)
            if not connector:
                return False

            updated = False
            new_tools: list[McpToolDefinition] = []
            for t in connector.allowed_tools:
                if t.name == tool_name:
                    new_tools.append(t.model_copy(update={"is_approved": True}))
                    updated = True
                else:
                    new_tools.append(t)

            if updated:
                self._connectors[connector_id] = connector.model_copy(update={"allowed_tools": new_tools})
                logger.info("Tool '%s' on connector '%s' approved", tool_name, connector_id)
            return updated

    def get_tool(self, connector_id: str, tool_name: str) -> McpToolDefinition | None:
        """Finds a tool definition within a connector."""
        with self._lock:
            connector = self.get_connector(connector_id)
            if not connector:
                return None
            for t in connector.allowed_tools:
                if t.name == tool_name:
                    return t
            return None

    # -----------------------------------------------------------------------
    # Endpoint Whitelisting & Path Matching (REST API)
    # -----------------------------------------------------------------------

    def match_endpoint(
        self,
        connector: ConnectorRegistration,
        requested_path: str,
        method: HttpMethod | str,
    ) -> EndpointDefinition | None:
        """
        Matches a requested path and HTTP method against connector's registered endpoints.
        Supports:
          1. Exact path match: /v1/weather == /v1/weather
          2. Parameterized template match: /users/{id} matches /users/123
        Returns the matching EndpointDefinition or None if unregistered.
        """
        norm_method = HttpMethod(method) if isinstance(method, str) else method
        norm_path = self._normalize_path(requested_path)

        for ep in connector.allowed_endpoints:
            if norm_method not in ep.methods:
                continue

            ep_norm = self._normalize_path(ep.path)
            if ep_norm == norm_path:
                return ep

            # Parameterized matching: e.g. /users/{user_id}/items -> ^/users/[^/]+/items$
            if "{" in ep_norm and "}" in ep_norm:
                pattern = re.sub(r"\{[a-zA-Z0-9_]+\}", r"[^/]+", ep_norm)
                if re.fullmatch(f"^{pattern}$", norm_path):
                    return ep

        return None

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalizes path by ensuring leading slash and removing trailing slash."""
        p = path.strip()
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1 and p.endswith("/"):
            p = p.rstrip("/")
        return p

    def clear(self) -> None:
        """Clears all registered connectors (primarily for test resets)."""
        with self._lock:
            self._connectors.clear()
