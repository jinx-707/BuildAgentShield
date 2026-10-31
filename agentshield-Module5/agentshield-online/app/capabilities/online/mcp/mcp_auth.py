"""
MCP authentication — injects credentials for MCP server connections.
"""
from __future__ import annotations

import logging
from typing import Any

from app.capabilities.online.mcp.server_registry import MCPServerConfig
from app.integrations.ports import SecretProviderPort

logger = logging.getLogger(__name__)


class MCPAuth:
    """Retrieves and prepares auth for MCP server connections."""

    def __init__(self, secret_provider: SecretProviderPort) -> None:
        self._secrets = secret_provider

    async def get_auth_headers(self, server: MCPServerConfig) -> dict[str, str]:
        """Return auth headers for connecting to a MCP server."""
        if server.auth_type == "none":
            return {}
        if not server.credential_id:
            return {}

        try:
            credential = await self._secrets.get_credential(
                credential_id=server.credential_id,
            )
        except Exception as e:
            logger.warning(
                "MCPAuth: could not get credential for server %s: %s", server.id, e
            )
            return {}

        if server.auth_type == "api_key":
            return {"X-API-Key": credential}
        elif server.auth_type == "bearer":
            return {"Authorization": f"Bearer {credential}"}
        return {}
