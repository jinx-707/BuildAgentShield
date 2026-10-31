"""
Request policy for external API calls — enforces method/path/domain restrictions.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from app.capabilities.online.external_apis.connector_registry import ConnectorConfig, ConnectorRegistry
from app.core.exceptions import APISchemaValidationError, UnknownConnectorError

logger = logging.getLogger(__name__)


class RequestPolicy:
    """Enforces method, path, and domain restrictions per connector."""

    def __init__(self, registry: ConnectorRegistry) -> None:
        self._registry = registry

    def validate_request(
        self,
        connector_id: str,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
    ) -> ConnectorConfig:
        """
        Validate a request against the connector registry.
        Returns the ConnectorConfig if valid.
        Raises UnknownConnectorError or APISchemaValidationError.
        """
        cfg = self._registry.get(connector_id)
        if not cfg:
            raise UnknownConnectorError(
                f"Connector '{connector_id}' is not registered. "
                "Only approved connectors may be executed."
            )

        if not self._registry.is_method_allowed(connector_id, method):
            raise APISchemaValidationError(
                f"HTTP method '{method}' is not allowed for connector '{connector_id}'. "
                f"Allowed: {cfg.allowed_methods}"
            )

        if cfg.allowed_paths and not self._registry.is_path_allowed(connector_id, path):
            raise APISchemaValidationError(
                f"Path '{path}' is not in the allowed paths for connector '{connector_id}'. "
                f"Allowed: {cfg.allowed_paths}"
            )

        # Validate no attempt to override Authorization header from external input
        if headers:
            blocked_override_headers = {"authorization", "x-api-key", "cookie"}
            for h in headers:
                if h.lower() in blocked_override_headers:
                    raise APISchemaValidationError(
                        f"Header '{h}' cannot be set by the agent — it is managed by "
                        "the credential manager."
                    )

        return cfg

    def build_url(self, cfg: ConnectorConfig, path: str) -> str:
        """Build the full URL from connector base_url and path."""
        base = cfg.base_url.rstrip("/")
        path = path if path.startswith("/") else f"/{path}"
        return f"{base}{path}"
