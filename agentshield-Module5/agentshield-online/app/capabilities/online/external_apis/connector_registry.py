"""
API Connector Registry — defines and loads approved external API connectors.
Unknown connectors are DENIED.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parents[5] / "configs" / "api_policy.yaml"


class ConnectorConfig(BaseModel):
    """Definition of a single approved API connector."""
    id: str
    name: str
    base_url: str
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET"])
    allowed_paths: list[str] = Field(default_factory=list)
    auth_type: str = "none"  # none | api_key | bearer | basic | oauth2
    credential_id: str | None = None
    permission_required: str | None = None
    timeout_seconds: int = 30
    rate_limit_per_minute: int = 60
    response_size_limit_bytes: int = 5242880
    request_schema: dict[str, Any] | None = None
    response_schema: dict[str, Any] | None = None
    allowed_domains: list[str] = Field(default_factory=list)


class ConnectorRegistry:
    """
    Maintains the registry of approved API connectors.
    Only connectors defined here may be executed.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        self._connectors: dict[str, ConnectorConfig] = {}
        path = Path(config_path or _DEFAULT_CONFIG_PATH)
        self._load(path)

    def _load(self, path: Path) -> None:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            for raw in data.get("api_connectors", []):
                cfg = ConnectorConfig(**raw)
                self._connectors[cfg.id] = cfg
            logger.info("ConnectorRegistry: loaded %d connectors from %s", len(self._connectors), path)
        except Exception as e:
            logger.warning("ConnectorRegistry: could not load %s: %s", path, e)

    def get(self, connector_id: str) -> ConnectorConfig | None:
        return self._connectors.get(connector_id)

    def list_ids(self) -> list[str]:
        return list(self._connectors.keys())

    def is_registered(self, connector_id: str) -> bool:
        return connector_id in self._connectors

    def is_method_allowed(self, connector_id: str, method: str) -> bool:
        cfg = self._connectors.get(connector_id)
        if not cfg:
            return False
        return method.upper() in [m.upper() for m in cfg.allowed_methods]

    def is_path_allowed(self, connector_id: str, path: str) -> bool:
        cfg = self._connectors.get(connector_id)
        if not cfg:
            return False
        for allowed in cfg.allowed_paths:
            # Simple glob-style matching
            if allowed.endswith("/*"):
                prefix = allowed[:-2]
                if path.startswith(prefix):
                    return True
            elif "{" in allowed:
                # Path parameter matching
                import re
                pattern = re.escape(allowed)
                pattern = re.sub(r"\\{[^}]+\\}", "[^/]+", pattern)
                if re.fullmatch(pattern, path):
                    return True
            elif allowed == path:
                return True
        return False

    def register(self, connector: ConnectorConfig) -> None:
        """Register a connector at runtime (for testing)."""
        self._connectors[connector.id] = connector
