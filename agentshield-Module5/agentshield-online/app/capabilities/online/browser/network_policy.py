"""
Browser network policy — loads YAML config and provides policy checks
for browser navigation and subresource requests.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parents[5] / "configs" / "browser_policy.yaml"


class BrowserNetworkPolicy:
    """
    Loads browser_policy.yaml and enforces network-level rules.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        path = Path(config_path or _DEFAULT_CONFIG_PATH)
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            self._config: dict[str, Any] = data.get("browser", {})
        except Exception as e:
            logger.warning("BrowserNetworkPolicy: could not load %s: %s. Using defaults.", path, e)
            self._config = {}

    @property
    def allowed_schemes(self) -> list[str]:
        return self._config.get("allowed_schemes", ["https", "http"])

    @property
    def blocked_schemes(self) -> list[str]:
        return self._config.get(
            "blocked_schemes",
            ["javascript", "file", "data", "ftp", "blob", "vbscript"],
        )

    @property
    def domain_allowlist(self) -> list[str]:
        return self._config.get("domain_allowlist", [])

    @property
    def domain_blocklist(self) -> list[str]:
        return self._config.get("domain_blocklist", [])

    @property
    def allowed_ports(self) -> list[int]:
        return self._config.get("allowed_ports", [80, 443, 8080, 8443])

    @property
    def max_redirects(self) -> int:
        return self._config.get("max_redirects", 5)

    @property
    def session_timeout(self) -> int:
        return self._config.get("session_timeout_seconds", 120)

    @property
    def navigation_timeout(self) -> int:
        return self._config.get("navigation_timeout_seconds", 30)

    @property
    def request_timeout(self) -> int:
        return self._config.get("request_timeout_seconds", 15)

    @property
    def inspect_content(self) -> bool:
        return self._config.get("inspect_extracted_content", True)

    @property
    def max_sessions(self) -> int:
        return self._config.get("max_sessions", 10)

    def get_action_policy(self, action: str) -> str:
        """Return the policy for a given browser action."""
        actions = self._config.get("actions", {})
        return actions.get(action, "deny")
