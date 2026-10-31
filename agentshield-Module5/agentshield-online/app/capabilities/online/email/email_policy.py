"""
Email policy loader and enforcer.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parents[5] / "configs" / "email_policy.yaml"


class EmailPolicy:
    """Loads email_policy.yaml and provides policy checks."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        path = Path(config_path or _DEFAULT_CONFIG_PATH)
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            self._config: dict[str, Any] = data.get("email", {})
        except Exception as e:
            logger.warning("EmailPolicy: could not load %s: %s. Using secure defaults.", path, e)
            self._config = {}

    @property
    def allowed_sender_accounts(self) -> list[str]:
        return self._config.get("allowed_sender_accounts", [])

    @property
    def approved_recipients(self) -> list[str]:
        return self._config.get("approved_recipients", [])

    @property
    def approved_domains(self) -> list[str]:
        return self._config.get("approved_domains", [])

    @property
    def blocked_addresses(self) -> list[str]:
        return self._config.get("blocked_addresses", [])

    @property
    def allow_external_recipients(self) -> bool:
        return self._config.get("allow_external_recipients", False)

    @property
    def require_approval_for_send(self) -> bool:
        return self._config.get("require_approval_for_send", True)

    @property
    def approval_expires_seconds(self) -> int:
        return self._config.get("approval_expires_seconds", 300)

    @property
    def dlp_enabled(self) -> bool:
        return self._config.get("dlp_check_enabled", True)

    @property
    def allowed_attachment_types(self) -> list[str]:
        return self._config.get("allowed_attachment_types", [".pdf", ".txt", ".png"])

    @property
    def max_attachment_size_mb(self) -> int:
        return self._config.get("max_attachment_size_mb", 10)

    @property
    def gmail_scopes(self) -> list[str]:
        return self._config.get("gmail_scopes", [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.send",
        ])
