"""
AgentShield Offline — Environment Variable Policy.

Manages allowlists and denylists for environment variable access.
"""

from __future__ import annotations

import re
from typing import Optional

import structlog

from app.core.configuration import get_settings, load_yaml_config

log = structlog.get_logger(__name__)

# Hard-coded sensitive variable names — these can never be allowlisted
_ALWAYS_DENIED: frozenset[str] = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "COHERE_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_SUBSCRIPTION_ID",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN",
        "GITLAB_TOKEN",
        "DATABASE_URL",
        "DB_PASSWORD",
        "DATABASE_PASSWORD",
        "SECRET_KEY",
        "DJANGO_SECRET_KEY",
        "FLASK_SECRET_KEY",
        "JWT_SECRET",
        "PRIVATE_KEY",
        "SSH_PRIVATE_KEY",
        "SSL_KEY",
        "TLS_KEY",
        "VAULT_TOKEN",
        "VAULT_SECRET_ID",
        "PASSWORD",
        "PASSWD",
    }
)

# Patterns that indicate a variable is likely a secret
_SENSITIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:SECRET|PASSWORD|PASSWD|CREDENTIAL|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)", re.IGNORECASE),
]


class EnvironmentPolicy:
    """
    Decides whether an agent may read a specific environment variable.

    Policy precedence (highest to lowest):
    1. ALWAYS_DENIED list — unconditional denial.
    2. Configured denylist.
    3. Sensitive patterns.
    4. Agent allowlist — if configured, only listed vars are permitted.
    5. Global allowlist — if configured, only listed vars are permitted.
    6. Deny by default.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        settings = get_settings()
        cfg = load_yaml_config(config_path or settings.offline_policy_path)
        env_cfg = cfg.get("environment", {})

        self._global_allowlist: set[str] = set(env_cfg.get("allowlist", []))
        self._global_denylist: set[str] = set(env_cfg.get("denylist", []))
        self._agent_configs: dict[str, dict] = {}
        for entry in env_cfg.get("agents", []):
            aid = entry.get("agent_id", "")
            if aid:
                self._agent_configs[aid] = entry

        log.info(
            "environment_policy_loaded",
            global_allowlist_size=len(self._global_allowlist),
            global_denylist_size=len(self._global_denylist),
        )

    def is_allowed(self, variable_name: str, agent_id: str = "") -> tuple[bool, str]:
        """
        Returns (allowed, reason).
        """
        upper = variable_name.upper()

        # 1. Always-denied
        if upper in _ALWAYS_DENIED:
            return False, f"Variable '{variable_name}' is in the unconditional denylist"

        # 2. Configured denylist
        if upper in {v.upper() for v in self._global_denylist}:
            return False, f"Variable '{variable_name}' is in the configured denylist"

        # 3. Sensitive patterns
        for p in _SENSITIVE_PATTERNS:
            if p.search(upper):
                return False, f"Variable '{variable_name}' matches sensitive pattern"

        # 4. Agent-specific allowlist
        if agent_id and agent_id in self._agent_configs:
            agent_allow = self._agent_configs[agent_id].get("allowed_vars", [])
            if agent_allow:
                if variable_name in agent_allow or upper in {v.upper() for v in agent_allow}:
                    return True, "In agent-specific allowlist"
                return False, f"Variable '{variable_name}' not in agent allowlist"

        # 5. Global allowlist
        if self._global_allowlist:
            if variable_name in self._global_allowlist or upper in {v.upper() for v in self._global_allowlist}:
                return True, "In global allowlist"
            return False, f"Variable '{variable_name}' not in global allowlist"

        # 6. Deny by default
        return False, "Environment access denied by default — no allowlist configured"
