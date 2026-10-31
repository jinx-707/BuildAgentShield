"""
AgentShield Offline — Environment Guard.

Provides a minimal isolated environment for execution workers.
The host's os.environ is NEVER passed to untrusted processes.
"""

from __future__ import annotations

import os
from typing import Optional

import structlog

from app.capabilities.offline.environment.environment_policy import EnvironmentPolicy

log = structlog.get_logger(__name__)

# Variables that are safe to include in any subprocess environment
_SAFE_DEFAULTS = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
}


class EnvironmentGuard:
    """
    Builds a minimal, safe environment for subprocess/container execution.

    Key guarantee: secrets and host credentials are NEVER included unless
    explicitly approved and requested.
    """

    def __init__(self, policy: EnvironmentPolicy) -> None:
        self._policy = policy

    def build_minimal_env(
        self,
        *,
        agent_id: str = "",
        explicit_additions: Optional[dict[str, str]] = None,
    ) -> dict[str, str]:
        """
        Build a minimal environment containing only safe defaults plus
        any explicitly approved additions.

        This method intentionally does NOT read from os.environ.
        """
        env = dict(_SAFE_DEFAULTS)

        if explicit_additions:
            for var, value in explicit_additions.items():
                allowed, reason = self._policy.is_allowed(var, agent_id)
                if allowed:
                    env[var] = value
                    log.debug("env_var_added", variable=var, agent_id=agent_id)
                else:
                    log.warning(
                        "env_var_rejected",
                        variable=var,
                        agent_id=agent_id,
                        reason=reason,
                        # value intentionally NOT logged
                    )

        return env

    def inspect_requested_vars(
        self, variable_names: list[str], agent_id: str = ""
    ) -> dict[str, tuple[bool, str]]:
        """
        Check which of the requested variables are accessible.
        Returns {variable_name: (allowed, reason)}.
        """
        results = {}
        for var in variable_names:
            allowed, reason = self._policy.is_allowed(var, agent_id)
            results[var] = (allowed, reason)
            if not allowed:
                log.warning(
                    "env_access_denied",
                    variable=var,
                    agent_id=agent_id,
                    reason=reason,
                )
        return results

    def get_var_if_allowed(
        self, variable_name: str, agent_id: str = ""
    ) -> Optional[str]:
        """
        Return the value of an environment variable from the HOST if allowed.
        Use sparingly — only for variables explicitly on the global allowlist.
        """
        allowed, reason = self._policy.is_allowed(variable_name, agent_id)
        if not allowed:
            log.warning(
                "env_access_denied",
                variable=variable_name,
                agent_id=agent_id,
                reason=reason,
            )
            return None
        # Access from host environment only if the policy approves
        value = os.environ.get(variable_name)
        # Never log the value
        log.info(
            "env_var_accessed",
            variable=variable_name,
            agent_id=agent_id,
            found=value is not None,
        )
        return value
