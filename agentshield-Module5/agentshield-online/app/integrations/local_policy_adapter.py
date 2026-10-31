"""
LOCAL DEVELOPMENT ONLY — Policy Adapter.

Defaults to DENY for all operations.
Explicit allow-lists are loaded from the YAML policy configs.
Replace with Person 4's OPA-based policy engine in production.
"""
from __future__ import annotations

import logging
from typing import Any

import yaml

from app.integrations.ports import PolicyPort, PolicyContext, PolicyDecision

logger = logging.getLogger(__name__)

# Operations explicitly allowed in local dev without extra configuration.
# Everything else is DENIED by default.
_DEFAULT_ALLOWED: set[tuple[str, str]] = {
    ("browser", "search"),
    ("browser", "navigate"),
    ("browser", "extract"),
    ("downloads", "request"),
    ("downloads", "status"),
    ("apis", "execute"),
    ("mcp", "list_servers"),
    ("mcp", "list_tools"),
    ("mcp", "invoke"),
    ("payments", "validate"),
    ("payments", "status"),
    ("health", "check"),
}


class LocalPolicyAdapter(PolicyPort):
    """
    Development policy adapter.
    DEFAULTS TO DENY.
    Allows the operations listed in _DEFAULT_ALLOWED and YAML configs.
    """

    def __init__(self, config_path: str | None = None) -> None:
        self._allowed: set[tuple[str, str]] = set(_DEFAULT_ALLOWED)
        if config_path:
            self._load_yaml(config_path)

    def _load_yaml(self, path: str) -> None:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            allowed = data.get("policy", {}).get("allowed_operations", [])
            for entry in allowed:
                cap = entry.get("capability", "")
                op = entry.get("operation", "")
                if cap and op:
                    self._allowed.add((cap, op))
        except Exception as e:
            logger.warning("LocalPolicyAdapter: could not load %s: %s", path, e)

    async def authorize(self, context: PolicyContext) -> PolicyDecision:
        key = (context.capability, context.operation)
        if key in self._allowed:
            return PolicyDecision(
                allowed=True,
                policy_id="LOCAL-POLICY-ALLOW",
                reason=f"Local dev policy: {context.capability}.{context.operation} allowed",
            )

        logger.info(
            "LocalPolicyAdapter DENY: agent=%s cap=%s op=%s",
            context.agent_id,
            context.capability,
            context.operation,
        )
        return PolicyDecision(
            allowed=False,
            policy_id="LOCAL-POLICY-DENY",
            reason=(
                f"[LOCAL DEV] Operation '{context.capability}.{context.operation}' "
                f"is not explicitly allowed. Add it to local policy or replace with "
                f"Person 4's OPA engine."
            ),
        )
