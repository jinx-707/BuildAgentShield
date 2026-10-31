"""
AgentShield Offline — Local Development Policy Adapter.

⚠️  DEVELOPMENT COMPONENT — NOT FOR PRODUCTION USE ⚠️

This adapter enforces filesystem-level workspace and permission policies
locally without requiring Person 4's OPA / policy engine.

It is intentionally simple: it reads agent workspace configurations from
the offline_policy.yaml file and enforces deny-by-default behaviour.

When Person 4's central policy engine is available, replace this adapter
through the dependency injection container in app/api/dependencies.py.
See docs/integration_guide.md for instructions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import structlog

from app.core.configuration import get_settings, load_yaml_config
from app.core.contracts import FileOperation, SecurityDecision
from app.integrations.ports import PolicyPort

log = structlog.get_logger(__name__)

# Operations that map to permission categories
_OP_PERMISSION_MAP: dict[str, str] = {
    FileOperation.READ: "read",
    FileOperation.SEARCH: "read",
    FileOperation.LIST: "read",
    FileOperation.CREATE: "write",
    FileOperation.WRITE: "write",
    FileOperation.DELETE: "delete",
    FileOperation.MOVE: "write",
    FileOperation.COPY: "read",
}


class LocalFilesystemPolicyAdapter:
    """
    Local development implementation of PolicyPort.

    Reads agent workspace configs from offline_policy.yaml.
    Enforces directory-scoped read/write/delete permissions.
    Returns DENY for any operation not explicitly permitted.
    """

    _ADAPTER_NOTE = (
        "LOCAL_DEVELOPMENT_POLICY — replace with Person 4's OPA adapter in production"
    )

    def __init__(self) -> None:
        self._settings = get_settings()
        self._config = load_yaml_config(self._settings.offline_policy_path)
        self._agents: dict[str, dict] = {}
        self._load_agents()
        log.info(
            "local_policy_adapter_loaded",
            agents=list(self._agents.keys()),
            note=self._ADAPTER_NOTE,
        )

    def _load_agents(self) -> None:
        agents_cfg = self._config.get("agents", [])
        for cfg in agents_cfg:
            agent_id = cfg.get("agent_id", "")
            if agent_id:
                self._agents[agent_id] = cfg

    def get_agent_config(self, agent_id: str) -> Optional[dict]:
        return self._agents.get(agent_id)

    def get_workspace(self, agent_id: str) -> Optional[str]:
        cfg = self.get_agent_config(agent_id)
        if cfg:
            return cfg.get("workspace")
        # Fall back to global default
        return self._settings.default_workspace

    def get_permitted_paths(self, agent_id: str, permission: str) -> list[str]:
        """Return list of permitted absolute paths for a given permission."""
        cfg = self.get_agent_config(agent_id)
        if not cfg:
            return []
        return cfg.get("permissions", {}).get(permission, [])

    async def authorize(
        self,
        *,
        agent_id: str,
        tenant_id: str,
        operation: str,
        resource: str,
        context: Optional[dict[str, Any]] = None,
    ) -> SecurityDecision:
        permission = _OP_PERMISSION_MAP.get(operation, operation)
        permitted = self.get_permitted_paths(agent_id, permission)
        resource_path = Path(resource).resolve()

        for p in permitted:
            try:
                resource_path.relative_to(Path(p).resolve())
                log.info(
                    "policy_allow",
                    agent_id=agent_id,
                    operation=operation,
                    resource=resource,
                )
                return SecurityDecision.ALLOW
            except ValueError:
                continue

        log.warning(
            "policy_deny",
            agent_id=agent_id,
            operation=operation,
            resource=resource,
            adapter=self._ADAPTER_NOTE,
        )
        return SecurityDecision.DENY


class DenyAllPolicyAdapter:
    """
    A fail-safe policy adapter that denies every request.
    Used when no policy configuration is available.
    """

    async def authorize(
        self,
        *,
        agent_id: str,
        tenant_id: str,
        operation: str,
        resource: str,
        context: Optional[dict[str, Any]] = None,
    ) -> SecurityDecision:
        log.warning(
            "deny_all_policy_active",
            agent_id=agent_id,
            operation=operation,
            resource=resource,
        )
        return SecurityDecision.DENY
