"""Capability permission service for AgentShield.

Provides server-side enforcement of agent-scoped capability permissions:
enabled state, allowed tools, resource scope, domain restrictions, and
human approval requirements. All checks are organization-scoped and
persisted in PostgreSQL.
"""

from __future__ import annotations

import logging
from typing import Any

from app.db.base import get_db_session
from app.db.models import Agent, AgentCapability, ApprovalRequest, Capability

logger = logging.getLogger(__name__)


class CapabilityDecision:
    """Result of a capability check."""

    def __init__(
        self,
        *,
        allowed: bool,
        require_approval: bool = False,
        reason: str | None = None,
        capability_key: str | None = None,
        capability_id: str | None = None,
    ) -> None:
        self.allowed = allowed
        self.require_approval = require_approval
        self.reason = reason
        self.capability_key = capability_key
        self.capability_id = capability_id

    def __bool__(self) -> bool:
        return self.allowed


class CapabilityService:
    """Server-side capability permission enforcement."""

    def __init__(self, db=None) -> None:
        self._db = db
        self._own_db = False

    def _ensure_db(self):
        if self._db is None:
            try:
                self._db = get_db_session()
                self._own_db = True
            except RuntimeError:
                self._db = None

    def _release_db(self):
        if self._own_db and self._db is not None:
            try:
                self._db.close()
            except Exception:
                pass
            self._own_db = False
            self._db = None

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def _get_agent_capabilities(
        self, db, agent: Agent
    ) -> list[tuple[AgentCapability, Capability]]:
        if db is None:
            return []
        return (
            db.query(AgentCapability, Capability)
            .join(Capability, AgentCapability.capability_id == Capability.id)
            .filter(
                AgentCapability.agent_id == agent.id,
                Capability.is_active == True,  # noqa: E712
            )
            .all()
        )

    def _find_capability(
        self,
        db,
        agent: Agent,
        capability_key: str | None = None,
        tool_name: str | None = None,
    ) -> tuple[AgentCapability, Capability] | None:
        """Find the AgentCapability for a given capability key or tool name."""
        if db is None:
            return None
        caps = self._get_agent_capabilities(db, agent)
        for ac, cap in caps:
            if capability_key and cap.key == capability_key:
                return (ac, cap)
            if tool_name and cap.tools and tool_name in (cap.tools or []):
                return (ac, cap)
        return None

    # ------------------------------------------------------------------
    # Core enforcement
    # ------------------------------------------------------------------

    def check_capability(
        self,
        *,
        agent: Agent,
        organization_id: str,
        capability_key: str | None = None,
        tool_name: str | None = None,
        target: str | None = None,
        tool_args: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        """Check whether an agent may invoke a capability/tool.

        Checks (in order):
        1. AgentCapability exists and is enabled
        2. Tool is in allowed_tools
        3. Resource scope allows the target
        4. Domain restrictions allow the target
        5. If require_approval, return require_approval=True

        When no database session is available, permits by default (falls back
        to the caller's legacy permission check).
        """
        self._ensure_db()
        db = self._db
        # No database available: cannot enforce capabilities, permit by default.
        if db is None:
            return CapabilityDecision(
                allowed=True,
                reason="no database; capability enforcement deferred",
            )
        try:
            # Organization ownership check
            if str(agent.organization_id) != organization_id:
                return CapabilityDecision(
                    allowed=False,
                    reason="agent does not belong to organization",
                )

            # Find the capability
            found = self._find_capability(db, agent, capability_key=capability_key, tool_name=tool_name)
            if found is None:
                return CapabilityDecision(
                    allowed=False,
                    reason=f"no capability configured for {capability_key or tool_name}",
                )

            ac, cap = found

            # Enabled check
            if not ac.enabled:
                return CapabilityDecision(
                    allowed=False,
                    reason=f"capability '{cap.key}' is disabled",
                    capability_key=cap.key,
                    capability_id=str(cap.id),
                )

            # Tool check
            if tool_name and ac.allowed_tools and tool_name not in (ac.allowed_tools or []):
                return CapabilityDecision(
                    allowed=False,
                    reason=f"tool '{tool_name}' not allowed for capability '{cap.key}'",
                    capability_key=cap.key,
                    capability_id=str(cap.id),
                )

            # Resource scope check
            if target and ac.resource_scope:
                if not self._target_in_scope(target, ac.resource_scope):
                    return CapabilityDecision(
                        allowed=False,
                        reason=f"target '{target}' outside resource scope for capability '{cap.key}'",
                        capability_key=cap.key,
                        capability_id=str(cap.id),
                    )

            # Domain restriction check
            if target and ac.allowed_domains:
                if not self._domain_allowed(target, ac.allowed_domains):
                    return CapabilityDecision(
                        allowed=False,
                        reason=f"domain of '{target}' not allowed for capability '{cap.key}'",
                        capability_key=cap.key,
                        capability_id=str(cap.id),
                    )

            # Approval requirement
            if ac.require_approval:
                return CapabilityDecision(
                    allowed=False,
                    require_approval=True,
                    reason=f"capability '{cap.key}' requires human approval",
                    capability_key=cap.key,
                    capability_id=str(cap.id),
                )

            return CapabilityDecision(
                allowed=True,
                reason=f"capability '{cap.key}' permitted",
                capability_key=cap.key,
                capability_id=str(cap.id),
            )
        finally:
            self._release_db()

    # ------------------------------------------------------------------
    # Scope helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _target_in_scope(target: str | None, resource_scope: list[str]) -> bool:
        """Check if a target URL/path is within the allowed resource scope."""
        if not target:
            return True
        if not resource_scope:
            return True
        from urllib.parse import urlparse

        try:
            parsed = urlparse(target)
        except Exception:
            return False
        path = parsed.path or "/"
        for pattern in resource_scope:
            pattern = pattern.strip()
            if not pattern:
                continue
            if pattern == "*" or pattern == "/**":
                return True
            if pattern.endswith("/**"):
                prefix = pattern[:-3]
                if path == prefix or path.startswith(prefix + "/"):
                    return True
            if path == pattern or path.startswith(pattern.rstrip("/") + "/"):
                return True
        return False

    @staticmethod
    def _domain_allowed(target: str | None, allowed_domains: list[str]) -> bool:
        """Check if a target's domain is in the allowed domains list."""
        if not target:
            return True
        if not allowed_domains:
            return True
        from urllib.parse import urlparse

        try:
            parsed = urlparse(target)
        except Exception:
            return False
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            return True
        for domain in allowed_domains:
            domain = domain.strip().lower().rstrip(".")
            if not domain:
                continue
            if domain.startswith("*."):
                suffix = domain[1:]  # ".example.com"
                if hostname == suffix[1:] or hostname.endswith(suffix):
                    return True
            if hostname == domain:
                return True
        return False

    # ------------------------------------------------------------------
    # Approval queue
    # ------------------------------------------------------------------

    def create_approval_request(
        self,
        *,
        db,
        agent: Agent,
        organization_id: str,
        capability: Capability,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        target: str | None = None,
        requested_by: str | None = None,
    ) -> ApprovalRequest:
        """Create a pending approval request."""
        if str(agent.organization_id) != organization_id:
            raise ValueError("agent does not belong to organization")
        approval = ApprovalRequest(
            organization_id=organization_id,
            agent_id=agent.id,
            capability_id=capability.id,
            tool_name=tool_name,
            tool_args=tool_args or {},
            target=target,
            status="pending",
            requested_by=requested_by,
        )
        db.add(approval)
        db.flush()
        return approval
