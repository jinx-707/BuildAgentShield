"""Database-backed policy engine for AgentShield enterprise control plane.

Resolves the effective policy for a navigation request from PostgreSQL,
querying the active organization-level or agent-specific policy. This is what
makes dashboard policy changes take effect in the real enforcement path:
every navigation is evaluated against the policy stored in the database, not
against static environment variables.

Organization-scoped: an agent can only be evaluated against policies belonging
to its own organization, preventing cross-tenant policy access.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.db.base import get_db_session
from app.db.models import Agent, Organization, Policy
from app.interfaces.policy import PolicyDecision, PolicyEngine, PolicyRequest
from app.security.domain_policy import DomainPolicy

logger = logging.getLogger(__name__)


class DatabasePolicyEngine(PolicyEngine):
    """Policy engine that resolves effective policy from the database."""

    name = "database-policy-engine"

    def __init__(
        self,
        *,
        allowed_domains: str = "",
        blocked_domains: str = "",
        default_domain_policy: str = "deny",
        allowed_ports: str = "80,443",
        allow_private_networks: bool = False,
    ) -> None:
        # Fallback policy used when no database policy is found (e.g. before an
        # organization has created one). Fail-closed by default.
        self._fallback = DomainPolicy(
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
            default_policy=default_domain_policy,
        )
        self._allowed_ports = allowed_ports
        self._allow_private_networks = allow_private_networks

    async def authorize(self, request: PolicyRequest) -> PolicyDecision:
        policy = self._get_effective_policy(
            organization_id=request.organization_id,
            agent_id=request.agent_id,
        )
        if policy is None:
            return self._decide(
                request.request_id,
                allowed=False,
                policy_name="database-policy-engine",
                reason="no active policy for organization",
            )

        domain_policy = DomainPolicy(
            allowed_domains=",".join(policy.allowed_domains or []),
            blocked_domains=",".join(policy.blocked_domains or []),
            default_policy=policy.default_domain_policy or "deny",
        )
        hostname = self._hostname(request.url)
        try:
            domain_policy.evaluate(hostname)
        except Exception as exc:
            logger.info(
                "policy_denied",
                extra={"request_id": request.request_id, "hostname": hostname, "reason": str(exc)},
            )
            return self._decide(
                request.request_id,
                allowed=False,
                policy_name=f"database-policy:{policy.id}",
                reason=str(exc),
            )

        return self._decide(
            request.request_id,
            allowed=True,
            policy_name=f"database-policy:{policy.id}",
            reason="destination is permitted by database policy",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_effective_policy(
        self,
        *,
        organization_id: Optional[str],
        agent_id: Optional[str],
    ) -> Optional[Policy]:
        if not organization_id:
            return None
        db = get_db_session()
        try:
            # Agent-specific policy takes precedence, but only if the agent
            # belongs to the requesting organization.
            if agent_id:
                agent = (
                    db.query(Agent)
                    .filter(Agent.agent_id == agent_id)
                    .first()
                )
                if agent and str(agent.organization_id) == organization_id:
                    agent_policy = (
                        db.query(Policy)
                        .filter(
                            Policy.agent_id == agent.id,
                            Policy.organization_id == organization_id,
                            Policy.is_active == True,  # noqa: E712
                        )
                        .order_by(Policy.version.desc())
                        .first()
                    )
                    if agent_policy:
                        return agent_policy

            # Fall back to the organization's active default policy.
            org_policy = (
                db.query(Policy)
                .filter(
                    Policy.organization_id == organization_id,
                    Policy.agent_id.is_(None),
                    Policy.is_active == True,  # noqa: E712
                )
                .order_by(Policy.version.desc())
                .first()
            )
            return org_policy
        finally:
            db.close()

    @staticmethod
    def _hostname(url: str) -> str:
        from urllib.parse import urlparse

        return (urlparse(url).hostname or "").lower().rstrip(".")

    @staticmethod
    def _decide(
        request_id: str,
        *,
        allowed: bool,
        policy_name: str,
        reason: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=allowed,
            policy_name=policy_name,
            reason=reason,
        )
