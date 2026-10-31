"""Real policy engine that enforces domain allowlist/denylist.

This is a production policy backend that wraps the domain policy logic
to produce explicit authorization decisions with proper provenance.
"""

from __future__ import annotations

import logging

from app.interfaces.policy import PolicyDecision, PolicyEngine, PolicyRequest
from app.security.domain_policy import DomainPolicy

logger = logging.getLogger(__name__)


class RealPolicyEngine(PolicyEngine):
    """Production policy engine backed by domain allowlist/denylist.

    Enforces domain policy decisions with explicit ALLOW/DENY outcomes.
    This complements (does not replace) the NetworkPreflight URL/DNS/IP
    validation that runs before authorization.
    """

    def __init__(
        self,
        *,
        allowed_domains: str = "",
        blocked_domains: str = "",
        default_domain_policy: str = "deny",
    ) -> None:
        self._domain_policy = DomainPolicy(
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
            default_policy=default_domain_policy,
        )

    async def authorize(self, request: PolicyRequest) -> PolicyDecision:
        from urllib.parse import urlparse

        parsed = urlparse(request.url)
        hostname = (parsed.hostname or "").lower().rstrip(".")

        try:
            self._domain_policy.evaluate(hostname)
        except Exception as exc:
            logger.info(
                "policy_denied",
                extra={
                    "request_id": request.request_id,
                    "hostname": hostname,
                    "reason": str(exc),
                },
            )
            return PolicyDecision(
                allowed=False,
                policy_name="egress-domain-policy",
                reason=str(exc),
            )

        logger.info(
            "policy_allowed",
            extra={
                "request_id": request.request_id,
                "hostname": hostname,
            },
        )
        return PolicyDecision(
            allowed=True,
            policy_name="egress-domain-policy",
            reason="destination is permitted by domain policy",
        )
