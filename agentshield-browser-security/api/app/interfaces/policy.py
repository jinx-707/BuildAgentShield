from typing import Protocol

from app.schemas.browser import PolicyDecision, PolicyRequest


class PolicyEngine(Protocol):
    name: str

    async def authorize(self, request: PolicyRequest) -> PolicyDecision:
        """Return an authorization decision for a browser navigation request."""
        ...
