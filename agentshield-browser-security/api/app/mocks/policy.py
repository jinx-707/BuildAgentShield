from urllib.parse import urlparse

from app.schemas.browser import PolicyDecision, PolicyRequest


class MockPolicyEngine:
    """Development-only policy engine. It is not a security control."""

    name = "mock-policy"

    async def authorize(self, request: PolicyRequest) -> PolicyDecision:
        parsed = urlparse(request.url)

        if parsed.scheme not in {"http", "https"}:
            return PolicyDecision(
                allowed=False,
                policy_name=self.name,
                reason="Only HTTP and HTTPS URLs are permitted by the mock policy.",
            )

        if parsed.username or parsed.password:
            return PolicyDecision(
                allowed=False,
                policy_name=self.name,
                reason="URLs containing embedded credentials are not permitted.",
            )

        if not parsed.hostname:
            return PolicyDecision(
                allowed=False,
                policy_name=self.name,
                reason="The URL must include a hostname.",
            )

        return PolicyDecision(
            allowed=True,
            policy_name=self.name,
            reason="Allowed by the development-only mock policy.",
        )
