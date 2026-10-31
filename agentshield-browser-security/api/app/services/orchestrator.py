from app.clients.browser_worker import BrowserWorkerClient
from app.interfaces.inspection import ContentInspectionRequest, ContentInspector
from app.interfaces.policy import PolicyEngine
from app.schemas.browser import (
    BrowserNavigateRequest,
    BrowserNavigateResponse,
    PolicyRequest,
)
from app.security.errors import SecurityViolation
from app.security.preflight import NetworkPreflight


class PolicyDeniedError(Exception):
    def __init__(self, reason: str, policy_name: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.policy_name = policy_name


class RedirectDestinationBlockedError(Exception):
    """Raised when the worker's final_url (after redirects) is not permitted."""

    def __init__(self, final_url: str) -> None:
        super().__init__(
            f"redirect destination is not permitted by policy: {final_url}"
        )
        self.final_url = final_url


class BrowserSecurityOrchestrator:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        content_inspector: ContentInspector,
        worker_client: BrowserWorkerClient,
        network_preflight: NetworkPreflight,
    ) -> None:
        self._policy_engine = policy_engine
        self._content_inspector = content_inspector
        self._worker_client = worker_client
        self._network_preflight = network_preflight

    async def navigate(
        self,
        request: BrowserNavigateRequest,
        *,
        request_id: str,
        agent_id: str | None = None,
        organization_id: str | None = None,
    ) -> BrowserNavigateResponse:
        validated_url = await self._network_preflight.validate(str(request.url))

        decision = await self._policy_engine.authorize(
            PolicyRequest(
                request_id=request_id,
                url=validated_url.url,
                organization_id=organization_id,
                agent_id=agent_id,
            )
        )
        if not decision.allowed:
            raise PolicyDeniedError(
                reason=decision.reason, policy_name=decision.policy_name
            )

        worker_result = await self._worker_client.navigate(
            url=validated_url.url,
            wait_until=request.wait_until,
            timeout_ms=request.timeout_ms,
            request_id=request_id,
            session_id=request.session_id,
            agent_id=agent_id,
        )

        # Defense in depth: re-validate the final URL after redirects.
        # The worker and proxy enforce redirect policy, but the API
        # independently verifies the destination to ensure a blocked
        # destination cannot reach the caller via a redirect chain.
        if worker_result.final_url and worker_result.final_url != validated_url.url:
            try:
                await self._network_preflight.validate(worker_result.final_url)
            except SecurityViolation:
                raise RedirectDestinationBlockedError(worker_result.final_url)

        inspection = await self._content_inspector.inspect(
            ContentInspectionRequest(
                request_id=request_id,
                url=worker_result.final_url,
                content=worker_result.content,
            )
        )

        return BrowserNavigateResponse(
            request_id=request_id,
            requested_url=worker_result.requested_url,
            final_url=worker_result.final_url,
            status_code=worker_result.status_code,
            title=worker_result.title,
            content=worker_result.content,
            content_truncated=worker_result.content_truncated,
            elapsed_ms=worker_result.elapsed_ms,
            redirect_count=worker_result.redirect_count,
            blocked_request_count=worker_result.blocked_request_count,
            blocked_target_count=getattr(
                worker_result, "blocked_target_count", 0
            ),
            policy=decision,
            inspection=inspection,
        )
