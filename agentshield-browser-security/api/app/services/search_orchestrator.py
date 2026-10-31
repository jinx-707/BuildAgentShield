from datetime import datetime, timezone
from urllib.parse import urlparse

from app.clients.search_provider import SearchProvider
from app.interfaces.inspection import ContentInspectionRequest, ContentInspector
from app.interfaces.policy import PolicyEngine
from app.schemas.browser import PolicyRequest
from app.schemas.search import SearchRequest, SearchResponse, SearchResult
from app.security.errors import SecurityViolation
from app.security.preflight import NetworkPreflight


class SearchOrchestrator:
    """Run a provider search and return only pre-validated destinations.

    Every result URL is passed through the same NetworkPreflight and policy
    engine as a navigation request. A result whose destination is blocked is
    dropped from the response and counted in filtered_count; it is never
    presented to the caller as a navigable result. Provider titles and snippets
    are always untrusted and are inspected with the configured prompt-injection
    detector.
    """

    def __init__(
        self,
        *,
        provider: SearchProvider,
        network_preflight: NetworkPreflight,
        policy_engine: PolicyEngine,
        content_inspector: ContentInspector,
        max_results: int,
    ) -> None:
        self._provider = provider
        self._network_preflight = network_preflight
        self._policy_engine = policy_engine
        self._content_inspector = content_inspector
        self._max_results = max_results

    async def search(
        self, request: SearchRequest, *, request_id: str
    ) -> SearchResponse:
        started = datetime.now(timezone.utc)
        requested_max = min(
            request.max_results or self._max_results, self._max_results
        )

        hits = await self._provider.search(
            query=request.query,
            max_results=requested_max,
            safe_search=request.safe_search,
        )

        results: list[SearchResult] = []
        filtered_count = 0
        for hit in hits:
            if len(results) >= requested_max:
                break
            try:
                validated = await self._network_preflight.validate(hit.url)
                decision = await self._policy_engine.authorize(
                    PolicyRequest(request_id=request_id, url=validated.url)
                )
            except SecurityViolation:
                filtered_count += 1
                continue

            if not decision.allowed:
                filtered_count += 1
                continue

            parsed = urlparse(validated.url)
            source = (parsed.hostname or "").lower()
            if not source:
                filtered_count += 1
                continue

            results.append(
                SearchResult(
                    title=hit.title,
                    url=validated.url,
                    snippet=hit.snippet,
                    source=source,
                    position=hit.position,
                    retrieved_at=started,
                    trust_label="untrusted",
                )
            )

        inspection = await self._content_inspector.inspect(
            ContentInspectionRequest(
                request_id=request_id,
                url=f"search://{self._provider.name}",
                content="\n".join(
                    f"{result.title}\n{result.snippet}" for result in results
                ),
            )
        )

        elapsed_ms = int(
            (datetime.now(timezone.utc) - started).total_seconds() * 1000
        )
        return SearchResponse(
            request_id=request_id,
            query=request.query,
            provider=self._provider.name,
            provider_mode=self._provider.mode,
            provider_notice=self._provider.notice,
            results=results,
            filtered_count=filtered_count,
            results_truncated=len(hits) > requested_max,
            elapsed_ms=elapsed_ms,
            trust_label="untrusted",
            inspection=inspection,
        )
