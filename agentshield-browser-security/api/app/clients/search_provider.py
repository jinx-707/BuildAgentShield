"""Search provider abstraction and real provider clients (C1).

Only fixed, operator-selected provider endpoints are contacted. No caller
controlled URL is ever passed to these clients, so a search request cannot be
turned into an SSRF primitive. API keys live in SecretStr settings and are sent
only in provider headers; they are never included in errors or responses.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Protocol

import httpx

from app.config import Settings

_ZERO_WIDTH = re.compile(r"[\u200b-\u200d\u2060\ufeff]")
_TAG = re.compile(r"<[^>]{0,500}>")
_WHITESPACE = re.compile(r"\s+")

BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
DUCKDUCKGO_ENDPOINT = "https://api.duckduckgo.com/"


class SearchProviderError(Exception):
    """Base error for search provider failures."""


class SearchProviderNotConfigured(SearchProviderError):
    pass


class SearchProviderAuthError(SearchProviderError):
    pass


class SearchProviderTimeout(SearchProviderError):
    pass


class SearchProviderRateLimited(SearchProviderError):
    def __init__(self, message: str, *, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class SearchProviderUnavailable(SearchProviderError):
    pass


class SearchProviderResponseError(SearchProviderError):
    pass


@dataclass(frozen=True)
class SearchHit:
    title: str
    url: str
    snippet: str
    position: int


class SearchProvider(Protocol):
    name: str
    mode: str
    notice: str | None
    endpoint: str

    async def search(
        self, *, query: str, max_results: int, safe_search: bool
    ) -> list[SearchHit]:
        """Return normalized provider hits in ranking order."""

    async def aclose(self) -> None:
        ...


def _clean_text(value: object, *, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = html.unescape(_TAG.sub(" ", value))
    text = _ZERO_WIDTH.sub("", text)
    text = _WHITESPACE.sub(" ", text).strip()
    return text[:limit]


def _retry_after(response: httpx.Response) -> int | None:
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    try:
        return max(0, int(raw))
    except ValueError:
        return None


class BraveSearchClient:
    name = "brave"
    mode = "full"
    notice = None
    endpoint = BRAVE_ENDPOINT

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = settings.search_api_key.get_secret_value()
        self._timeout = settings.search_timeout_ms / 1000.0
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def search(
        self, *, query: str, max_results: int, safe_search: bool
    ) -> list[SearchHit]:
        if not self._api_key:
            raise SearchProviderNotConfigured(
                "search provider is not configured: SEARCH_API_KEY is empty"
            )

        params = {
            "q": query,
            "count": str(max_results),
            "safesearch": "strict" if safe_search else "moderate",
            "text_decorations": "0",
            "spellcheck": "0",
        }
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": self._api_key,
        }
        try:
            response = await self._client.get(
                self.endpoint, params=params, headers=headers
            )
        except httpx.TimeoutException as exc:
            raise SearchProviderTimeout("search provider request timed out") from exc
        except httpx.HTTPError as exc:
            raise SearchProviderUnavailable("search provider is unavailable") from exc

        if response.status_code == 429:
            raise SearchProviderRateLimited(
                "search provider rate limit exceeded",
                retry_after=_retry_after(response),
            )
        if response.status_code in {401, 403}:
            raise SearchProviderAuthError(
                "search provider rejected the configured credentials"
            )
        if response.status_code >= 500:
            raise SearchProviderUnavailable("search provider is unavailable")
        if response.status_code not in {200, 202}:
            raise SearchProviderResponseError(
                f"search provider returned HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise SearchProviderResponseError(
                "search provider returned invalid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise SearchProviderResponseError(
                "search provider returned an invalid response"
            )
        web = payload.get("web")
        if not isinstance(web, dict) or not isinstance(web.get("results"), list):
            raise SearchProviderResponseError(
                "search provider response is missing web results"
            )

        hits: list[SearchHit] = []
        for entry in web["results"]:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url")
            title = entry.get("title")
            if not isinstance(url, str) or not url:
                continue
            hits.append(
                SearchHit(
                    title=_clean_text(title, limit=500) or url,
                    url=url.strip(),
                    snippet=_clean_text(entry.get("description"), limit=2000),
                    position=len(hits) + 1,
                )
            )
        return hits


class DuckDuckGoInstantAnswerClient:
    """Limited keyless fallback. This is NOT full web search."""

    name = "duckduckgo-instant-answer"
    mode = "limited_fallback"
    notice = (
        "DuckDuckGo Instant Answer is a limited keyless fallback: it returns "
        "instant answers and related topics only, not full web search results."
    )
    endpoint = DUCKDUCKGO_ENDPOINT

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._timeout = settings.search_timeout_ms / 1000.0
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def search(
        self, *, query: str, max_results: int, safe_search: bool
    ) -> list[SearchHit]:
        params = {
            "q": query,
            "format": "json",
            "no_html": "1",
            "no_redirect": "1",
            "skip_disambig": "1",
        }
        try:
            response = await self._client.get(self.endpoint, params=params)
        except httpx.TimeoutException as exc:
            raise SearchProviderTimeout("search provider request timed out") from exc
        except httpx.HTTPError as exc:
            raise SearchProviderUnavailable("search provider is unavailable") from exc

        if response.status_code == 429:
            raise SearchProviderRateLimited(
                "search provider rate limit exceeded",
                retry_after=_retry_after(response),
            )
        if response.status_code >= 500:
            raise SearchProviderUnavailable("search provider is unavailable")
        if response.status_code not in {200, 202}:
            raise SearchProviderResponseError(
                f"search provider returned HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise SearchProviderResponseError(
                "search provider returned invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise SearchProviderResponseError(
                "search provider returned an invalid response"
            )

        hits: list[SearchHit] = []
        abstract_url = payload.get("AbstractURL")
        abstract_text = payload.get("AbstractText")
        if isinstance(abstract_url, str) and abstract_url:
            hits.append(
                SearchHit(
                    title=_clean_text(payload.get("Heading"), limit=500)
                    or abstract_url,
                    url=abstract_url.strip(),
                    snippet=_clean_text(abstract_text, limit=2000),
                    position=1,
                )
            )

        def add_topics(topics: object) -> None:
            if not isinstance(topics, list):
                return
            for topic in topics:
                if len(hits) >= max_results:
                    return
                if not isinstance(topic, dict):
                    continue
                if isinstance(topic.get("Topics"), list):
                    add_topics(topic["Topics"])
                    continue
                url = topic.get("FirstURL")
                text = topic.get("Text")
                if not isinstance(url, str) or not url:
                    continue
                title = _clean_text(text, limit=500) or url
                hits.append(
                    SearchHit(
                        title=title,
                        url=url.strip(),
                        snippet=_clean_text(text, limit=2000),
                        position=len(hits) + 1,
                    )
                )

        add_topics(payload.get("RelatedTopics"))
        return hits[:max_results]


def build_search_provider(settings: Settings) -> SearchProvider:
    if settings.search_provider == "brave":
        return BraveSearchClient(settings)
    if settings.search_provider == "duckduckgo":
        return DuckDuckGoInstantAnswerClient(settings)
    raise ValueError(f"unsupported search provider: {settings.search_provider}")
