"""
Pluggable web search service.
Supports: Serper, Brave Search, Mock (for testing).
Does NOT automate search engine pages — uses approved APIs only.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.core.result_models import SearchResult, SearchResults

logger = logging.getLogger(__name__)


class SearchProvider(ABC):
    """Abstract search provider interface."""

    @abstractmethod
    async def search(
        self,
        query: str,
        num_results: int = 10,
        safe_search: bool = True,
    ) -> SearchResults:
        ...


class SerperSearchProvider(SearchProvider):
    """
    Google Search via Serper.dev API.
    Requires SERPER_API_KEY environment variable.
    """

    BASE_URL = "https://google.serper.dev/search"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def search(
        self,
        query: str,
        num_results: int = 10,
        safe_search: bool = True,
    ) -> SearchResults:
        payload = {
            "q": query,
            "num": min(num_results, 10),
            "safe": "active" if safe_search else "off",
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self.BASE_URL,
                json=payload,
                headers={
                    "X-API-KEY": self._api_key,
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        results = []
        for i, item in enumerate(data.get("organic", []), start=1):
            url = item.get("link", "")
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            results.append(
                SearchResult(
                    title=item.get("title", ""),
                    url=url,
                    snippet=item.get("snippet", ""),
                    domain=domain,
                    position=i,
                )
            )

        return SearchResults(
            query=query,
            provider="serper",
            results=results,
            total=len(results),
        )


class BraveSearchProvider(SearchProvider):
    """
    Brave Search API.
    Requires BRAVE_SEARCH_API_KEY environment variable.
    """

    BASE_URL = "https://api.search.brave.com/res/v1/web/search"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def search(
        self,
        query: str,
        num_results: int = 10,
        safe_search: bool = True,
    ) -> SearchResults:
        params: dict[str, Any] = {
            "q": query,
            "count": min(num_results, 20),
            "safesearch": "strict" if safe_search else "off",
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                self.BASE_URL,
                params=params,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip",
                    "X-Subscription-Token": self._api_key,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        results = []
        web = data.get("web", {}).get("results", [])
        for i, item in enumerate(web, start=1):
            url = item.get("url", "")
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            results.append(
                SearchResult(
                    title=item.get("title", ""),
                    url=url,
                    snippet=item.get("description", ""),
                    domain=domain,
                    position=i,
                )
            )

        return SearchResults(
            query=query,
            provider="brave",
            results=results,
            total=len(results),
        )


class MockSearchProvider(SearchProvider):
    """
    Mock search provider for testing.
    Returns synthetic results. Does NOT make real network calls.
    """

    async def search(
        self,
        query: str,
        num_results: int = 10,
        safe_search: bool = True,
    ) -> SearchResults:
        results = [
            SearchResult(
                title=f"Mock Result {i}: {query}",
                url=f"https://example.com/result/{i}",
                snippet=f"This is a mock search result for query: {query}",
                domain="example.com",
                position=i,
            )
            for i in range(1, min(num_results, 5) + 1)
        ]
        return SearchResults(
            query=query,
            provider="mock",
            results=results,
            total=len(results),
        )


def create_search_provider(provider_name: str, **kwargs: Any) -> SearchProvider:
    """Factory — creates the configured search provider."""
    if provider_name == "serper":
        api_key = kwargs.get("api_key", "")
        if not api_key:
            raise ValueError("Serper API key required")
        return SerperSearchProvider(api_key=api_key)
    elif provider_name == "brave":
        api_key = kwargs.get("api_key", "")
        if not api_key:
            raise ValueError("Brave Search API key required")
        return BraveSearchProvider(api_key=api_key)
    elif provider_name == "mock":
        return MockSearchProvider()
    else:
        raise ValueError(f"Unknown search provider: {provider_name}")
