"""C1 provider clients: fixed endpoints, key handling, normalization."""

import httpx
import pytest

from app.clients.search_provider import (
    BraveSearchClient,
    DuckDuckGoInstantAnswerClient,
    SearchProviderAuthError,
    SearchProviderNotConfigured,
    SearchProviderRateLimited,
    SearchProviderResponseError,
    SearchProviderTimeout,
    SearchProviderUnavailable,
)
from tests.conftest import make_settings


def brave_settings(**overrides):
    values = {
        "search_provider": "brave",
        "search_api_key": "brave-secret",
        "search_timeout_ms": 1000,
    }
    values.update(overrides)
    return make_settings(**values)


async def test_brave_uses_fixed_endpoint_and_sends_key_only_in_header():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url.copy_with(query=None))
        captured["params"] = dict(request.url.params)
        captured["headers"] = dict(request.headers)
        return httpx.Response(
            200,
            json={
                "web": {
                    "results": [
                        {
                            "title": "<b>Hello</b> \u200bworld",
                            "url": "https://example.com/a",
                            "description": "A <em>snippet</em>",
                        },
                        {"title": "No URL"},
                    ]
                }
            },
        )

    client = BraveSearchClient(
        brave_settings(), transport=httpx.MockTransport(handler)
    )
    try:
        hits = await client.search(
            query="safe query", max_results=3, safe_search=True
        )
    finally:
        await client.aclose()

    assert captured["url"] == "https://api.search.brave.com/res/v1/web/search"
    assert captured["params"]["q"] == "safe query"
    assert captured["params"]["count"] == "3"
    assert captured["params"]["safesearch"] == "strict"
    assert captured["headers"]["x-subscription-token"] == "brave-secret"
    assert "brave-secret" not in str(captured["params"])
    assert len(hits) == 1
    assert hits[0].title == "Hello world"
    assert hits[0].snippet == "A snippet"
    assert hits[0].url == "https://example.com/a"


async def test_brave_without_key_fails_before_any_request():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"web": {"results": []}})

    client = BraveSearchClient(
        brave_settings(search_api_key=""), transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(SearchProviderNotConfigured):
            await client.search(query="q", max_results=3, safe_search=True)
    finally:
        await client.aclose()

    assert called is False


@pytest.mark.parametrize(
    ("status", "error", "retry_after"),
    [
        (401, SearchProviderAuthError, None),
        (403, SearchProviderAuthError, None),
        (429, SearchProviderRateLimited, 9),
        (500, SearchProviderUnavailable, None),
        (502, SearchProviderUnavailable, None),
        (400, SearchProviderResponseError, None),
    ],
)
async def test_brave_maps_provider_statuses(status, error, retry_after):
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"retry-after": str(retry_after)} if retry_after else {}
        return httpx.Response(status, headers=headers, json={"error": "x"})

    client = BraveSearchClient(
        brave_settings(), transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(error) as caught:
            await client.search(query="q", max_results=3, safe_search=True)
    finally:
        await client.aclose()

    if retry_after is not None:
        assert caught.value.retry_after == retry_after


async def test_brave_maps_timeout_and_invalid_json():
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client = BraveSearchClient(
        brave_settings(), transport=httpx.MockTransport(timeout_handler)
    )
    try:
        with pytest.raises(SearchProviderTimeout):
            await client.search(query="q", max_results=3, safe_search=True)
    finally:
        await client.aclose()

    def invalid_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    client = BraveSearchClient(
        brave_settings(), transport=httpx.MockTransport(invalid_handler)
    )
    try:
        with pytest.raises(SearchProviderResponseError):
            await client.search(query="q", max_results=3, safe_search=True)
    finally:
        await client.aclose()


async def test_brave_rejects_response_without_web_results():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query": "q"})

    client = BraveSearchClient(
        brave_settings(), transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(SearchProviderResponseError):
            await client.search(query="q", max_results=3, safe_search=True)
    finally:
        await client.aclose()


@pytest.mark.parametrize("status", [200, 202])
async def test_duckduckgo_is_explicitly_limited_and_normalizes_topics(status):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url.copy_with(query=None))
        return httpx.Response(
            status,
            json={
                "Heading": "Test",
                "AbstractURL": "https://example.com/abstract",
                "AbstractText": "An abstract",
                "RelatedTopics": [
                    {
                        "FirstURL": "https://example.com/one",
                        "Text": "Topic one",
                    },
                    {
                        "Name": "Group",
                        "Topics": [
                            {
                                "FirstURL": "https://example.com/two",
                                "Text": "Topic two",
                            }
                        ],
                    },
                ],
            },
        )

    client = DuckDuckGoInstantAnswerClient(
        make_settings(search_provider="duckduckgo"),
        transport=httpx.MockTransport(handler),
    )
    try:
        hits = await client.search(
            query="q", max_results=2, safe_search=True
        )
    finally:
        await client.aclose()

    assert captured["url"] == "https://api.duckduckgo.com/"
    assert client.mode == "limited_fallback"
    assert "not full web search" in client.notice
    assert [hit.url for hit in hits] == [
        "https://example.com/abstract",
        "https://example.com/one",
    ]
    assert hits[0].title == "Test"


def test_search_api_key_is_masked_in_settings_representation():
    settings = brave_settings(search_api_key="super-secret-key")
    assert "super-secret-key" not in repr(settings)
    assert "super-secret-key" not in str(settings.search_api_key)
    assert settings.search_api_key.get_secret_value() == "super-secret-key"
