"""API contract tests for A3 sessions, B1 extraction and C1 search."""

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from app.clients.browser_worker import BrowserWorkerPolicyError
from app.clients.search_provider import (
    SearchProviderNotConfigured,
    SearchProviderRateLimited,
    SearchProviderResponseError,
    SearchProviderTimeout,
)
from app.main import create_app
from tests.conftest import (
    FakeContentInspector,
    FakePolicyEngine,
    FakeSearchProvider,
    FakeWorkerClient,
    make_settings,
    make_test_app,
)

AGENT = {"X-Agent-ID": "agent-42"}


def app_with(worker=None, provider=None, **settings):
    worker = worker or FakeWorkerClient()
    provider = provider or FakeSearchProvider()
    app = make_test_app(make_settings(**settings), worker, search_provider=provider)
    return app, worker, provider


# ---------------------------------------------------------------------------
# A3 session lifecycle
# ---------------------------------------------------------------------------


def test_create_session_requires_agent_identity():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post("/v1/browser/session", json={})

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_AGENT_ID"
    assert worker.create_session_calls == []


def test_create_session_forwards_identity_and_bounds():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/session",
            headers=AGENT,
            json={"idle_timeout_ms": 60000, "max_age_ms": 120000},
        )

    assert response.status_code == 201
    assert response.json()["session_id"] == "session-123"
    call = worker.create_session_calls[0]
    assert call["agent_id"] == "agent-42"
    assert call["idle_timeout_ms"] == 60000
    assert call["max_age_ms"] == 120000
    assert call["request_id"]


def test_get_and_close_session_forward_identity():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        get_response = client.get("/v1/browser/session/session-123", headers=AGENT)
        close_response = client.delete(
            "/v1/browser/session/session-123", headers=AGENT
        )

    assert get_response.status_code == 200
    assert close_response.status_code == 200
    assert close_response.json()["closed"] is True
    assert worker.get_session_calls[0]["agent_id"] == "agent-42"
    assert worker.get_session_calls[0]["session_id"] == "session-123"
    assert worker.close_session_calls[0]["agent_id"] == "agent-42"


@pytest.mark.parametrize("session_id", ["bad id", "x" * 129, "bad%20id"])
def test_session_path_rejects_malformed_ids(session_id):
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.get(f"/v1/browser/session/{session_id}", headers=AGENT)

    assert response.status_code == 422
    assert worker.get_session_calls == []


def test_session_owner_mismatch_is_not_rewritten_to_forbidden():
    worker = FakeWorkerClient()
    worker.session_error = BrowserWorkerPolicyError(
        "SESSION_FORBIDDEN", "session is not owned by this agent", status_code=403
    )
    app, _, _ = app_with(worker=worker)
    with TestClient(app) as client:
        response = client.get("/v1/browser/session/session-123", headers=AGENT)

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "SESSION_FORBIDDEN"


def test_session_limit_maps_to_service_unavailable():
    worker = FakeWorkerClient()
    worker.session_error = BrowserWorkerPolicyError(
        "SESSION_LIMIT_EXCEEDED", "too many sessions", status_code=503
    )
    app, _, _ = app_with(worker=worker)
    with TestClient(app) as client:
        response = client.post("/v1/browser/session", headers=AGENT, json={})

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "SESSION_LIMIT_EXCEEDED"


# ---------------------------------------------------------------------------
# B1 extraction
# ---------------------------------------------------------------------------


def test_extract_requires_agent_identity():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/extract", json={"session_id": "session-123"}
        )

    assert response.status_code == 400
    assert worker.extract_calls == []


def test_extract_forwards_identity_and_marks_content_untrusted():
    inspector = FakeContentInspector()
    worker = FakeWorkerClient()
    app = create_app(
        make_settings(),
        browser_client=worker,
        content_inspector=inspector,
        search_provider=FakeSearchProvider(),
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/extract",
            headers=AGENT,
            json={"session_id": "session-123"},
        )

    assert response.status_code == 200
    body = response.json()
    assert worker.extract_calls[0]["agent_id"] == "agent-42"
    assert worker.extract_calls[0]["session_id"] == "session-123"
    assert body["security"]["trust_label"] == "untrusted"
    assert body["content"]["text"] == "Visible page text"
    assert body["content"]["byte_length"] == len("Visible page text")
    assert body["security"]["hidden_content_excluded"] is True
    assert "HIDDEN_CONTENT_EXCLUDED" in body["security"]["warnings"]
    assert "UNTRUSTED_PAGE_CONTENT" in body["security"]["warnings"]
    assert inspector.calls[0].content == "Visible page text"
    assert body["metadata"]["canonical_url"] == "https://example.com/"


def test_extract_busy_session_maps_to_conflict():
    worker = FakeWorkerClient()
    worker.extract_error = BrowserWorkerPolicyError(
        "SESSION_CHECKED_OUT", "session is busy", status_code=409
    )
    app, _, _ = app_with(worker=worker)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/extract",
            headers=AGENT,
            json={"session_id": "session-123"},
        )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "SESSION_CHECKED_OUT"


# ---------------------------------------------------------------------------
# C1 search
# ---------------------------------------------------------------------------


@dataclass
class UrlDenyPolicy(FakePolicyEngine):
    denied_url: str = ""

    async def authorize(self, request):
        self.calls.append(request)
        from app.schemas.browser import PolicyDecision

        if str(request.url).startswith(self.denied_url):
            return PolicyDecision(
                allowed=False,
                policy_name="test-deny",
                reason="destination not permitted",
            )
        return PolicyDecision(
            allowed=True,
            policy_name=self.name,
            reason=self.reason,
        )


def make_hits():
    from app.clients.search_provider import SearchHit

    return [
        SearchHit(
            title="Allowed result",
            url="https://example.com/page",
            snippet="A safe snippet",
            position=1,
        ),
        SearchHit(
            title="Blocked result",
            url="https://evil.test/page",
            snippet="A malicious snippet",
            position=2,
        ),
    ]


def test_search_returns_only_prevalidated_results_and_inspects_text():
    inspector = FakeContentInspector()
    provider = FakeSearchProvider(hits=make_hits())
    app = create_app(
        make_settings(allowed_domains="example.com"),
        browser_client=FakeWorkerClient(),
        policy_engine=FakePolicyEngine(),
        content_inspector=inspector,
        search_provider=provider,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/search",
            json={"query": "test query", "max_results": 2},
        )

    assert response.status_code == 200
    body = response.json()
    assert provider.calls[0] == {
        "query": "test query",
        "max_results": 2,
        "safe_search": True,
    }
    assert [r["url"] for r in body["results"]] == ["https://example.com/page"]
    assert body["filtered_count"] == 1
    assert body["trust_label"] == "untrusted"
    assert body["results"][0]["trust_label"] == "untrusted"
    assert body["results"][0]["source"] == "example.com"
    assert body["provider_mode"] == "full"
    assert "Allowed result" in inspector.calls[0].content
    assert "Blocked result" not in inspector.calls[0].content


def test_search_applies_policy_denial_to_results():
    provider = FakeSearchProvider(
        hits=[
            make_hits()[0],
            make_hits()[1],
        ]
    )
    policy = UrlDenyPolicy(denied_url="https://")
    app = create_app(
        make_settings(allowed_domains="example.com,evil.test"),
        browser_client=FakeWorkerClient(),
        policy_engine=policy,
        content_inspector=FakeContentInspector(),
        search_provider=provider,
    )
    with TestClient(app) as client:
        response = client.post("/v1/browser/search", json={"query": "test"})

    assert response.status_code == 200
    assert response.json()["results"] == []
    assert response.json()["filtered_count"] == 2


def test_search_caps_requested_results_at_operator_limit():
    provider = FakeSearchProvider(hits=make_hits())
    app, _, _ = app_with(provider=provider, search_max_results=3)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/search",
            json={"query": "test", "max_results": 20},
        )

    assert response.status_code == 200
    assert provider.calls[0]["max_results"] == 3


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (SearchProviderNotConfigured("missing key"), 503, "SEARCH_NOT_CONFIGURED"),
        (SearchProviderTimeout("timeout"), 504, "SEARCH_PROVIDER_TIMEOUT"),
        (
            SearchProviderRateLimited("limited", retry_after=7),
            429,
            "SEARCH_PROVIDER_RATE_LIMITED",
        ),
        (
            SearchProviderResponseError("bad json"),
            502,
            "SEARCH_PROVIDER_INVALID_RESPONSE",
        ),
    ],
)
def test_search_provider_failures_are_mapped(error, status, code):
    provider = FakeSearchProvider(error=error)
    app, _, _ = app_with(provider=provider)
    with TestClient(app) as client:
        response = client.post("/v1/browser/search", json={"query": "test"})

    assert response.status_code == status
    assert response.json()["detail"]["code"] == code
    if status == 429:
        assert response.headers["retry-after"] == "7"


def test_blank_search_query_is_rejected():
    app, _, _ = app_with()
    with TestClient(app) as client:
        response = client.post("/v1/browser/search", json={"query": "   "})

    assert response.status_code == 422


def test_navigate_forwards_agent_identity_for_session_ownership():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            headers=AGENT,
            json={
                "url": "https://example.com/",
                "session_id": "session-123",
            },
        )

    assert response.status_code == 200
    assert worker.navigate_calls[0]["agent_id"] == "agent-42"
    assert worker.navigate_calls[0]["session_id"] == "session-123"


def test_navigate_rejects_malformed_agent_identity_before_worker():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            headers={"X-Agent-ID": "agent a;drop"},
            json={"url": "https://example.com/"},
        )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_AGENT_ID"
    assert "agent a;drop" not in response.text
    assert worker.navigate_calls == []
