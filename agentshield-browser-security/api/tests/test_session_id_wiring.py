"""A2 — session ID propagation from the API to the browser worker.

These are mocked tests: the worker is either the FakeWorkerClient stub or an
httpx.MockTransport. They prove the API-side contract (validation, forwarding,
non-interference with authorization). Real worker and real Chromium coverage
lives in worker/test/session_id.test.js, worker/test/security_integration.test.js
and api/tests/integration/test_worker_integration.py.
"""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.clients.browser_worker import BrowserWorkerClient, BrowserWorkerPolicyError
from app.main import create_app
from tests.conftest import (
    FakeContentInspector,
    FakePolicyEngine,
    FakeWorkerClient,
    make_settings,
    make_test_app,
)

VALID_SESSION_IDS = [
    "conv-42",
    "agent.session:7",
    "A_b-C.0:9",
    "x" * 128,
]

# Each of these would either be reinterpreted by a lenient parser or smuggle
# something into the outbound header, so the API must refuse them outright.
MALFORMED_SESSION_IDS = [
    pytest.param("", id="empty"),
    pytest.param(" ", id="single-space"),
    pytest.param("conv 42", id="inner-space"),
    pytest.param("conv/42", id="path-separator"),
    pytest.param("conv/../etc", id="traversal-shaped"),
    pytest.param("conv\n42", id="embedded-newline"),
    pytest.param("conv\r\nX-Injected: 1\r\n", id="header-injection"),
    pytest.param("conv\t42", id="embedded-tab"),
    pytest.param("sessioné", id="non-ascii"),
    pytest.param("x" * 129, id="over-long"),
    pytest.param("<script>alert(1)</script>", id="html-payload"),
]


def worker_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "request_id": "req-1",
            "requested_url": "https://example.com/",
            "final_url": "https://example.com/",
            "status_code": 200,
            "title": "Example",
            "content": "<html></html>",
            "content_truncated": False,
            "elapsed_ms": 10,
        },
    )


def build_client(handler, **overrides) -> BrowserWorkerClient:
    return BrowserWorkerClient(
        make_settings(**overrides), transport=httpx.MockTransport(handler)
    )


async def call_navigate(client: BrowserWorkerClient, **kwargs) -> None:
    try:
        await client.navigate(**kwargs)
    finally:
        await client.aclose()


BASE_CALL = {
    "url": "https://example.com/",
    "wait_until": "load",
    "timeout_ms": 5000,
    "request_id": "req-1",
}


# ---------------------------------------------------------------------------
# 1. The API forwards the exact session ID
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("session_id", VALID_SESSION_IDS)
def test_navigate_forwards_session_id_unchanged(test_app, fake_worker, session_id):
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/", "session_id": session_id},
        )

    assert response.status_code == 200
    assert fake_worker.navigate_calls[0]["session_id"] == session_id


async def test_worker_client_puts_identity_on_the_wire_verbatim():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["payload"] = json.loads(request.content)
        return worker_response()

    await call_navigate(
        build_client(handler), **BASE_CALL, session_id="conv-42"
    )

    assert captured["headers"]["x-agent-session"] == "conv-42"
    # The identity is a header only: the worker's body contract is unchanged.
    assert "session_id" not in captured["payload"]


async def test_worker_client_keeps_identity_alongside_credentials():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return worker_response()

    await call_navigate(
        build_client(handler, worker_auth_token="worker-secret"),
        **BASE_CALL,
        session_id="conv-42",
    )

    assert captured["headers"]["authorization"] == "Bearer worker-secret"
    assert captured["headers"]["x-agent-session"] == "conv-42"


# ---------------------------------------------------------------------------
# 3 / 7. Missing session ID keeps the documented compatibility behavior
# ---------------------------------------------------------------------------


def test_navigate_without_session_id_is_unchanged(test_app, fake_worker):
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={
                "url": "https://example.com/",
                "wait_until": "load",
                "timeout_ms": 5000,
            },
        )

    assert response.status_code == 200
    assert fake_worker.navigate_calls[0]["session_id"] is None
    assert fake_worker.navigate_calls[0]["timeout_ms"] == 5000


async def test_worker_client_omits_identity_header_when_absent():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return worker_response()

    await call_navigate(build_client(handler), **BASE_CALL)

    assert "x-agent-session" not in captured["headers"]


def test_api_does_not_generate_a_session_id(test_app, fake_worker):
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate", json={"url": "https://example.com/"}
        )

    assert response.status_code == 200
    assert fake_worker.navigate_calls[0]["session_id"] is None


# ---------------------------------------------------------------------------
# 4. Malformed session IDs are rejected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("session_id", MALFORMED_SESSION_IDS)
def test_malformed_session_id_rejected(test_app, fake_worker, session_id):
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/", "session_id": session_id},
        )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "session_id"]
    # Rejected at the schema, so the worker is never reached with a bad identity.
    assert fake_worker.navigate_calls == []


def test_non_string_session_id_rejected(test_app):
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/", "session_id": 12345},
        )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 5 / 8. An identity is not a credential and does not relax policy
# ---------------------------------------------------------------------------


def test_session_id_does_not_bypass_api_authentication(fake_worker):
    app = make_test_app(make_settings(api_auth_token="api-secret"), fake_worker)

    with TestClient(app) as client:
        unauthenticated = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/", "session_id": "conv-42"},
        )

    assert unauthenticated.status_code == 401
    assert fake_worker.navigate_calls == []

    with TestClient(app) as client:
        authenticated = client.post(
            "/v1/browser/navigate",
            headers={"Authorization": "Bearer api-secret"},
            json={"url": "https://example.com/", "session_id": "conv-42"},
        )

    assert authenticated.status_code == 200
    assert fake_worker.navigate_calls[0]["session_id"] == "conv-42"


def test_session_id_does_not_bypass_domain_policy(fake_worker):
    policy = FakePolicyEngine(allowed=False, reason="destination not permitted")
    app = create_app(
        make_settings(),
        browser_client=fake_worker,
        policy_engine=policy,
        content_inspector=FakeContentInspector(),
    )

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/", "session_id": "victim-session"},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "policy_denied"
    assert fake_worker.navigate_calls == []


def test_policy_decision_is_made_without_the_identity(fake_worker):
    policy = FakePolicyEngine()
    app = create_app(
        make_settings(),
        browser_client=fake_worker,
        policy_engine=policy,
        content_inspector=FakeContentInspector(),
    )

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/", "session_id": "conv-42"},
        )

    assert response.status_code == 200
    assert not any("conv-42" in str(value) for value in vars(policy.calls[0]).values())


async def test_worker_client_maps_auth_failure_even_with_identity():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={
                "error": "unauthorized",
                "code": "WORKER_AUTH_FAILED",
                "message": "worker authentication failed",
            },
        )

    client = build_client(handler, worker_auth_token="wrong-token")
    with pytest.raises(BrowserWorkerPolicyError) as raised:
        await call_navigate(client, **BASE_CALL, session_id="conv-42")

    assert raised.value.code == "WORKER_AUTH_FAILED"
    assert raised.value.status_code == 401


def test_worker_auth_failure_maps_unchanged_through_the_route():
    worker = FakeWorkerClient()
    worker.navigate_error = BrowserWorkerPolicyError(
        "WORKER_AUTH_FAILED", "worker authentication failed", status_code=401
    )
    app = make_test_app(make_settings(), worker)

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/", "session_id": "conv-42"},
        )

    assert response.status_code == 502
    assert response.json()["detail"]["code"] == "WORKER_AUTH_FAILED"


def test_session_id_not_echoed_in_response(test_app, fake_worker):
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/", "session_id": "conv-secret-42"},
        )

    assert "session_id" not in response.json()
    assert "conv-secret-42" not in response.text


def test_blocked_navigation_does_not_leak_identity(fake_worker):
    app = make_test_app(make_settings(allowed_domains="example.com"), fake_worker)

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://blocked.test/", "session_id": "conv-42"},
        )

    assert response.status_code == 403
    assert "conv-42" not in response.text
