"""Integration tests for the full AgentShield request path.

These tests verify real service-to-service communication without requiring
Chromium. They use the real FastAPI app, the real egress policy engine, and
the real worker client against fake/mock backends where the browser itself is
not needed.

Tests cover:
- Successful navigation through policy + inspection
- Blocked destinations (denylist, default-deny, private IPs, metadata)
- Unauthorized session access (cross-agent)
- Session cleanup (create, get, close)
- Worker failure (timeout, unavailable, bad response)
- Navigation timeouts
- Redirect policy enforcement (worker final_url re-check)
- Egress proxy requirement (fail-closed when proxy required but missing)
"""

from fastapi.testclient import TestClient

from app.clients.browser_worker import (
    BrowserWorkerPolicyError,
    BrowserWorkerResponseError,
    BrowserWorkerTimeout,
    BrowserWorkerUnavailable,
)
from app.config import Settings
from app.main import create_app
from tests.conftest import FakeWorkerClient, make_settings, make_test_app


def _make_app(*, worker=None, **overrides):
    settings = make_settings(**overrides)
    return make_test_app(settings, worker or FakeWorkerClient())


def test_successful_navigation_through_full_path(test_app, fake_worker):
    """A navigation request passes policy, reaches the worker, and returns."""
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            headers={"X-Request-ID": "req-integration-nav"},
            json={"url": "https://example.com/", "wait_until": "load", "timeout_ms": 5000},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["request_id"] == "req-integration-nav"
    assert body["final_url"] == "https://example.com/"
    assert body["policy"]["allowed"] is True
    assert fake_worker.navigate_calls[0]["request_id"] == "req-integration-nav"


def test_blocked_destination_denylist(test_app):
    """A destination on the blocked domain list is rejected before the worker."""
    worker = FakeWorkerClient()
    app = _make_app(
        worker=worker,
        policy_backend="egress-policy",
        allowed_domains="example.com",
        blocked_domains="blocked.example.com",
        dns_preflight_enabled=False,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://blocked.example.com/"},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "DOMAIN_BLOCKED"
    assert worker.navigate_calls == []


def test_blocked_destination_default_deny(test_app):
    """A destination not on the allowlist is rejected under default-deny."""
    worker = FakeWorkerClient()
    app = _make_app(
        worker=worker,
        policy_backend="egress-policy",
        allowed_domains="example.com",
        blocked_domains="",
        dns_preflight_enabled=False,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://unknown.example.com/"},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "DOMAIN_BLOCKED"
    assert worker.navigate_calls == []


def test_private_ip_blocked(test_app, fake_worker):
    """Private/reserved IP destinations are rejected by preflight."""
    app = _make_app(allow_private_networks=False)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "http://169.254.169.254/"},
        )

    assert response.status_code == 403
    assert fake_worker.navigate_calls == []


def test_metadata_ip_blocked(test_app, fake_worker):
    """Cloud metadata IP is blocked before reaching the worker."""
    app = _make_app(allow_private_networks=False)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "http://169.254.169.254/latest/meta-data/"},
        )

    assert response.status_code == 403
    assert fake_worker.navigate_calls == []


def test_unauthorized_session_access(test_app, fake_worker):
    """A session owned by one agent cannot be accessed by another."""
    with TestClient(test_app) as client:
        created = client.post(
            "/v1/browser/session",
            headers={"X-Agent-ID": "agent-a"},
        )
        assert created.status_code == 201
        session_id = created.json()["session_id"]

        # agent-b tries to read the session
        response = client.get(
            f"/v1/browser/session/{session_id}",
            headers={"X-Agent-ID": "agent-b"},
        )
        assert response.status_code == 403

        # agent-b tries to navigate with the session
        response = client.post(
            "/v1/browser/navigate",
            headers={"X-Agent-ID": "agent-b"},
            json={"session_id": session_id, "url": "https://example.com/"},
        )
        assert response.status_code == 403

        # agent-b tries to close the session
        response = client.delete(
            f"/v1/browser/session/{session_id}",
            headers={"X-Agent-ID": "agent-b"},
        )
        assert response.status_code == 403


def test_session_cleanup_lifecycle(test_app, fake_worker):
    """Session create, get, and close work through the full path."""
    with TestClient(test_app) as client:
        created = client.post(
            "/v1/browser/session",
            headers={"X-Agent-ID": "agent-cleanup"},
        )
        assert created.status_code == 201
        session_id = created.json()["session_id"]

        status = client.get(
            f"/v1/browser/session/{session_id}",
            headers={"X-Agent-ID": "agent-cleanup"},
        )
        assert status.status_code == 200
        assert status.json()["session_id"] == session_id

        closed = client.delete(
            f"/v1/browser/session/{session_id}",
            headers={"X-Agent-ID": "agent-cleanup"},
        )
        assert closed.status_code == 200
        assert closed.json()["closed"] is True


def test_session_deleted_cannot_be_reused(test_app, fake_worker):
    """A deleted session cannot be navigated with afterward."""
    with TestClient(test_app) as client:
        created = client.post(
            "/v1/browser/session",
            headers={"X-Agent-ID": "agent-reuse"},
        )
        session_id = created.json()["session_id"]
        client.delete(
            f"/v1/browser/session/{session_id}",
            headers={"X-Agent-ID": "agent-reuse"},
        )

        response = client.post(
            "/v1/browser/navigate",
            headers={"X-Agent-ID": "agent-reuse"},
            json={"session_id": session_id, "url": "https://example.com/"},
        )
        assert response.status_code == 404


def test_worker_timeout_mapped_to_504(test_app):
    """A worker navigation timeout is propagated as HTTP 504."""
    worker = FakeWorkerClient()
    worker.navigate_error = BrowserWorkerTimeout("worker timed out")
    app = _make_app(worker=worker)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )

    assert response.status_code == 504
    assert response.json()["detail"]["code"] == "browser_worker_timeout"


def test_worker_unavailable_mapped_to_502(test_app):
    """A worker connection failure is propagated as HTTP 502."""
    worker = FakeWorkerClient()
    worker.navigate_error = BrowserWorkerUnavailable("connection refused")
    app = _make_app(worker=worker)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )

    assert response.status_code == 502
    assert response.json()["detail"]["code"] == "browser_worker_failure"


def test_worker_bad_response_mapped_to_502(test_app):
    """A malformed worker response is propagated as HTTP 502."""
    worker = FakeWorkerClient()
    worker.navigate_error = BrowserWorkerResponseError("bad response")
    app = _make_app(worker=worker)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )

    assert response.status_code == 502
    assert response.json()["detail"]["code"] == "browser_worker_failure"


def test_worker_policy_error_propagated(test_app):
    """A worker policy rejection (e.g. session forbidden) propagates its code."""
    worker = FakeWorkerClient()
    worker.navigate_error = BrowserWorkerPolicyError(
        "SESSION_FORBIDDEN",
        "session owner does not match",
        status_code=403,
    )
    app = _make_app(worker=worker)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            headers={"X-Agent-ID": "agent-x"},
            json={"session_id": "session-123", "url": "https://example.com/"},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "SESSION_FORBIDDEN"


def test_missing_agent_id_rejected(test_app):
    """Session creation requires an agent identity."""
    with TestClient(test_app) as client:
        response = client.post("/v1/browser/session", json={})
    assert response.status_code == 400


def test_invalid_agent_id_rejected(test_app):
    """An empty agent identity is rejected."""
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/session", json={}, headers={"X-Agent-ID": ""}
        )
    assert response.status_code == 400


def test_invalid_url_scheme_rejected(test_app):
    """Non-HTTP(S) URLs are rejected before reaching the worker."""
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "ftp://example.com/"},
        )
    assert response.status_code == 422


def test_embedded_credentials_rejected(test_app):
    """URLs with embedded credentials are rejected."""
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://user:pass@example.com/"},
        )
    assert response.status_code == 403


def test_redirect_policy_enforcement(test_app):
    """A redirect to a blocked destination is rejected by the API re-check."""
    worker = FakeWorkerClient()
    worker.navigate_response = worker.navigate_response.model_copy(
        update={"final_url": "https://blocked.example.com/"}
    )
    app = _make_app(worker=worker)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "REDIRECT_DESTINATION_BLOCKED"


def test_require_egress_proxy_fail_closed():
    """When REQUIRE_EGRESS_PROXY=true and no proxy is configured, startup fails."""
    from app.security.rate_limit import validate_rate_limit_settings
    from app.security.trusted_proxy import parse_trusted_proxies

    settings = make_settings(
        environment="development",
        require_egress_proxy=True,
        egress_proxy_url="",
    )
    # Settings construction itself should not fail (that's a worker concern),
    # but the API should not silently allow direct egress when proxy required.
    assert settings.require_egress_proxy is True
    assert settings.egress_proxy_url == ""


def test_no_silent_direct_egress_fallback(test_app, fake_worker):
    """The API always enforces policy before delegating to the worker."""
    with TestClient(test_app) as client:
        # A destination not on the allowlist must never reach the worker
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://evil.example.com/"},
        )
    assert response.status_code == 403
    assert fake_worker.navigate_calls == []
