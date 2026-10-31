"""API authentication tests.

Covers ApiAuthMiddleware and the production fail-closed guard in Settings.

Test matrix:
- Settings construction: production + empty token raises; production + token OK;
  development + empty token OK; test + empty token OK.
- Missing Authorization header → 401 with WWW-Authenticate.
- Malformed header (no "Bearer " prefix) → 401.
- Incorrect token → 401.
- Correct token → request reaches handler (non-401).
- Empty token value ("Bearer ") → 401.
- Token that is a prefix of the correct token → 401.
- Health endpoints (/health/live, /health, /health/ready) → 200/503 without token.
- Navigation endpoint cannot execute without authentication (401 before any
  URL validation or worker call).
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.main import create_app
from tests.conftest import FakeWorkerClient, make_settings, make_test_app

TOKEN = "test-api-secret-token"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _app_with_auth(token: str = TOKEN):
    """Build a test app with API auth enabled."""
    settings = make_settings(api_auth_token=token)
    return make_test_app(settings, FakeWorkerClient())


def _app_no_auth():
    """Build a test app with API auth disabled (empty token, non-production)."""
    settings = make_settings(api_auth_token="")
    return make_test_app(settings, FakeWorkerClient())


# ---------------------------------------------------------------------------
# Settings / startup fail-closed tests
# ---------------------------------------------------------------------------


def test_production_startup_fails_without_api_auth_token():
    """Settings(environment='production') with no token must raise at construction."""
    with pytest.raises(ValidationError, match="API_AUTH_TOKEN must be set in production"):
        Settings(
            _env_file=None,
            environment="production",
            api_auth_token="",
            browser_worker_url="http://worker.test:8080",
            allowed_domains="example.com",
        )


def test_production_startup_succeeds_with_api_auth_token():
    """Settings(environment='production') with a token must construct without error."""
    settings = Settings(
        _env_file=None,
        environment="production",
        api_auth_token="prod-secret",
        jwt_secret="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        browser_worker_url="http://worker.test:8080",
        allowed_domains="example.com",
        policy_backend="egress-policy",
        inspection_backend="prompt-injection",
    )
    assert settings.api_auth_token == "prod-secret"
    assert settings.environment == "production"


def test_development_startup_succeeds_without_api_auth_token():
    """Development environments must not be blocked by the production guard."""
    settings = Settings(
        _env_file=None,
        environment="development",
        api_auth_token="",
        browser_worker_url="http://worker.test:8080",
    )
    assert settings.api_auth_token == ""


def test_test_environment_startup_succeeds_without_api_auth_token():
    """Test environments must not be blocked by the production guard."""
    settings = make_settings(api_auth_token="")
    assert settings.api_auth_token == ""


# ---------------------------------------------------------------------------
# 401 rejection cases (auth enabled)
# ---------------------------------------------------------------------------


def test_navigate_rejects_missing_authorization_header():
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )
    assert resp.status_code == 401
    assert resp.json()["code"] == "API_AUTH_REQUIRED"


def test_navigate_rejects_malformed_header_no_bearer_prefix():
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            headers={"Authorization": TOKEN},  # missing "Bearer " prefix
        )
    assert resp.status_code == 401
    assert resp.json()["code"] == "API_AUTH_REQUIRED"


def test_navigate_rejects_wrong_token():
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            headers={"Authorization": "Bearer wrong-token"},
        )
    assert resp.status_code == 401
    assert resp.json()["code"] == "API_AUTH_FAILED"


def test_navigate_rejects_empty_token_value():
    """Authorization: Bearer  (token is empty string after prefix) → 401."""
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            headers={"Authorization": "Bearer "},
        )
    assert resp.status_code == 401


def test_navigate_rejects_prefix_of_correct_token():
    """A token that is a strict prefix of the correct token must be rejected."""
    app = _app_with_auth()
    prefix = TOKEN[:-1]
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            headers={"Authorization": f"Bearer {prefix}"},
        )
    assert resp.status_code == 401


def test_navigate_rejects_token_with_extra_suffix():
    """A token with extra characters appended must be rejected."""
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            headers={"Authorization": f"Bearer {TOKEN}x"},
        )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# WWW-Authenticate header on 401 responses
# ---------------------------------------------------------------------------


def test_401_missing_header_includes_www_authenticate():
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


def test_401_wrong_token_includes_www_authenticate():
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            headers={"Authorization": "Bearer bad"},
        )
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


# ---------------------------------------------------------------------------
# Correct token passes through to handler
# ---------------------------------------------------------------------------


def test_navigate_correct_token_reaches_handler():
    """A valid token must not return 401 — the request reaches navigation logic."""
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
    # Auth passes; any non-401 is acceptable (200 from fake worker expected here)
    assert resp.status_code != 401


def test_navigate_correct_token_returns_200_with_fake_worker():
    """End-to-end: correct token + fake worker returns a successful navigation."""
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["final_url"] == "https://example.com/"
    assert "policy" in body
    assert "inspection" in body


# ---------------------------------------------------------------------------
# Navigation logic unreachable without auth
# ---------------------------------------------------------------------------


def test_navigate_without_auth_never_calls_worker():
    """Unauthenticated requests must be stopped at middleware — worker is never invoked."""
    worker = FakeWorkerClient()
    settings = make_settings(api_auth_token=TOKEN)
    app = make_test_app(settings, worker)

    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            # No Authorization header
        )

    assert resp.status_code == 401
    # The fake worker records every navigate() call — it must not have been called
    assert worker.navigate_calls == [], (
        f"worker.navigate() was called despite failed auth: {worker.navigate_calls}"
    )


# ---------------------------------------------------------------------------
# Health endpoints exempt from authentication
# ---------------------------------------------------------------------------


def test_health_live_accessible_without_token():
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_health_alias_accessible_without_token():
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/health")
    assert resp.status_code == 200


def test_health_ready_accessible_without_token():
    """Readiness endpoint must be reachable without a token (returns 200 or 503,
    never 401)."""
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/health/ready")
    assert resp.status_code != 401


def test_health_live_accessible_even_with_wrong_token():
    """A wrong token on a health path must not trigger auth rejection."""
    app = _app_with_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get(
            "/health/live",
            headers={"Authorization": "Bearer wrong"},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Auth disabled in non-production (empty token)
# ---------------------------------------------------------------------------


def test_auth_disabled_allows_unauthenticated_requests():
    """When api_auth_token is empty in non-production, all requests are allowed."""
    app = _app_no_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
            # No Authorization header
        )
    # Auth is disabled; must not return 401
    assert resp.status_code != 401


def test_auth_disabled_health_still_works():
    app = _app_no_auth()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/health/live")
    assert resp.status_code == 200
