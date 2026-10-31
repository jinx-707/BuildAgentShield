"""Tests for API authentication and authorization."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.middleware import ApiAuthMiddleware, RateLimitMiddleware, RequestContextMiddleware
from fastapi import FastAPI
from fastapi.responses import JSONResponse


def make_test_app(token: str = "") -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(ApiAuthMiddleware, api_auth_token=token)
    app.add_middleware(RateLimitMiddleware, max_per_minute=100, enabled=True)

    @app.get("/health/live")
    def health():
        return {"status": "ok"}

    @app.get("/online/downloads")
    def protected():
        return {"data": "secret"}

    return app


class TestBearerTokenAuth:
    def test_protected_endpoint_requires_token(self):
        app = make_test_app(token="secret-token")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/online/downloads")
        assert resp.status_code == 401
        assert resp.json()["code"] == "API_AUTH_REQUIRED"

    def test_valid_token_grants_access(self):
        app = make_test_app(token="secret-token")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/online/downloads",
            headers={"Authorization": "Bearer secret-token"},
        )
        assert resp.status_code == 200

    def test_wrong_token_denied(self):
        app = make_test_app(token="secret-token")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/online/downloads",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401
        assert resp.json()["code"] == "API_AUTH_FAILED"

    def test_missing_bearer_prefix_denied(self):
        app = make_test_app(token="secret-token")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/online/downloads",
            headers={"Authorization": "secret-token"},
        )
        assert resp.status_code == 401

    def test_health_endpoint_always_accessible(self):
        app = make_test_app(token="secret-token")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health/live")
        assert resp.status_code == 200

    def test_auth_disabled_when_no_token_configured(self):
        app = make_test_app(token="")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/online/downloads")
        assert resp.status_code == 200


class TestRateLimiting:
    def test_rate_limit_exceeded(self):
        app = FastAPI()
        app.add_middleware(RequestContextMiddleware)
        app.add_middleware(ApiAuthMiddleware, api_auth_token="")
        app.add_middleware(RateLimitMiddleware, max_per_minute=2, enabled=True)

        @app.get("/test")
        def test_endpoint():
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        client.get("/test")
        client.get("/test")
        resp = client.get("/test")  # 3rd request should be rate-limited
        assert resp.status_code == 429
        assert resp.json()["code"] == "RATE_LIMIT_EXCEEDED"

    def test_health_exempt_from_rate_limit(self):
        app = FastAPI()
        app.add_middleware(RequestContextMiddleware)
        app.add_middleware(RateLimitMiddleware, max_per_minute=1, enabled=True)

        @app.get("/health/live")
        def health():
            return {"status": "ok"}

        client = TestClient(app, raise_server_exceptions=False)
        for _ in range(10):
            resp = client.get("/health/live")
            assert resp.status_code == 200


class TestRequestId:
    def test_request_id_propagated_in_response(self):
        app = FastAPI()
        app.add_middleware(RequestContextMiddleware)

        @app.get("/test")
        def test_endpoint():
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/test", headers={"X-Request-ID": "my-request-id"})
        assert resp.headers.get("x-request-id") == "my-request-id"

    def test_request_id_generated_when_absent(self):
        app = FastAPI()
        app.add_middleware(RequestContextMiddleware)

        @app.get("/test")
        def test_endpoint():
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/test")
        assert "x-request-id" in resp.headers
        assert len(resp.headers["x-request-id"]) > 0
