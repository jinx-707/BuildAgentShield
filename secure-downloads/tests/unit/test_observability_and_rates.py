"""
Observability and tenant-aware rate-limit tests (Prompt 3, Phase 3F).

Verifies the middleware contract directly: request IDs are always returned,
completion logs carry no credentials or request bodies, and the limiter keeps
independent per-IP and per-tenant budgets that neither identifier can evade
alone.
"""
from __future__ import annotations

import logging

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.testclient import TestClient

from api.middleware import (
    ApiAuthMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
)


def make_app(*, token: str = "", max_per_minute: int = 100, enabled: bool = True) -> FastAPI:
    app = FastAPI()
    # Last-added is outermost, matching create_app: every early response
    # (401/429) still passes through RequestContextMiddleware.
    app.add_middleware(
        RateLimitMiddleware, max_per_minute=max_per_minute, enabled=enabled
    )
    app.add_middleware(ApiAuthMiddleware, api_auth_token=token)
    app.add_middleware(RequestContextMiddleware)

    @app.get("/health/live")
    def live():
        return {"status": "ok"}

    @app.get("/resource")
    def resource():
        return {"ok": True}

    @app.post("/echo")
    async def echo():
        return JSONResponse({"ok": True})

    return app


class TestRateLimitBudgets:
    def test_per_tenant_budget_binds_across_source_ips(self):
        app = make_app(max_per_minute=2)
        first_ip = TestClient(app, client=("10.0.0.1", 1000))
        second_ip = TestClient(app, client=("10.0.0.2", 1000))
        headers = {"X-Tenant-ID": "tenant-a"}

        assert first_ip.get("/resource", headers=headers).status_code == 200
        assert first_ip.get("/resource", headers=headers).status_code == 200
        blocked = second_ip.get("/resource", headers=headers)
        assert blocked.status_code == 429
        assert blocked.json()["code"] == "RATE_LIMIT_EXCEEDED"
        assert 1 <= int(blocked.headers["retry-after"]) <= 60

    def test_rotating_tenant_header_cannot_evade_the_ip_budget(self):
        app = make_app(max_per_minute=2)
        client = TestClient(app, client=("10.0.0.9", 1000))

        assert client.get("/resource", headers={"X-Tenant-ID": "a"}).status_code == 200
        assert client.get("/resource", headers={"X-Tenant-ID": "b"}).status_code == 200
        blocked = client.get("/resource", headers={"X-Tenant-ID": "c"})
        assert blocked.status_code == 429

    def test_one_tenant_exhaustion_does_not_block_another(self):
        app = make_app(max_per_minute=2)
        client_a = TestClient(app, client=("10.0.0.1", 1000))
        client_b = TestClient(app, client=("10.0.0.2", 1000))

        assert client_a.get("/resource", headers={"X-Tenant-ID": "a"}).status_code == 200
        assert client_a.get("/resource", headers={"X-Tenant-ID": "a"}).status_code == 200
        assert client_a.get("/resource", headers={"X-Tenant-ID": "a"}).status_code == 429
        # Different IP and tenant: both budgets are fresh.
        assert client_b.get("/resource", headers={"X-Tenant-ID": "b"}).status_code == 200

    def test_requests_without_tenant_are_limited_by_ip_only(self):
        app = make_app(max_per_minute=1)
        client = TestClient(app, client=("10.0.0.3", 1000))
        assert client.get("/resource").status_code == 200
        assert client.get("/resource").status_code == 429

    def test_health_endpoints_are_exempt(self):
        app = make_app(max_per_minute=1)
        client = TestClient(app, client=("10.0.0.4", 1000))
        for _ in range(10):
            assert client.get("/health/live").status_code == 200

    def test_disabled_limiter_never_blocks(self):
        app = make_app(max_per_minute=1, enabled=False)
        client = TestClient(app, client=("10.0.0.5", 1000))
        for _ in range(10):
            assert client.get("/resource").status_code == 200

    def test_stale_buckets_are_pruned(self):
        direct = RateLimitMiddleware(app=lambda *a: None, max_per_minute=10)
        now = 1_000_000.0
        direct._ip_hits["ip:old"] = [now - 120]
        direct._tenant_hits["tenant:old"] = [now - 120]
        direct._last_prune = now - 61
        direct._prune_if_due(now, now - 60)
        assert "ip:old" not in direct._ip_hits
        assert "tenant:old" not in direct._tenant_hits


class TestRequestIds:
    def test_valid_request_id_is_echoed(self):
        client = TestClient(make_app())
        resp = client.get("/resource", headers={"X-Request-ID": "req-123_ok"})
        assert resp.headers["x-request-id"] == "req-123_ok"

    def test_invalid_request_id_is_replaced(self):
        client = TestClient(make_app())
        resp = client.get(
            "/resource", headers={"X-Request-ID": "bad id\twith control"}
        )
        request_id = resp.headers["x-request-id"]
        assert request_id != "bad id\twith control"
        assert len(request_id) == 32

    def test_auth_and_rate_limit_responses_still_carry_a_request_id(self):
        auth_client = TestClient(make_app(token="secret"))
        unauth = auth_client.get("/resource")
        assert unauth.status_code == 401
        assert "x-request-id" in unauth.headers

        limited_client = TestClient(
            make_app(max_per_minute=1), client=("10.0.0.8", 1000)
        )
        assert limited_client.get("/resource").status_code == 200
        limited = limited_client.get("/resource")
        assert limited.status_code == 429
        assert "x-request-id" in limited.headers


class TestLoggingHygiene:
    def test_completion_log_carries_ids_but_no_credentials_or_body(self, caplog):
        token = "super-secret-api-token"
        body_marker = "document-body-marker"
        app = make_app(token=token)
        client = TestClient(app)

        with caplog.at_level(logging.INFO, logger="api.middleware"):
            resp = client.post(
                "/echo",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Request-ID": "log-check-1",
                    "X-Tenant-ID": "tenant-log",
                },
                json={"text": body_marker},
            )

        assert resp.status_code == 200
        records = [
            record for record in caplog.records if record.msg == "request_completed"
        ]
        assert records, caplog.text
        record = records[-1]
        assert record.request_id == "log-check-1"
        assert record.method == "POST"
        assert record.path == "/echo"
        assert record.status_code == 200
        assert token not in caplog.text
        assert body_marker not in caplog.text
        assert "Authorization" not in caplog.text
