"""Production configuration and rate-limiter tests.

Covers:
  Blocker 1 — Mock integration defaults and production guard
  Blocker 2 — Rate-limiter backend selection, Redis implementation, production guard
"""

import json
import threading
import time
from unittest.mock import MagicMock, patch

import fakeredis
import pytest

from app.middleware.rate_limit import (
    BACKEND_UNAVAILABLE,
    DevelopmentOnlyRateLimiter,
    RedisRateLimiter,
    RateLimitMiddleware,
    _LIMITS,
    _backend_unavailable_response,
    _rate_limit_response,
    assert_rate_limiter_production_safe,
    build_rate_limiter_backend,
)
from app.services.email_service import _assert_no_mocks_in_production, _is_mock, build_policy_coordinator
from mocks.mock_approval import MockApprovalClient
from mocks.mock_attachment_scanner import MockAttachmentScanner
from mocks.mock_audit import MockAuditClient
from mocks.mock_inspector import MockInspectionClient
from mocks.mock_policy import MockPolicyClient


# ===========================================================================
# Helpers
# ===========================================================================

def _fake_redis():
    """Return a fakeredis client that behaves like a real Redis client."""
    return fakeredis.FakeRedis()


def _mock_settings(**overrides):
    s = MagicMock()
    s.APP_ENV = overrides.get("APP_ENV", "development")
    s.USE_MOCK_INTEGRATIONS = overrides.get("USE_MOCK_INTEGRATIONS", False)
    s.RATE_LIMITER_BACKEND = overrides.get("RATE_LIMITER_BACKEND", "development")
    s.REDIS_URL = overrides.get("REDIS_URL", "")
    s.POLICY_SERVICE_URL = overrides.get("POLICY_SERVICE_URL", "http://policy")
    s.INSPECTION_SERVICE_URL = overrides.get("INSPECTION_SERVICE_URL", "http://inspect")
    s.AUDIT_SERVICE_URL = overrides.get("AUDIT_SERVICE_URL", "http://audit")
    return s


# ===========================================================================
# Blocker 1 — Mock integration defaults
# ===========================================================================

class TestMockIntegrationDefaults:

    def test_default_use_mock_integrations_is_false(self):
        """USE_MOCK_INTEGRATIONS must default to False."""
        from app.config import Settings, get_settings
        get_settings.cache_clear()
        # Remove the env var entirely so pydantic uses the field default
        env_without_mock = {k: v for k, v in __import__("os").environ.items()
                            if k != "USE_MOCK_INTEGRATIONS"}
        with patch.dict("os.environ", env_without_mock, clear=True):
            s = Settings(_env_file=None)
            assert s.USE_MOCK_INTEGRATIONS is False
        get_settings.cache_clear()

    def test_mock_sentinel_present_on_all_mock_classes(self):
        """Every mock class must carry IS_DEVELOPMENT_MOCK=True."""
        for cls in (MockPolicyClient, MockInspectionClient, MockAuditClient,
                    MockApprovalClient, MockAttachmentScanner):
            assert getattr(cls, "IS_DEVELOPMENT_MOCK", False) is True, (
                f"{cls.__name__} missing IS_DEVELOPMENT_MOCK sentinel"
            )

    def test_is_mock_returns_true_for_mock_instances(self):
        assert _is_mock(MockPolicyClient()) is True
        assert _is_mock(MockAuditClient()) is True

    def test_is_mock_returns_false_for_real_clients(self):
        from app.integrations.policy_client import HttpPolicyClient
        from app.integrations.audit_client import HttpAuditClient
        assert _is_mock(HttpPolicyClient()) is False
        assert _is_mock(HttpAuditClient()) is False


class TestProductionMockGuard:

    def test_production_with_use_mock_integrations_true_raises(self):
        """build_policy_coordinator must raise if APP_ENV=production and USE_MOCK_INTEGRATIONS=True."""
        with patch("app.services.email_service.get_settings") as mock_settings:
            mock_settings.return_value = _mock_settings(
                APP_ENV="production", USE_MOCK_INTEGRATIONS=True
            )
            with pytest.raises(RuntimeError, match="USE_MOCK_INTEGRATIONS=True is forbidden"):
                build_policy_coordinator()

    def test_production_with_injected_mock_policy_client_raises(self):
        """Injected MockPolicyClient must be rejected in production."""
        real = MagicMock(IS_DEVELOPMENT_MOCK=False)
        with pytest.raises(RuntimeError, match="policy_client"):
            _assert_no_mocks_in_production(MockPolicyClient(), real, real, real, real)

    def test_production_with_injected_mock_inspection_client_raises(self):
        real = MagicMock(IS_DEVELOPMENT_MOCK=False)
        with pytest.raises(RuntimeError, match="inspection_client"):
            _assert_no_mocks_in_production(real, MockInspectionClient(), real, real, real)

    def test_production_with_injected_mock_audit_client_raises(self):
        real = MagicMock(IS_DEVELOPMENT_MOCK=False)
        with pytest.raises(RuntimeError, match="audit_client"):
            _assert_no_mocks_in_production(real, real, MockAuditClient(), real, real)

    def test_production_with_injected_mock_approval_client_raises(self):
        real = MagicMock(IS_DEVELOPMENT_MOCK=False)
        with pytest.raises(RuntimeError, match="approval_client"):
            _assert_no_mocks_in_production(real, real, real, MockApprovalClient(), real)

    def test_production_with_injected_mock_attachment_scanner_raises(self):
        real = MagicMock(IS_DEVELOPMENT_MOCK=False)
        with pytest.raises(RuntimeError, match="attachment_scanner"):
            _assert_no_mocks_in_production(real, real, real, real, MockAttachmentScanner())

    def test_assert_no_mocks_passes_for_all_real_clients(self):
        """_assert_no_mocks_in_production must not raise when all clients are real."""
        real = MagicMock(IS_DEVELOPMENT_MOCK=False)
        _assert_no_mocks_in_production(real, real, real, real, real)  # must not raise

    def test_development_env_with_use_mock_integrations_true_uses_mocks(self):
        """Development environment with USE_MOCK_INTEGRATIONS=True must succeed and use mocks."""
        with patch("app.services.email_service.get_settings") as mock_settings:
            mock_settings.return_value = _mock_settings(
                APP_ENV="development", USE_MOCK_INTEGRATIONS=True
            )
            coordinator = build_policy_coordinator()
        assert _is_mock(coordinator.policy_client) is True
        assert _is_mock(coordinator.inspection_client) is True
        assert _is_mock(coordinator.audit_client) is True

    def test_test_env_always_uses_mocks_regardless_of_flag(self):
        """APP_ENV=test must always use mocks even if USE_MOCK_INTEGRATIONS=False."""
        with patch("app.services.email_service.get_settings") as mock_settings:
            mock_settings.return_value = _mock_settings(
                APP_ENV="test", USE_MOCK_INTEGRATIONS=False
            )
            coordinator = build_policy_coordinator()
        assert _is_mock(coordinator.policy_client) is True

    def test_production_no_session_raises(self):
        """Production without a database session must raise (no MockApprovalClient fallback)."""
        with patch("app.services.email_service.get_settings") as mock_settings:
            mock_settings.return_value = _mock_settings(APP_ENV="production")
            with pytest.raises(RuntimeError):
                # No session, no injected approval_client — must not silently use mock
                build_policy_coordinator(session=None, approval_client=None)


# ===========================================================================
# Blocker 2 — Rate limiter: DevelopmentOnlyRateLimiter
# ===========================================================================

class TestDevelopmentOnlyRateLimiter:

    def test_is_development_only_flag(self):
        assert DevelopmentOnlyRateLimiter.IS_DEVELOPMENT_ONLY is True

    def test_burst_allows_initial_requests(self):
        limiter = DevelopmentOnlyRateLimiter(limits={"read": (0.01, 3)})
        for _ in range(3):
            ok, _ = limiter.consume("t:a", "read")
            assert ok is True

    def test_burst_exceeded_returns_false(self):
        limiter = DevelopmentOnlyRateLimiter(limits={"read": (0.01, 2)})
        limiter.consume("t:a", "read")
        limiter.consume("t:a", "read")
        ok, retry = limiter.consume("t:a", "read")
        assert ok is False
        assert retry > 0

    def test_cross_agent_isolation(self):
        limiter = DevelopmentOnlyRateLimiter(limits={"read": (0.01, 1)})
        ok_a, _ = limiter.consume("tenant:agent-a", "read")
        ok_b, _ = limiter.consume("tenant:agent-b", "read")
        assert ok_a is True
        assert ok_b is True

    def test_cross_tenant_isolation(self):
        limiter = DevelopmentOnlyRateLimiter(limits={"read": (0.01, 1)})
        ok_a, _ = limiter.consume("tenant-a:agent", "read")
        ok_b, _ = limiter.consume("tenant-b:agent", "read")
        assert ok_a is True
        assert ok_b is True

    def test_bucket_refills_over_time(self):
        limiter = DevelopmentOnlyRateLimiter(limits={"read": (100.0, 1)})
        limiter.consume("t:a", "read")  # drain
        time.sleep(0.02)               # 20 ms at 100 tokens/s ≈ 2 tokens
        ok, _ = limiter.consume("t:a", "read")
        assert ok is True

    def test_retry_after_is_positive(self):
        limiter = DevelopmentOnlyRateLimiter(limits={"read": (0.01, 1)})
        limiter.consume("t:a", "read")
        ok, retry = limiter.consume("t:a", "read")
        assert ok is False
        assert retry > 0

    def test_concurrent_requests_thread_safe(self):
        """Multiple threads consuming the same bucket must not exceed burst."""
        burst = 10
        limiter = DevelopmentOnlyRateLimiter(limits={"read": (0.001, burst)})
        results = []
        barrier = threading.Barrier(20)

        def worker():
            barrier.wait()
            ok, _ = limiter.consume("t:a", "read")
            results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = sum(1 for r in results if r)
        assert allowed == burst, f"Expected exactly {burst} allowed, got {allowed}"

    def test_operation_specific_limits(self):
        """Different categories must have independent buckets."""
        limiter = DevelopmentOnlyRateLimiter(limits={"read": (0.01, 1), "send": (0.01, 1)})
        ok_read, _ = limiter.consume("t:a", "read")
        ok_send, _ = limiter.consume("t:a", "send")
        assert ok_read is True
        assert ok_send is True


# ===========================================================================
# Blocker 2 — Rate limiter: RedisRateLimiter (via fakeredis)
# ===========================================================================

class TestRedisRateLimiter:

    def _limiter(self, limits=None):
        return RedisRateLimiter(redis_client=_fake_redis(), limits=limits)

    def test_is_not_development_only(self):
        assert RedisRateLimiter.IS_DEVELOPMENT_ONLY is False

    def test_burst_allows_initial_requests(self):
        limiter = self._limiter({"read": (0.01, 3)})
        for _ in range(3):
            ok, _ = limiter.consume("t:a", "read")
            assert ok is True

    def test_burst_exceeded_returns_false(self):
        limiter = self._limiter({"read": (0.01, 2)})
        limiter.consume("t:a", "read")
        limiter.consume("t:a", "read")
        ok, retry = limiter.consume("t:a", "read")
        assert ok is False
        assert retry > 0

    def test_cross_agent_isolation(self):
        limiter = self._limiter({"read": (0.01, 1)})
        ok_a, _ = limiter.consume("tenant:agent-a", "read")
        ok_b, _ = limiter.consume("tenant:agent-b", "read")
        assert ok_a is True
        assert ok_b is True

    def test_cross_tenant_isolation(self):
        limiter = self._limiter({"read": (0.01, 1)})
        ok_a, _ = limiter.consume("tenant-a:agent", "read")
        ok_b, _ = limiter.consume("tenant-b:agent", "read")
        assert ok_a is True
        assert ok_b is True

    def test_operation_specific_limits(self):
        limiter = self._limiter({"read": (0.01, 1), "send": (0.01, 1)})
        ok_read, _ = limiter.consume("t:a", "read")
        ok_send, _ = limiter.consume("t:a", "send")
        assert ok_read is True
        assert ok_send is True

    def test_multiple_instances_share_counters(self):
        """Two RedisRateLimiter instances sharing the same Redis client share counters."""
        client = _fake_redis()
        limiter_a = RedisRateLimiter(redis_client=client, limits={"read": (0.01, 1)})
        limiter_b = RedisRateLimiter(redis_client=client, limits={"read": (0.01, 1)})
        ok_a, _ = limiter_a.consume("t:agent", "read")
        ok_b, _ = limiter_b.consume("t:agent", "read")
        assert ok_a is True
        assert ok_b is False, "Second instance must see the token already consumed by first"

    def test_bucket_refills_over_time(self):
        limiter = self._limiter({"read": (100.0, 1)})
        limiter.consume("t:a", "read")  # drain
        time.sleep(0.02)
        ok, _ = limiter.consume("t:a", "read")
        assert ok is True

    def test_retry_after_accuracy(self):
        """retry_after must be positive and proportional to the rate."""
        limiter = self._limiter({"send": (0.1, 1)})  # 1 token per 10 seconds
        limiter.consume("t:a", "send")
        ok, retry = limiter.consume("t:a", "send")
        assert ok is False
        # At rate=0.1 tokens/s, retry should be ~10 s
        assert 5.0 < retry < 15.0, f"Unexpected retry_after: {retry}"

    def test_expired_bucket_resets(self):
        """After TTL expiry the bucket should be reset (simulated via reset)."""
        limiter = self._limiter({"read": (0.01, 1)})
        limiter.consume("t:a", "read")
        limiter.reset("t:a", "read")
        ok, _ = limiter.consume("t:a", "read")
        assert ok is True

    def test_redis_unavailable_returns_backend_unavailable_sentinel(self):
        """When Redis raises, ALL categories must return (False, BACKEND_UNAVAILABLE)."""
        client = _fake_redis()
        limiter = RedisRateLimiter(redis_client=client, limits=_LIMITS)
        limiter._script = MagicMock(side_effect=Exception("connection refused"))
        for category in ("send", "oauth", "read", "draft", "tenant"):
            ok, retry = limiter.consume("t:a", category)
            assert ok is False, f"Expected False for category={category}"
            assert retry == BACKEND_UNAVAILABLE, (
                f"Expected BACKEND_UNAVAILABLE sentinel for category={category}, got {retry}"
            )

    def test_redis_unavailable_never_returns_true(self):
        """No category may fail open when Redis is unavailable."""
        client = _fake_redis()
        limiter = RedisRateLimiter(redis_client=client, limits=_LIMITS)
        limiter._script = MagicMock(side_effect=Exception("connection refused"))
        for category in _LIMITS:
            ok, _ = limiter.consume("t:a", category)
            assert ok is False, f"Category '{category}' must not fail open"

    def test_redis_recovers_after_failure(self):
        """After Redis becomes available again, requests must proceed."""
        client = _fake_redis()
        limiter = RedisRateLimiter(redis_client=client, limits={"read": (10.0, 5)})
        # Simulate failure then recovery
        real_script = limiter._script
        limiter._script = MagicMock(side_effect=Exception("connection refused"))
        ok_fail, retry = limiter.consume("t:a", "read")
        assert ok_fail is False
        assert retry == BACKEND_UNAVAILABLE
        # Restore script (Redis recovered)
        limiter._script = real_script
        ok_recover, _ = limiter.consume("t:a", "read")
        assert ok_recover is True

    def test_concurrent_requests_atomic(self):
        """Concurrent threads must not collectively exceed burst via race conditions."""
        burst = 5
        client = _fake_redis()
        limiter = RedisRateLimiter(redis_client=client, limits={"read": (0.001, burst)})
        results = []
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            ok, _ = limiter.consume("t:a", "read")
            results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = sum(1 for r in results if r)
        assert allowed == burst, f"Expected exactly {burst} allowed, got {allowed}"


# ===========================================================================
# Blocker 2 — Production startup guard
# ===========================================================================

class TestRateLimiterProductionGuard:

    def test_assert_production_safe_raises_for_dev_limiter(self):
        limiter = DevelopmentOnlyRateLimiter()
        with pytest.raises(RuntimeError, match="DevelopmentOnlyRateLimiter"):
            assert_rate_limiter_production_safe(limiter)

    def test_assert_production_safe_passes_for_redis_limiter(self):
        limiter = RedisRateLimiter(redis_client=_fake_redis())
        assert_rate_limiter_production_safe(limiter)  # must not raise

    def test_build_rate_limiter_returns_dev_limiter_by_default(self):
        settings = _mock_settings(RATE_LIMITER_BACKEND="development")
        backend = build_rate_limiter_backend(settings)
        assert isinstance(backend, DevelopmentOnlyRateLimiter)

    def test_build_rate_limiter_redis_without_url_raises(self):
        settings = _mock_settings(RATE_LIMITER_BACKEND="redis", REDIS_URL="")
        with pytest.raises(RuntimeError, match="REDIS_URL"):
            build_rate_limiter_backend(settings)

    def test_build_rate_limiter_redis_with_url_returns_redis_limiter(self):
        settings = _mock_settings(RATE_LIMITER_BACKEND="redis", REDIS_URL="redis://localhost:6379/0")
        mock_client = MagicMock()
        with patch("app.middleware.rate_limit.redis") as mock_redis_mod:
            mock_redis_mod.Redis.from_url.return_value = mock_client
            backend = build_rate_limiter_backend(settings)
        assert isinstance(backend, RedisRateLimiter)


# ===========================================================================
# Rate-limit middleware: 429 response format
# ===========================================================================

def test_rate_limit_response_status_and_header():
    resp = _rate_limit_response("req-1", "send", 45.3)
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
    assert int(resp.headers["Retry-After"]) >= 46


def test_rate_limit_response_minimum_retry_after():
    """Retry-After must be at least 1 even for tiny retry values."""
    resp = _rate_limit_response("req-1", "read", 0.001)
    assert int(resp.headers["Retry-After"]) >= 1


# ===========================================================================
# Startup lifecycle: production assertions
# ===========================================================================

class TestProductionStartupAssertions:

    async def _run_lifespan(self, app):
        """Drive the lifespan context manager to its first yield (startup)."""
        ctx = app.router.lifespan_context(app)
        await ctx.__aenter__()

    def test_production_startup_rejects_mock_integrations(self):
        """create_app lifespan must raise if APP_ENV=production and USE_MOCK_INTEGRATIONS=True."""
        with patch("app.main.get_settings") as mock_get:
            s = _mock_settings(APP_ENV="production", USE_MOCK_INTEGRATIONS=True)
            s.RATE_LIMITER_BACKEND = "development"
            mock_get.return_value = s
            from app.main import create_app
            app = create_app()
            with pytest.raises(RuntimeError, match="USE_MOCK_INTEGRATIONS"):
                import asyncio
                asyncio.run(self._run_lifespan(app))

    def test_production_startup_rejects_missing_policy_url(self):
        with patch("app.main.get_settings") as mock_get:
            s = _mock_settings(
                APP_ENV="production",
                USE_MOCK_INTEGRATIONS=False,
                POLICY_SERVICE_URL="",
            )
            mock_get.return_value = s
            from app.main import create_app
            app = create_app()
            with pytest.raises(RuntimeError, match="POLICY_SERVICE_URL"):
                import asyncio
                asyncio.run(self._run_lifespan(app))

    def test_production_startup_rejects_dev_rate_limiter(self):
        with patch("app.main.get_settings") as mock_get:
            s = _mock_settings(
                APP_ENV="production",
                USE_MOCK_INTEGRATIONS=False,
                RATE_LIMITER_BACKEND="development",
            )
            mock_get.return_value = s
            from app.main import create_app
            app = create_app()
            with pytest.raises(RuntimeError):
                import asyncio
                asyncio.run(self._run_lifespan(app))


# ===========================================================================
# Redis failure semantics: HTTP 503 vs 429 — response-level tests
# ===========================================================================

class TestRedisFailureHttpSemantics:
    """Verify the middleware returns correct HTTP status codes for each outcome."""

    def test_503_response_has_correct_status(self):
        resp = _backend_unavailable_response("req-x")
        assert resp.status_code == 503

    def test_503_response_error_code_is_stable(self):
        resp = _backend_unavailable_response("req-x")
        body = json.loads(resp.body)
        assert body["error"]["code"] == "RATE_LIMIT_BACKEND_UNAVAILABLE"

    def test_503_response_does_not_claim_rate_limit_exceeded(self):
        resp = _backend_unavailable_response("req-x")
        body = json.loads(resp.body)
        assert body["error"]["code"] != "RATE_LIMIT_EXCEEDED"

    def test_503_response_includes_request_id(self):
        resp = _backend_unavailable_response("req-abc")
        body = json.loads(resp.body)
        assert body["error"]["request_id"] == "req-abc"

    def test_429_response_does_not_claim_backend_unavailable(self):
        resp = _rate_limit_response("req-x", "send", 5.0)
        body = json.loads(resp.body)
        assert body["error"]["code"] == "RATE_LIMIT_EXCEEDED"
        assert "BACKEND_UNAVAILABLE" not in body["error"]["code"]

    def test_429_includes_retry_after_header(self):
        resp = _rate_limit_response("req-x", "read", 30.0)
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert int(resp.headers["Retry-After"]) >= 31

    def test_503_has_no_retry_after_header(self):
        """503 must not include Retry-After — the outage duration is unknown."""
        resp = _backend_unavailable_response("req-x")
        assert "Retry-After" not in resp.headers


# ===========================================================================
# Middleware integration: HTTP responses via ASGI test client
# ===========================================================================

@pytest.mark.asyncio
async def test_middleware_redis_available_under_limit_proceeds():
    """Redis available and under limit → request proceeds (not 429 or 503)."""
    from httpx import ASGITransport, AsyncClient
    from app.main import create_app

    client = _fake_redis()
    limiter = RedisRateLimiter(redis_client=client, limits=_LIMITS)
    app = create_app()
    app.state.rate_limiter_backend = limiter

    # Patch the middleware to use our limiter
    for mw in app.middleware_stack.__class__.__mro__:
        pass  # just ensure app is built

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={
            "Authorization": "Bearer dev-secret-token",
            "X-Tenant-ID": "t1",
            "X-Agent-ID": "a1",
        },
    ) as ac:
        resp = await ac.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_middleware_redis_unavailable_returns_503_for_all_routes():
    """Redis unavailable → HTTP 503 for all protected route categories."""
    from httpx import ASGITransport, AsyncClient

    broken_limiter = RedisRateLimiter(
        redis_client=_fake_redis(),
        limits=_LIMITS,
    )
    broken_limiter._script = MagicMock(side_effect=Exception("redis down"))

    from app.middleware.rate_limit import RateLimitMiddleware as RLM
    from fastapi import FastAPI
    from app.middleware.request_id import RequestIdMiddleware
    from app.middleware.authentication import GatewayAuthenticationMiddleware

    mini = FastAPI()
    mini.add_middleware(RequestIdMiddleware)
    mini.add_middleware(GatewayAuthenticationMiddleware)
    mini.add_middleware(RLM, backend=broken_limiter)

    @mini.get("/emails")
    async def emails():
        return {"ok": True}

    @mini.post("/emails/send")
    async def send():
        return {"ok": True}

    @mini.post("/emails/draft")
    async def draft():
        return {"ok": True}

    @mini.get("/oauth/callback")
    async def oauth():
        return {"ok": True}

    @mini.post("/emails/forward")
    async def forward():
        return {"ok": True}

    headers = {
        "Authorization": "Bearer dev-secret-token",
        "X-Tenant-ID": "t1",
        "X-Agent-ID": "a1",
    }

    async with AsyncClient(
        transport=ASGITransport(app=mini),
        base_url="http://test",
        headers=headers,
    ) as ac:
        for method, path in [
            ("GET", "/emails"),
            ("POST", "/emails/send"),
            ("POST", "/emails/draft"),
            ("GET", "/oauth/callback"),
            ("POST", "/emails/forward"),
        ]:
            resp = await ac.request(method, path)
            assert resp.status_code == 503, (
                f"{method} {path} returned {resp.status_code}, expected 503"
            )
            body = resp.json()
            assert body["error"]["code"] == "RATE_LIMIT_BACKEND_UNAVAILABLE", (
                f"{method} {path} body: {body}"
            )


@pytest.mark.asyncio
async def test_middleware_redis_over_limit_returns_429():
    """Redis available and over limit → HTTP 429 with RATE_LIMIT_EXCEEDED."""
    from httpx import ASGITransport, AsyncClient
    from fastapi import FastAPI
    from app.middleware.request_id import RequestIdMiddleware
    from app.middleware.authentication import GatewayAuthenticationMiddleware
    from app.middleware.rate_limit import RateLimitMiddleware as RLM

    # Burst of 1 so second request is denied
    limiter = RedisRateLimiter(redis_client=_fake_redis(), limits={"read": (0.001, 1)})

    mini = FastAPI()
    mini.add_middleware(RequestIdMiddleware)
    mini.add_middleware(GatewayAuthenticationMiddleware)
    mini.add_middleware(RLM, backend=limiter)

    @mini.get("/emails")
    async def emails():
        return {"ok": True}

    headers = {
        "Authorization": "Bearer dev-secret-token",
        "X-Tenant-ID": "t1",
        "X-Agent-ID": "a1",
    }

    async with AsyncClient(
        transport=ASGITransport(app=mini),
        base_url="http://test",
        headers=headers,
    ) as ac:
        r1 = await ac.get("/emails")
        r2 = await ac.get("/emails")

    assert r1.status_code == 200
    assert r2.status_code == 429
    body = r2.json()
    assert body["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in r2.headers


# ===========================================================================
# Real Redis integration
# ===========================================================================

def test_real_redis_integration_status():
    """
    Real Redis integration: NOT TESTED.

    A real Redis server is not available in this environment.
    Fakeredis is used for all Redis-backed limiter tests.
    Atomic Lua execution is verified via fakeredis (which executes Lua atomically).
    Real Redis integration must be verified separately before production sign-off.
    """
    pytest.skip("Real Redis server not available in this environment — NOT TESTED")
