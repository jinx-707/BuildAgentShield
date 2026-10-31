"""Real Redis integration tests for RedisRateLimiter.

This module is skipped automatically when no Redis server is reachable at
REDIS_TEST_URL (default: redis://127.0.0.1:6379/15).

Database 15 is used to isolate test keys from any other data.  All keys
written by these tests are prefixed with ``ratelimit:`` and are deleted in
teardown even if a test fails.

To run against a real server:

    # Start Redis (example via Docker):
    docker run -d -p 6379:6379 redis:7-alpine

    # Run only this file:
    .venv/bin/python -m pytest tests/integration/test_real_redis.py -v

Environment variables:
    REDIS_TEST_URL   Override the Redis URL (default: redis://127.0.0.1:6379/15)
"""

import os
import threading
import time

import pytest
import redis as redis_lib

from app.middleware.rate_limit import (
    BACKEND_UNAVAILABLE,
    RedisRateLimiter,
    _LIMITS,
    _backend_unavailable_response,
    _rate_limit_response,
)

# ---------------------------------------------------------------------------
# Connection probe — skip entire module if no real Redis is reachable
# ---------------------------------------------------------------------------

_REDIS_TEST_URL = os.environ.get("REDIS_TEST_URL", "redis://127.0.0.1:6379/15")

_REDIS_AVAILABLE = False
_REDIS_VERSION: str = "unknown"

try:
    _probe = redis_lib.Redis.from_url(_REDIS_TEST_URL, socket_connect_timeout=1)
    _info = _probe.info("server")
    _REDIS_VERSION = _info.get("redis_version", "unknown")
    _REDIS_AVAILABLE = True
    _probe.close()
except Exception:
    pass

pytestmark = pytest.mark.skipif(
    not _REDIS_AVAILABLE,
    reason=f"Real Redis not reachable at {_REDIS_TEST_URL} — NOT TESTED",
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TEST_KEY_PREFIX = "ratelimit:"


@pytest.fixture()
def redis_client():
    """Fresh Redis client connected to the isolated test database."""
    client = redis_lib.Redis.from_url(_REDIS_TEST_URL, decode_responses=False)
    yield client
    # Cleanup: delete all keys written by this test run
    for key in client.scan_iter(f"{_TEST_KEY_PREFIX}*"):
        client.delete(key)
    client.close()


@pytest.fixture()
def limiter(redis_client):
    """RedisRateLimiter wired to the real Redis test database."""
    return RedisRateLimiter(redis_client=redis_client, limits=_LIMITS)


@pytest.fixture()
def fast_limiter(redis_client):
    """RedisRateLimiter with fast-refilling limits for timing-sensitive tests."""
    return RedisRateLimiter(
        redis_client=redis_client,
        limits={
            "read":   (100.0, 3),   # 100 tokens/s, burst 3
            "send":   (100.0, 2),
            "draft":  (100.0, 2),
            "oauth":  (100.0, 1),
            "tenant": (100.0, 10),
        },
    )


# ---------------------------------------------------------------------------
# 1. Connection and script registration
# ---------------------------------------------------------------------------

class TestRealRedisConnection:

    def test_redis_version_reported(self):
        """Confirm we are talking to a real Redis server and know its version."""
        assert _REDIS_VERSION != "unknown", "Could not determine Redis server version"
        # Version string is at least "M.m.p"
        parts = _REDIS_VERSION.split(".")
        assert len(parts) >= 2
        print(f"\n  Redis server version: {_REDIS_VERSION}")

    def test_lua_script_registers_without_error(self, redis_client):
        """The token-bucket Lua script must register successfully on a real server."""
        limiter = RedisRateLimiter(redis_client=redis_client, limits=_LIMITS)
        assert limiter._script is not None

    def test_ping_succeeds(self, redis_client):
        assert redis_client.ping() is True


# ---------------------------------------------------------------------------
# 2. Lua script execution and return values
# ---------------------------------------------------------------------------

class TestLuaScriptExecution:

    def test_first_consume_allowed(self, limiter):
        ok, retry = limiter.consume("real:agent-lua", "read")
        assert ok is True
        assert retry == 0.0

    def test_consume_returns_two_element_result(self, limiter):
        result = limiter.consume("real:agent-result", "send")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_burst_exhaustion_returns_false(self, fast_limiter):
        key = "real:agent-burst"
        # Drain the burst of 3
        for _ in range(3):
            ok, _ = fast_limiter.consume(key, "read")
            assert ok is True
        ok, retry = fast_limiter.consume(key, "read")
        assert ok is False
        assert retry > 0.0

    def test_retry_after_is_positive_on_denial(self, fast_limiter):
        """retry_after must be > 0 when the bucket is empty."""
        key = "real:agent-retry"
        # rate=100 tokens/s, burst=2 → drain
        fast_limiter.consume(key, "send")
        fast_limiter.consume(key, "send")
        ok, retry = fast_limiter.consume(key, "send")
        assert ok is False
        assert retry > 0.0

    def test_retry_after_proportional_to_rate(self, redis_client):
        """At rate=0.1 tokens/s (1 token per 10 s), retry_after must be ~10 s."""
        limiter = RedisRateLimiter(
            redis_client=redis_client,
            limits={"send": (0.1, 1)},
        )
        key = "real:agent-proportional"
        limiter.consume(key, "send")  # drain
        ok, retry = limiter.consume(key, "send")
        assert ok is False
        assert 5.0 < retry < 15.0, f"Unexpected retry_after={retry} for rate=0.1"


# ---------------------------------------------------------------------------
# 3. Token-bucket burst enforcement
# ---------------------------------------------------------------------------

class TestBurstEnforcement:

    def test_exactly_burst_requests_allowed(self, redis_client):
        burst = 4
        limiter = RedisRateLimiter(
            redis_client=redis_client,
            limits={"read": (0.001, burst)},
        )
        key = "real:agent-exact-burst"
        allowed = sum(1 for _ in range(burst) if limiter.consume(key, "read")[0])
        assert allowed == burst

    def test_burst_plus_one_denied(self, redis_client):
        burst = 3
        limiter = RedisRateLimiter(
            redis_client=redis_client,
            limits={"read": (0.001, burst)},
        )
        key = "real:agent-burst-plus-one"
        results = [limiter.consume(key, "read")[0] for _ in range(burst + 1)]
        assert results[:burst] == [True] * burst
        assert results[burst] is False

    def test_cross_agent_isolation(self, fast_limiter):
        """Two different agent keys must have independent buckets."""
        ok_a, _ = fast_limiter.consume("real:tenant:agent-a", "read")
        ok_b, _ = fast_limiter.consume("real:tenant:agent-b", "read")
        assert ok_a is True
        assert ok_b is True

    def test_cross_tenant_isolation(self, fast_limiter):
        ok_a, _ = fast_limiter.consume("real:tenant-a:agent", "read")
        ok_b, _ = fast_limiter.consume("real:tenant-b:agent", "read")
        assert ok_a is True
        assert ok_b is True

    def test_category_isolation(self, fast_limiter):
        """read and send buckets for the same key must be independent."""
        key = "real:tenant:agent-cat"
        ok_read, _ = fast_limiter.consume(key, "read")
        ok_send, _ = fast_limiter.consume(key, "send")
        assert ok_read is True
        assert ok_send is True


# ---------------------------------------------------------------------------
# 4. Refill and retry-after calculations
# ---------------------------------------------------------------------------

class TestRefillBehavior:

    def test_bucket_refills_after_sleep(self, redis_client):
        """After draining, sleeping long enough must allow a new request."""
        # rate=50 tokens/s, burst=1 → refill in ~20 ms
        limiter = RedisRateLimiter(
            redis_client=redis_client,
            limits={"read": (50.0, 1)},
        )
        key = "real:agent-refill"
        limiter.consume(key, "read")          # drain
        time.sleep(0.05)                       # 50 ms >> 20 ms refill time
        ok, _ = limiter.consume(key, "read")
        assert ok is True

    def test_reset_restores_full_bucket(self, fast_limiter):
        """reset() must allow a previously exhausted bucket to accept requests."""
        key = "real:agent-reset"
        fast_limiter.consume(key, "read")
        fast_limiter.consume(key, "read")
        fast_limiter.consume(key, "read")  # burst=3, now empty
        fast_limiter.reset(key, "read")
        ok, _ = fast_limiter.consume(key, "read")
        assert ok is True


# ---------------------------------------------------------------------------
# 5. Shared state across independent clients
# ---------------------------------------------------------------------------

class TestSharedState:

    def test_two_independent_clients_share_counters(self, redis_client):
        """Two separately created RedisRateLimiter instances must share the same bucket."""
        client_a = redis_lib.Redis.from_url(_REDIS_TEST_URL, decode_responses=False)
        client_b = redis_lib.Redis.from_url(_REDIS_TEST_URL, decode_responses=False)
        try:
            limiter_a = RedisRateLimiter(redis_client=client_a, limits={"read": (0.001, 1)})
            limiter_b = RedisRateLimiter(redis_client=client_b, limits={"read": (0.001, 1)})
            key = "real:shared-state-agent"
            ok_a, _ = limiter_a.consume(key, "read")
            ok_b, _ = limiter_b.consume(key, "read")
            assert ok_a is True
            assert ok_b is False, "Second independent client must see the token consumed by first"
        finally:
            client_a.delete(f"ratelimit:read:{key}")
            client_a.close()
            client_b.close()

    def test_reset_by_one_client_visible_to_other(self, redis_client):
        """A reset issued by one client must be visible to a second client."""
        client_a = redis_lib.Redis.from_url(_REDIS_TEST_URL, decode_responses=False)
        client_b = redis_lib.Redis.from_url(_REDIS_TEST_URL, decode_responses=False)
        try:
            limiter_a = RedisRateLimiter(redis_client=client_a, limits={"read": (0.001, 1)})
            limiter_b = RedisRateLimiter(redis_client=client_b, limits={"read": (0.001, 1)})
            key = "real:shared-reset-agent"
            limiter_a.consume(key, "read")   # drain via A
            limiter_a.reset(key, "read")     # reset via A
            ok_b, _ = limiter_b.consume(key, "read")  # B should see full bucket
            assert ok_b is True
        finally:
            client_a.delete(f"ratelimit:read:{key}")
            client_a.close()
            client_b.close()


# ---------------------------------------------------------------------------
# 6. Concurrent request atomicity
# ---------------------------------------------------------------------------

class TestConcurrentAtomicity:

    def test_concurrent_threads_do_not_exceed_burst(self, redis_client):
        """20 concurrent threads against burst=5 must yield exactly 5 allowed."""
        burst = 5
        threads_n = 20
        limiter = RedisRateLimiter(
            redis_client=redis_client,
            limits={"read": (0.001, burst)},
        )
        key = "real:concurrent-agent"
        results = []
        barrier = threading.Barrier(threads_n)

        def worker():
            barrier.wait()
            ok, _ = limiter.consume(key, "read")
            results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(threads_n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = sum(1 for r in results if r)
        assert allowed == burst, (
            f"Expected exactly {burst} allowed across {threads_n} concurrent threads, got {allowed}"
        )

    def test_two_independent_clients_concurrent_do_not_exceed_burst(self):
        """Concurrent requests from two independent clients must not exceed burst."""
        burst = 3
        threads_n = 12
        key = "real:concurrent-two-clients"

        clients = [
            redis_lib.Redis.from_url(_REDIS_TEST_URL, decode_responses=False)
            for _ in range(threads_n)
        ]
        limiters = [
            RedisRateLimiter(redis_client=c, limits={"read": (0.001, burst)})
            for c in clients
        ]

        results = []
        barrier = threading.Barrier(threads_n)

        def worker(lim):
            barrier.wait()
            ok, _ = lim.consume(key, "read")
            results.append(ok)

        threads = [threading.Thread(target=worker, args=(limiters[i],)) for i in range(threads_n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Cleanup
        clients[0].delete(f"ratelimit:read:{key}")
        for c in clients:
            c.close()

        allowed = sum(1 for r in results if r)
        assert allowed == burst, (
            f"Expected exactly {burst} allowed, got {allowed} — Lua atomicity violated"
        )


# ---------------------------------------------------------------------------
# 7. Redis outage behavior (all five categories)
# ---------------------------------------------------------------------------

class TestRedisOutageBehavior:

    def _broken_limiter(self, redis_client):
        """Limiter whose Lua script always raises (simulates connection drop)."""
        from unittest.mock import MagicMock
        lim = RedisRateLimiter(redis_client=redis_client, limits=_LIMITS)
        lim._script = MagicMock(side_effect=ConnectionError("simulated outage"))
        return lim

    @pytest.mark.parametrize("category", ["read", "draft", "send", "oauth", "tenant"])
    def test_outage_returns_backend_unavailable_for_all_categories(self, redis_client, category):
        """Every category must return (False, BACKEND_UNAVAILABLE) when Redis is down."""
        lim = self._broken_limiter(redis_client)
        ok, retry = lim.consume("real:outage-agent", category)
        assert ok is False, f"Category '{category}' must not be allowed during outage"
        assert retry == BACKEND_UNAVAILABLE, (
            f"Category '{category}': expected BACKEND_UNAVAILABLE, got {retry}"
        )

    @pytest.mark.parametrize("category", ["read", "draft", "send", "oauth", "tenant"])
    def test_outage_never_fails_open(self, redis_client, category):
        """No category may return True (fail-open) during a Redis outage."""
        lim = self._broken_limiter(redis_client)
        ok, _ = lim.consume("real:outage-failopen", category)
        assert ok is False, f"Category '{category}' must not fail open"

    def test_503_response_on_outage_not_429(self, redis_client):
        """BACKEND_UNAVAILABLE sentinel must produce HTTP 503, not 429."""
        resp = _backend_unavailable_response("req-real-1")
        assert resp.status_code == 503

    def test_503_error_code_is_stable(self, redis_client):
        import json
        resp = _backend_unavailable_response("req-real-2")
        body = json.loads(resp.body)
        assert body["error"]["code"] == "RATE_LIMIT_BACKEND_UNAVAILABLE"

    def test_503_has_no_retry_after(self, redis_client):
        resp = _backend_unavailable_response("req-real-3")
        assert "Retry-After" not in resp.headers

    def test_no_in_memory_fallback_during_outage(self, redis_client):
        """Outage must not silently switch to an in-memory counter."""
        from app.middleware.rate_limit import DevelopmentOnlyRateLimiter
        lim = self._broken_limiter(redis_client)
        # Confirm the limiter is still a RedisRateLimiter, not a dev limiter
        assert isinstance(lim, RedisRateLimiter)
        assert not isinstance(lim, DevelopmentOnlyRateLimiter)
        ok, retry = lim.consume("real:no-fallback", "read")
        assert ok is False
        assert retry == BACKEND_UNAVAILABLE


# ---------------------------------------------------------------------------
# 8. Recovery after Redis becomes available again
# ---------------------------------------------------------------------------

class TestRecoveryAfterOutage:

    def test_recovery_allows_requests_without_restart(self, redis_client):
        """After the script is restored (Redis recovered), requests must proceed."""
        from unittest.mock import MagicMock
        lim = RedisRateLimiter(redis_client=redis_client, limits={"read": (10.0, 5)})
        real_script = lim._script

        # Simulate outage
        lim._script = MagicMock(side_effect=ConnectionError("outage"))
        ok_fail, retry = lim.consume("real:recovery-agent", "read")
        assert ok_fail is False
        assert retry == BACKEND_UNAVAILABLE

        # Simulate recovery — restore script without restarting
        lim._script = real_script
        ok_recover, _ = lim.consume("real:recovery-agent", "read")
        assert ok_recover is True

    def test_recovery_does_not_require_new_limiter_instance(self, redis_client):
        """The same limiter instance must work after recovery — no restart needed."""
        from unittest.mock import MagicMock
        lim = RedisRateLimiter(redis_client=redis_client, limits={"send": (10.0, 3)})
        real_script = lim._script
        key = "real:recovery-same-instance"

        lim._script = MagicMock(side_effect=ConnectionError("outage"))
        lim.consume(key, "send")  # fails closed

        lim._script = real_script
        ok, _ = lim.consume(key, "send")
        assert ok is True, "Same limiter instance must recover without restart"


# ---------------------------------------------------------------------------
# 9. Redis restart behavior
# ---------------------------------------------------------------------------

class TestRedisRestartBehavior:

    def test_bucket_resets_after_key_deletion(self, redis_client):
        """Simulates Redis restart (key loss): bucket must reset to full burst."""
        lim = RedisRateLimiter(redis_client=redis_client, limits={"read": (0.001, 2)})
        key = "real:restart-agent"

        lim.consume(key, "read")
        lim.consume(key, "read")  # drain
        ok_drained, _ = lim.consume(key, "read")
        assert ok_drained is False

        # Simulate Redis restart: delete the key (state lost)
        redis_client.delete(f"ratelimit:read:{key}")

        # After restart, bucket initialises from burst — first request allowed
        ok_after, _ = lim.consume(key, "read")
        assert ok_after is True

    def test_behavior_safe_after_key_loss(self, redis_client):
        """After key loss the limiter must not allow more than burst requests."""
        burst = 2
        lim = RedisRateLimiter(
            redis_client=redis_client,
            limits={"read": (0.001, burst)},
        )
        key = "real:restart-safe"
        redis_client.delete(f"ratelimit:read:{key}")  # ensure clean state

        results = [lim.consume(key, "read")[0] for _ in range(burst + 1)]
        assert results[:burst] == [True] * burst
        assert results[burst] is False
