"""Server-side rate limiting for AgentShield Email Security.

Two backend implementations are provided:

  DevelopmentOnlyRateLimiter
    In-process token bucket.  Counters are process-local and reset on restart.
    UNSUITABLE FOR PRODUCTION: each worker process has independent state, so a
    tenant can exceed limits by a factor of N workers.  Production startup will
    refuse to start with this backend.

  RedisRateLimiter
    Shared token bucket backed by Redis with an atomic Lua script.
    All worker processes share the same counters.  Redis unavailability fails
    closed for ALL operations — there is no fail-open path.  Required for
    production.

Rate-limit categories and default limits:
  read    30 req / 60 s per agent   (0.5 tokens/s, burst 30)
  draft   20 req / 60 s per agent   (0.33 tokens/s, burst 20)
  send    10 req / 60 s per agent   (0.17 tokens/s, burst 10)
  oauth    5 req / 60 s per agent   (0.08 tokens/s, burst 5)
  tenant 200 req / 60 s per tenant  (3.33 tokens/s, burst 200)

HTTP 429 responses include a Retry-After header.
"""

import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from threading import Lock
from typing import Dict, Optional, Tuple

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None  # type: ignore

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

logger = logging.getLogger("agentshield.middleware.ratelimit")

# ---------------------------------------------------------------------------
# Limits: (rate tokens/sec, burst)
# ---------------------------------------------------------------------------
_LIMITS: Dict[str, Tuple[float, int]] = {
    "read":   (0.5,  30),
    "draft":  (0.33, 20),
    "send":   (0.17, 10),
    "oauth":  (0.08,  5),
    "tenant": (3.33, 200),
}

# All categories fail closed when the rate-limit backend is unavailable.
# Redis unavailability must never silently allow requests through.
_FAIL_CLOSED_CATEGORIES = frozenset(_LIMITS.keys())

# Lua script for atomic token-bucket consume in Redis.
# Keys: [bucket_key]
# Args: [rate_per_sec, burst, now_float, cost]
# Returns: [allowed (1/0), retry_after_ms (int)]
_REDIS_TOKEN_BUCKET_LUA = """
local key        = KEYS[1]
local rate       = tonumber(ARGV[1])
local burst      = tonumber(ARGV[2])
local now        = tonumber(ARGV[3])
local cost       = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens     = tonumber(data[1]) or burst
local last_refill = tonumber(data[2]) or now

local elapsed = now - last_refill
if elapsed < 0 then elapsed = 0 end
tokens = math.min(burst, tokens + elapsed * rate)

local allowed = 0
local retry_after_ms = 0

if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
else
    retry_after_ms = math.ceil(((cost - tokens) / rate) * 1000)
end

local ttl = math.ceil(burst / rate) + 10
redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
redis.call('EXPIRE', key, ttl)

return {allowed, retry_after_ms}
"""


# ---------------------------------------------------------------------------
# Abstract backend
# ---------------------------------------------------------------------------

# Sentinel returned by RedisRateLimiter.consume() when the backend itself is
# unavailable (not a normal rate-limit denial).  The middleware uses this to
# return HTTP 503 instead of HTTP 429.
BACKEND_UNAVAILABLE: float = -1.0


class RateLimiterBackend(ABC):
    """Abstract rate-limiter backend.  Concrete implementations must be thread-safe."""

    IS_DEVELOPMENT_ONLY: bool = False

    @abstractmethod
    def consume(self, key: str, category: str) -> Tuple[bool, float]:
        """Consume one token for key in category.

        Returns (allowed, retry_after_seconds).
        When the backend itself is unavailable and the operation must be
        blocked, returns (False, BACKEND_UNAVAILABLE).
        """

    @abstractmethod
    def reset(self, key: str, category: str) -> None:
        """Reset the bucket for key in category (test helper)."""


# ---------------------------------------------------------------------------
# In-memory backend — development only
# ---------------------------------------------------------------------------

@dataclass
class _Bucket:
    tokens: float
    last_refill: float = 0.0  # 0.0 ensures first refill covers full elapsed time


class DevelopmentOnlyRateLimiter(RateLimiterBackend):
    """In-process token bucket rate limiter.

    WARNING — DEVELOPMENT USE ONLY:
      Counters are stored in process memory.  Each worker process maintains
      independent state.  Under multi-worker deployment (gunicorn, uvicorn
      --workers > 1) a tenant can exceed limits by a factor of N workers.
      Production startup will raise RuntimeError if this backend is selected.

    For production, use RedisRateLimiter.
    """

    IS_DEVELOPMENT_ONLY: bool = True

    def __init__(self, limits: Optional[Dict[str, Tuple[float, int]]] = None):
        effective = limits or _LIMITS
        self._stores: Dict[str, Tuple[float, int, Dict[str, _Bucket], Lock]] = {}
        for cat, (rate, burst) in effective.items():
            self._stores[cat] = (rate, burst, defaultdict(lambda b=burst: _Bucket(tokens=float(b))), Lock())

    def consume(self, key: str, category: str) -> Tuple[bool, float]:
        if category not in self._stores:
            return True, 0.0
        rate, burst, buckets, lock = self._stores[category]
        now = time.monotonic()
        with lock:
            bucket = buckets[key]
            elapsed = now - bucket.last_refill
            if elapsed < 0:
                elapsed = 0.0
            bucket.tokens = min(burst, bucket.tokens + elapsed * rate)
            bucket.last_refill = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0.0
            return False, (1.0 - bucket.tokens) / rate

    def reset(self, key: str, category: str) -> None:
        if category in self._stores:
            _, _, buckets, lock = self._stores[category]
            with lock:
                buckets.pop(key, None)


# ---------------------------------------------------------------------------
# Redis-backed backend — production
# ---------------------------------------------------------------------------

class RedisRateLimiter(RateLimiterBackend):
    """Shared token-bucket rate limiter backed by Redis.

    Uses an atomic Lua script so concurrent requests across multiple workers
    cannot race.  Each (tenant, agent, category) combination has its own key.

    Fail-closed behavior:
      If Redis is unreachable, ALL operations are denied with HTTP 503.
      There is no fail-open path; enforcement must be guaranteed or refused.

    Key format:  ratelimit:{category}:{bucket_key}
    TTL:         ceil(burst / rate) + 10 seconds (set atomically in Lua)
    """

    IS_DEVELOPMENT_ONLY: bool = False

    def __init__(
        self,
        redis_client,
        limits: Optional[Dict[str, Tuple[float, int]]] = None,
    ):
        self._redis = redis_client
        self._limits = limits or _LIMITS
        try:
            self._script = self._redis.register_script(_REDIS_TOKEN_BUCKET_LUA)
        except Exception as e:
            logger.error(f"Failed to register Redis Lua script: {e}")
            self._script = None

    def consume(self, key: str, category: str) -> Tuple[bool, float]:
        if category not in self._limits:
            return True, 0.0
        rate, burst = self._limits[category]
        redis_key = f"ratelimit:{category}:{key}"
        now = time.time()
        try:
            result = self._script(keys=[redis_key], args=[rate, burst, now, 1])
            allowed = bool(result[0])
            retry_after = result[1] / 1000.0
            return allowed, retry_after
        except Exception as e:
            logger.error(f"Redis rate-limit error for key={redis_key}: {e}")
            logger.warning(
                f"Redis unavailable — failing closed for category '{category}'"
            )
            return False, BACKEND_UNAVAILABLE

    def reset(self, key: str, category: str) -> None:
        redis_key = f"ratelimit:{category}:{key}"
        try:
            self._redis.delete(redis_key)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Route classification
# ---------------------------------------------------------------------------

def _classify_route(path: str, method: str) -> str:
    p = path.rstrip("/")
    if "/oauth/" in p:
        return "oauth"
    if method in ("POST", "PATCH") and ("/send" in p or "/forward" in p):
        return "send"
    if method in ("POST", "PATCH") and ("/draft" in p or "/drafts" in p):
        return "draft"
    return "read"


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforces per-agent and per-tenant rate limits on all email API routes.

    Delegates to a RateLimiterBackend.  In production the backend must be
    RedisRateLimiter; DevelopmentOnlyRateLimiter is rejected at startup.
    Identity is sourced from request.state.security_context (set by
    GatewayAuthenticationMiddleware) — request headers cannot influence it.
    """

    _EXEMPT_PREFIXES = ("/health", "/docs", "/redoc", "/openapi.json")

    def __init__(self, app, backend: Optional[RateLimiterBackend] = None):
        super().__init__(app)
        self._backend = backend or DevelopmentOnlyRateLimiter()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if any(path.startswith(p) for p in self._EXEMPT_PREFIXES):
            return await call_next(request)

        ctx = getattr(request.state, "security_context", None)
        tenant_id = ctx.tenant_id if ctx else "unknown"
        agent_id = ctx.agent_id if ctx else "unknown"
        request_id = getattr(request.state, "request_id", "unknown")

        category = _classify_route(path, request.method)

        agent_key = f"{tenant_id}:{agent_id}"
        allowed, retry_after = self._backend.consume(agent_key, category)
        if not allowed:
            if retry_after == BACKEND_UNAVAILABLE:
                logger.error(
                    f"Rate-limit backend unavailable — rejecting sensitive op: "
                    f"tenant={tenant_id} agent={agent_id} category={category}"
                )
                return _backend_unavailable_response(request_id)
            logger.warning(
                f"Rate limit exceeded: tenant={tenant_id} agent={agent_id} "
                f"category={category} retry_after={retry_after:.1f}s"
            )
            return _rate_limit_response(request_id, category, retry_after)

        tenant_allowed, t_retry = self._backend.consume(tenant_id, "tenant")
        if not tenant_allowed:
            if t_retry == BACKEND_UNAVAILABLE:
                return _backend_unavailable_response(request_id)
            logger.warning(
                f"Tenant rate limit exceeded: tenant={tenant_id} retry_after={t_retry:.1f}s"
            )
            return _rate_limit_response(request_id, "tenant_global", t_retry)

        return await call_next(request)


def _backend_unavailable_response(request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": {
                "code": "RATE_LIMIT_BACKEND_UNAVAILABLE",
                "message": "Rate-limit enforcement is unavailable. Request rejected to maintain security guarantees.",
                "request_id": request_id,
            }
        },
    )


def _rate_limit_response(request_id: str, category: str, retry_after: float) -> JSONResponse:
    retry_int = max(1, int(retry_after) + 1)
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": str(retry_int)},
        content={
            "error": {
                "code": "RATE_LIMIT_EXCEEDED",
                "message": f"Rate limit exceeded for operation category '{category}'",
                "retry_after_seconds": retry_int,
                "request_id": request_id,
            }
        },
    )


def assert_rate_limiter_production_safe(backend: RateLimiterBackend) -> None:
    """Raise RuntimeError if backend is not safe for production use.

    Called during application startup before the API accepts traffic.
    """
    if getattr(backend, "IS_DEVELOPMENT_ONLY", False):
        raise RuntimeError(
            "SECURITY CONFIGURATION ERROR: DevelopmentOnlyRateLimiter is not suitable "
            "for production. Configure RATE_LIMITER_BACKEND=redis and set REDIS_URL. "
            "See docs/PHASE2_RECOVERY_REPORT.md for the required Redis-backed design."
        )


def build_rate_limiter_backend(settings=None) -> RateLimiterBackend:
    """Construct the appropriate rate-limiter backend from settings.

    Returns DevelopmentOnlyRateLimiter for development/test.
    Returns RedisRateLimiter when RATE_LIMITER_BACKEND=redis and REDIS_URL is set.
    """
    if settings is None:
        from app.config import get_settings
        settings = get_settings()

    if settings.RATE_LIMITER_BACKEND == "redis":
        if not settings.REDIS_URL:
            raise RuntimeError(
                "RATE_LIMITER_BACKEND=redis requires REDIS_URL to be configured."
            )
        if redis is None:  # pragma: no cover
            raise RuntimeError("redis package is not installed.")
        client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=False)
        logger.info(f"Rate limiter: Redis backend at {settings.REDIS_URL}")
        return RedisRateLimiter(redis_client=client)

    logger.warning(
        "Rate limiter: DevelopmentOnlyRateLimiter (in-memory, process-local). "
        "NOT suitable for multi-worker production deployment."
    )
    return DevelopmentOnlyRateLimiter()
