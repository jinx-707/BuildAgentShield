"""Rate limiting with trusted client identity and optional shared Redis state.

The in-memory backend exists for development and tests only. Production startup
rejects it so a horizontally scaled deployment cannot silently multiply the
effective limit. Redis updates use a single Lua script (INCR + PEXPIRE), which
is atomic across replicas.

Failure policy is explicit: backend errors return 503 by default. Operators may
opt into ``RATE_LIMIT_FAIL_OPEN=true`` for a documented degraded mode; that
choice is logged and never selected automatically.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Protocol
from urllib.parse import urlparse

from app.config import Settings
from app.security.trusted_proxy import ClientIdentity, parse_trusted_proxies

logger = logging.getLogger(__name__)

_DEVELOPMENT_BACKENDS = {"memory"}
_REDIS_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = ARGV[1]
end
return {current, ttl}
"""


class RateLimitConfigurationError(ValueError):
    """Invalid or unsafe rate-limit configuration."""


class RateLimitError(Exception):
    """Base class for rate-limit failures."""


class RateLimitExceeded(RateLimitError):
    def __init__(
        self,
        *,
        category: str,
        scope: str,
        limit: int,
        retry_after: int,
    ) -> None:
        super().__init__("rate limit exceeded")
        self.category = category
        self.scope = scope
        self.limit = limit
        self.retry_after = max(1, int(retry_after))


class RateLimitBackendUnavailable(RateLimitError):
    def __init__(self, message: str = "rate-limit backend is unavailable") -> None:
        super().__init__(message)
        self.code = "RATE_LIMIT_BACKEND_UNAVAILABLE"


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int = 0


class RateLimitBackend(Protocol):
    async def increment(
        self, key: str, *, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        ...

    async def aclose(self) -> None:
        ...


class InMemoryRateLimitBackend:
    """Development-only fixed-window counter.

    The class is deliberately explicit in logs and rejected by production
    configuration. It is process-local, so it cannot coordinate replicas.
    """

    development_only = True

    def __init__(self, *, max_keys: int = 10000) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = Lock()
        self._max_keys = max_keys

    def _prune_key(self, key: str, now: float, cutoff: float) -> None:
        hits = self._hits.get(key)
        if hits is None:
            return
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if not hits:
            self._hits.pop(key, None)

    def _make_room(self, now: float, cutoff: float) -> None:
        if len(self._hits) <= self._max_keys:
            return
        for key in list(self._hits):
            self._prune_key(key, now, cutoff)
            if len(self._hits) <= self._max_keys:
                return
        # Still full of live buckets: drop the oldest key rather than grow
        # without bound. This is a development-only safety valve.
        while len(self._hits) > self._max_keys:
            oldest = min(
                self._hits,
                key=lambda candidate: self._hits[candidate][0],
            )
            self._hits.pop(oldest, None)

    async def increment(
        self, key: str, *, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            self._prune_key(key, now, cutoff)
            self._make_room(now, cutoff)
            hits = self._hits.setdefault(key, deque())
            if len(hits) >= limit:
                retry_after = int(window_seconds - (now - hits[0])) + 1
                return RateLimitDecision(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    retry_after=max(1, retry_after),
                )
            hits.append(now)
            return RateLimitDecision(
                allowed=True,
                limit=limit,
                remaining=max(0, limit - len(hits)),
            )

    async def aclose(self) -> None:
        with self._lock:
            self._hits.clear()


class RedisRateLimitBackend:
    """Atomic shared counter backend using Redis INCR + PEXPIRE."""

    development_only = False

    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = 1.0,
        key_prefix: str = "agentshield:ratelimit:",
        client=None,
    ) -> None:
        self._key_prefix = key_prefix
        if client is not None:
            self._client = client
            return
        try:
            import redis.asyncio as redis
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise RateLimitConfigurationError(
                "RATE_LIMIT_BACKEND=redis requires the 'redis' Python package"
            ) from exc

        self._client = redis.Redis.from_url(
            url,
            socket_connect_timeout=timeout_seconds,
            socket_timeout=timeout_seconds,
            retry_on_timeout=False,
            health_check_interval=0,
            decode_responses=False,
        )

    async def increment(
        self, key: str, *, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        try:
            result = await self._client.eval(
                _REDIS_SCRIPT,
                1,
                f"{self._key_prefix}{key}",
                max(1, int(window_seconds * 1000)),
            )
            current = int(result[0])
            ttl_ms = int(result[1])
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise RateLimitBackendUnavailable() from exc

        if current > limit:
            return RateLimitDecision(
                allowed=False,
                limit=limit,
                remaining=0,
                retry_after=max(1, math.ceil(max(0, ttl_ms) / 1000)),
            )
        return RateLimitDecision(
            allowed=True,
            limit=limit,
            remaining=max(0, limit - current),
        )

    async def aclose(self) -> None:
        close = getattr(self._client, "aclose", None)
        if close is not None:
            await close()
        else:  # pragma: no cover - older redis-py
            await self._client.close()


@dataclass(frozen=True)
class LimitPolicy:
    limit: int
    window_seconds: int


def _bucket_key(category: str, scope: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:40]
    return f"{category}:{scope}:{digest}"


class RateLimiter:
    """Apply category limits across tenant, session and IP dimensions."""

    def __init__(
        self,
        backend: RateLimitBackend,
        *,
        policies: dict[str, LimitPolicy],
        fail_open: bool = False,
    ) -> None:
        self._backend = backend
        self._policies = policies
        self._fail_open = fail_open

    async def check(
        self,
        category: str,
        identity: ClientIdentity,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        policy = self._policies.get(category)
        if policy is None:
            return

        dimensions: list[tuple[str, str]] = []
        if agent_id:
            dimensions.append(("tenant", agent_id))
        if session_id:
            dimensions.append(("session", session_id))
        dimensions.append(("ip", identity.address))

        for scope, value in dimensions:
            key = _bucket_key(category, scope, value)
            try:
                decision = await self._backend.increment(
                    key,
                    limit=policy.limit,
                    window_seconds=policy.window_seconds,
                )
            except RateLimitBackendUnavailable:
                if self._fail_open:
                    logger.error(
                        "rate_limit_backend_unavailable_fail_open",
                        extra={"category": category, "scope": scope},
                    )
                    return
                logger.error(
                    "rate_limit_backend_unavailable_fail_closed",
                    extra={"category": category, "scope": scope},
                )
                raise
            if not decision.allowed:
                logger.warning(
                    "rate_limit_exceeded",
                    extra={
                        "category": category,
                        "scope": scope,
                        "limit": decision.limit,
                    },
                )
                raise RateLimitExceeded(
                    category=category,
                    scope=scope,
                    limit=decision.limit,
                    retry_after=decision.retry_after,
                )

    async def aclose(self) -> None:
        await self._backend.aclose()


def validate_rate_limit_settings(settings: Settings) -> None:
    """Validate settings at startup and fail closed on unsafe production config."""

    parse_trusted_proxies(settings.rate_limit_trusted_proxies)

    environment = settings.environment.lower()
    if environment == "production" and not settings.rate_limit_enabled:
        raise RateLimitConfigurationError(
            "RATE_LIMIT_ENABLED must be true in production"
        )
    if (
        environment == "production"
        and settings.rate_limit_backend in _DEVELOPMENT_BACKENDS
    ):
        raise RateLimitConfigurationError(
            "RATE_LIMIT_BACKEND=memory is development-only; "
            "set RATE_LIMIT_BACKEND=redis and REDIS_URL in production"
        )
    if settings.rate_limit_backend == "redis":
        redis_url = settings.redis_url.get_secret_value()
        if not redis_url:
            raise RateLimitConfigurationError(
                "REDIS_URL is required when RATE_LIMIT_BACKEND=redis"
            )
        parsed = urlparse(redis_url)
        if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
            raise RateLimitConfigurationError(
                "REDIS_URL must be an absolute redis:// or rediss:// URL"
            )


def build_rate_limiter(settings: Settings) -> RateLimiter:
    validate_rate_limit_settings(settings)

    if settings.rate_limit_backend == "redis":
        backend: RateLimitBackend = RedisRateLimitBackend(
            settings.redis_url.get_secret_value(),
            timeout_seconds=settings.redis_timeout_seconds,
        )
    else:
        backend = InMemoryRateLimitBackend()
        logger.warning(
            "rate_limit_memory_backend_development_only",
            extra={"environment": settings.environment},
        )

    window = settings.rate_limit_window_seconds
    policies = {
        "api": LimitPolicy(settings.rate_limit_per_minute, window),
        "navigation": LimitPolicy(settings.rate_limit_navigation_per_minute, window),
        "search": LimitPolicy(settings.rate_limit_search_per_minute, window),
        "session_create": LimitPolicy(
            settings.rate_limit_session_create_per_minute, window
        ),
        "action": LimitPolicy(settings.rate_limit_action_per_minute, window),
        "extract": LimitPolicy(settings.rate_limit_extract_per_minute, window),
        "screenshot": LimitPolicy(settings.rate_limit_screenshot_per_minute, window),
    }
    return RateLimiter(
        backend,
        policies=policies,
        fail_open=settings.rate_limit_fail_open,
    )
