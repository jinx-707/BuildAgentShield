from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque

try:
    from redis.asyncio import Redis
except ImportError:
    Redis = None


class CoordinationStore:
    def __init__(self, redis_url: str | None) -> None:
        self.redis_url = redis_url
        self.redis = None
        self.status = "MOCK"
        self.detail = "in-process fallback"
        self._windows: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        if not self.redis_url or Redis is None:
            return
        try:
            self.redis = Redis.from_url(self.redis_url, decode_responses=True)
            await self.redis.ping()
            self.status = "REAL"
            self.detail = "redis connected"
        except Exception:
            self.redis = None
            self.status = "UNHEALTHY"
            self.detail = "redis unavailable; using in-process limiter"

    async def close(self) -> None:
        if self.redis is not None:
            await self.redis.aclose()
            self.redis = None

    async def rate_limit(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        if self.redis is not None:
            try:
                bucket = f"agentshield:rl:{key}:{int(time.time() // window_seconds)}"
                count = await self.redis.incr(bucket)
                if count == 1:
                    await self.redis.expire(bucket, window_seconds + 1)
                return count <= limit, max(0, limit - int(count))
            except Exception:
                self.status = "UNHEALTHY"
                self.detail = "redis runtime failure; using in-process limiter"
        now = time.monotonic()
        async with self._lock:
            window = self._windows[key]
            while window and now - window[0] > window_seconds:
                window.popleft()
            if len(window) >= limit:
                return False, 0
            window.append(now)
            return True, limit - len(window) - 1
