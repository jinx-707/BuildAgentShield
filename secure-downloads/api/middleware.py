"""
API middleware: authentication, rate limiting, request-ID propagation.

Mirrors the patterns from the browser-security API middleware but is
fully standalone and does not import from that codebase.
"""
from __future__ import annotations

import hmac
import logging
import re
import time
import uuid
from collections import defaultdict
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEALTH_PATHS = {"/health", "/health/live", "/health/ready"}


def _timing_safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request_id to every request and logs completion."""

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get(REQUEST_ID_HEADER, "")
        request_id = (
            incoming
            if _REQUEST_ID_PATTERN.match(incoming)
            else uuid.uuid4().hex
        )
        request.state.request_id = request_id
        start = time.monotonic()
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "request_completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "elapsed_ms": elapsed_ms,
                "request_id": request_id,
            },
        )
        return response


class ApiAuthMiddleware(BaseHTTPMiddleware):
    """Optional Bearer token auth.  Health endpoints are always exempt."""

    def __init__(self, app, *, api_auth_token: str = "") -> None:
        super().__init__(app)
        self._token = api_auth_token
        self._enabled = bool(api_auth_token)

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self._enabled or request.url.path in _HEALTH_PATHS:
            return await call_next(request)

        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "code": "API_AUTH_REQUIRED",
                    "message": "API authentication is required.",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        supplied = header[len("Bearer "):]
        if not _timing_safe_equal(supplied, self._token):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "code": "API_AUTH_FAILED",
                    "message": "API authentication failed.",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory sliding-window limiter, enforced per client IP and per tenant.

    Two budgets are checked: the client IP (rotating X-Tenant-ID cannot evade
    it) and, when the header is present, the tenant (rotating source IPs
    cannot evade it).  A request is rejected when either budget is exhausted.
    Buckets are pruned on a fixed cadence so an attacker cycling identifiers
    cannot grow memory without bound.
    """

    _MAX_BUCKETS = 50_000

    def __init__(self, app, *, max_per_minute: int = 30, enabled: bool = True) -> None:
        super().__init__(app)
        self._enabled = enabled
        self._max = max_per_minute
        self._window = 60.0
        self._ip_hits: dict[str, list[float]] = defaultdict(list)
        self._tenant_hits: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._last_prune = time.monotonic()

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self._enabled or request.url.path in _HEALTH_PATHS:
            return await call_next(request)

        ip = request.client.host if request.client else "unknown"
        tenant = request.headers.get("X-Tenant-ID", "").strip()
        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            self._prune_if_due(now, cutoff)
            retry_after = self._consume(self._ip_hits, f"ip:{ip}", now, cutoff)
            if retry_after is None and tenant:
                retry_after = self._consume(
                    self._tenant_hits, f"tenant:{tenant}", now, cutoff
                )

        if retry_after is not None:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests; retry later.",
                },
                headers={"retry-after": str(retry_after)},
            )
        return await call_next(request)

    def _consume(
        self,
        table: dict[str, list[float]],
        key: str,
        now: float,
        cutoff: float,
    ) -> int | None:
        """Record one hit; return a Retry-After value when the budget is spent."""
        hits = [timestamp for timestamp in table.get(key, ()) if timestamp > cutoff]
        if len(hits) >= self._max:
            table[key] = hits
            return int(self._window - (now - hits[0])) + 1
        hits.append(now)
        table[key] = hits
        return None

    def _prune_if_due(self, now: float, cutoff: float) -> None:
        if now - self._last_prune < self._window:
            if (
                len(self._ip_hits) + len(self._tenant_hits)
                <= self._MAX_BUCKETS
            ):
                return
        self._last_prune = now
        for table in (self._ip_hits, self._tenant_hits):
            for key in list(table):
                kept = [t for t in table[key] if t > cutoff]
                if kept:
                    table[key] = kept
                else:
                    del table[key]
