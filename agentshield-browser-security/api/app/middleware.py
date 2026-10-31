import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.logging_config import request_id_ctx
from app.security.rate_limit import (
    RateLimitBackendUnavailable,
    RateLimitExceeded,
    RateLimiter,
)
from app.security.trusted_proxy import (
    ClientIdentity,
    InvalidForwardedAddress,
    resolve_client_identity,
)

REQUEST_ID_HEADER = "X-Request-ID"
SESSION_ID_HEADER = "X-Agent-Session"
AGENT_ID_HEADER = "X-Agent-ID"
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEALTH_LIVE_PATH = "/health/live"
_HEALTH_PATHS = {"/health/live", "/health", "/health/ready"}

logger = logging.getLogger(__name__)


def _timing_safe_equal(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


class ApiAuthMiddleware(BaseHTTPMiddleware):
    """Optional Bearer token authentication for API callers.

    When api_auth_token is set, all non-health endpoints require
    Authorization: Bearer <token>. Health endpoints are always exempt.
    """

    def __init__(self, app, *, api_auth_token: str = "", enabled: bool = True):
        super().__init__(app)
        self._token = api_auth_token
        self._enabled = enabled and bool(api_auth_token)

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self._enabled:
            return await call_next(request)

        path = request.url.path
        if path in _HEALTH_PATHS:
            return await call_next(request)

        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            logger.warning("api_auth_missing", extra={"path": path})
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "code": "API_AUTH_REQUIRED",
                    "message": "API authentication is required",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        supplied = header[len("Bearer "):]
        if not _timing_safe_equal(supplied, self._token):
            logger.warning("api_auth_failed", extra={"path": path})
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "code": "API_AUTH_FAILED",
                    "message": "API authentication failed",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)


_AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_FORWARDED_FOR_HEADER = "x-forwarded-for"


def _agent_id_for_limit(raw_value: str | None) -> str | None:
    if not raw_value or not _AGENT_ID_PATTERN.fullmatch(raw_value):
        return None
    return raw_value


def rate_limit_response(exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={
            "error": "rate_limit_exceeded",
            "code": "RATE_LIMIT_EXCEEDED",
            "message": "too many requests for this scope",
            "scope": exc.scope,
            "category": exc.category,
            "limit": exc.limit,
            "retry_after": exc.retry_after,
        },
        headers={
            "Retry-After": str(exc.retry_after),
            "X-RateLimit-Limit": str(exc.limit),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Scope": exc.scope,
        },
    )


def rate_limit_backend_response(
    exc: RateLimitBackendUnavailable,
) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "error": "rate_limit_backend_unavailable",
            "code": exc.code,
            "message": "the rate-limit backend is unavailable",
        },
        headers={"Retry-After": "1"},
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply trusted-proxy-aware limits before authentication and routing.

    The direct peer is authoritative. ``X-Forwarded-For`` is used only when the
    peer is in ``RATE_LIMIT_TRUSTED_PROXIES``; malformed chains from a trusted
    peer are rejected instead of being silently rewritten. Untrusted peers
    cannot influence their bucket with the header.
    """

    def __init__(
        self,
        app,
        *,
        limiter: RateLimiter,
        trusted_proxies=(),
        max_hops: int = 10,
        enabled: bool = True,
    ):
        super().__init__(app)
        self._limiter = limiter
        self._trusted_proxies = trusted_proxies
        self._max_hops = max_hops
        self._enabled = enabled

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if path == _HEALTH_LIVE_PATH:
            return await call_next(request)

        try:
            identity = resolve_client_identity(
                request.client.host if request.client else None,
                request.headers.get(_FORWARDED_FOR_HEADER),
                trusted_proxies=self._trusted_proxies,
                max_hops=self._max_hops,
            )
        except InvalidForwardedAddress as exc:
            logger.warning(
                "invalid_forwarded_for",
                extra={"path": path, "code": exc.code},
            )
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "code": exc.code,
                    "message": str(exc),
                },
            )

        request.state.client_identity = identity
        request.state.client_ip = identity.address

        if not self._enabled:
            return await call_next(request)

        try:
            await self._limiter.check(
                "api",
                identity,
                agent_id=_agent_id_for_limit(request.headers.get(AGENT_ID_HEADER)),
            )
        except RateLimitExceeded as exc:
            return rate_limit_response(exc)
        except RateLimitBackendUnavailable as exc:
            return rate_limit_backend_response(exc)

        return await call_next(request)


async def enforce_category_rate_limit(
    request: Request,
    category: str,
    *,
    session_id: str | None = None,
) -> None:
    """Apply a route-specific limit after the payload has been validated."""

    if not getattr(request.app.state, "rate_limit_enabled", True):
        return
    limiter = getattr(request.app.state, "rate_limiter", None)
    identity: ClientIdentity | None = getattr(
        request.state, "client_identity", None
    )
    if limiter is None or identity is None:
        return
    await limiter.check(
        category,
        identity,
        agent_id=_agent_id_for_limit(request.headers.get(AGENT_ID_HEADER)),
        session_id=session_id,
    )


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get(REQUEST_ID_HEADER)
        request_id = (
            incoming
            if incoming and _REQUEST_ID_PATTERN.fullmatch(incoming)
            else uuid.uuid4().hex
        )
        token = request_id_ctx.set(request_id)
        request.state.request_id = request_id
        started = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "request_failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            )
            request_id_ctx.reset(token)
            raise

        response.headers[REQUEST_ID_HEADER] = request_id
        logger.info(
            "request_completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        request_id_ctx.reset(token)
        return response
