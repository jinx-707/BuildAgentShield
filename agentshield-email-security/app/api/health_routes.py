"""Health check routes."""

import asyncio
import logging

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database.session import get_db
from app.middleware.rate_limit import DevelopmentOnlyRateLimiter, RedisRateLimiter

logger = logging.getLogger("agentshield.health")

router = APIRouter(tags=["Health"])

_DB_CHECK_TIMEOUT_SECONDS = 3.0


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Service Health Check",
    description="Returns service status, environment, and database connectivity.",
)
async def health_check(db: AsyncSession = Depends(get_db)):
    settings = get_settings()
    db_status = "unknown"
    try:
        await db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"unhealthy: {e}"

    return {
        "status": "ok",
        "service": "agentshield-email-security",
        "version": "1.0.0",
        "environment": settings.APP_ENV,
        "database": db_status,
        "mock_integrations": settings.USE_MOCK_INTEGRATIONS,
    }


async def _check_database() -> str:
    """Open an independent DB connection and run SELECT 1.

    Bounded by _DB_CHECK_TIMEOUT_SECONDS so a hung database cannot stall
    the readiness endpoint indefinitely.  Returns 'ok' or 'unavailable'.
    """
    from app.database.session import async_session_factory

    async def _query():
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))

    try:
        await asyncio.wait_for(_query(), timeout=_DB_CHECK_TIMEOUT_SECONDS)
        return "ok"
    except asyncio.CancelledError:
        raise
    except Exception:
        return "unavailable"


def _check_redis_backend(backend) -> str:
    """Inspect the actual active backend instance and ping Redis if applicable.

    Returns 'ok', 'unavailable', or 'not_configured'.
    Checks the real backend object — not just the settings string — so a
    misconfigured startup (e.g. DevelopmentOnlyRateLimiter wired when Redis
    was expected) is detected accurately.
    """
    if isinstance(backend, RedisRateLimiter):
        try:
            backend._redis.ping()
            return "ok"
        except Exception:
            return "unavailable"
    # DevelopmentOnlyRateLimiter or None — Redis is not in use
    return "not_configured"


@router.get(
    "/health/ready",
    summary="Readiness Check",
    description=(
        "Verifies that all mandatory dependencies are reachable before the application "
        "accepts traffic. Returns HTTP 200 when ready, HTTP 503 when not ready."
    ),
)
async def readiness_check(request: Request):
    settings = get_settings()
    checks: dict = {}
    ready = True

    # --- Database (bounded timeout) ---
    db_status = await _check_database()
    checks["database"] = db_status
    if db_status != "ok":
        ready = False

    # --- Rate-limit backend ---
    # Inspect the actual wired backend, not just the config string, so a
    # misconfigured startup is caught here rather than silently passing.
    backend = getattr(request.app.state, "rate_limiter_backend", None)
    redis_status = _check_redis_backend(backend)
    checks["redis"] = redis_status

    if settings.RATE_LIMITER_BACKEND == "redis":
        # Redis was required — any non-ok result blocks readiness
        if redis_status != "ok":
            ready = False
    elif settings.APP_ENV == "production" and isinstance(backend, DevelopmentOnlyRateLimiter):
        # Production must never run with the development limiter
        checks["redis"] = "development_limiter_in_production"
        ready = False

    # --- Policy service (configuration check; live connectivity not verified) ---
    if settings.POLICY_SERVICE_URL:
        checks["policy_service"] = "configured"
    else:
        checks["policy_service"] = "not_configured"
        if settings.APP_ENV == "production":
            ready = False

    # --- Inspection service (configuration check; live connectivity not verified) ---
    if settings.INSPECTION_SERVICE_URL:
        checks["inspection_service"] = "configured"
    else:
        checks["inspection_service"] = "not_configured"
        if settings.APP_ENV == "production":
            ready = False

    http_status = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(
        status_code=http_status,
        content={
            "status": "ready" if ready else "not_ready",
            "service": "agentshield-email-security",
            "checks": checks,
        },
    )

