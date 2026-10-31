"""AgentShield Email Security - FastAPI Application Entrypoint."""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.api import email_routes, health_routes, oauth_routes
from app.config import get_settings
from app.database.session import close_db, init_db
from app.middleware.authentication import GatewayAuthenticationMiddleware
from app.middleware.rate_limit import (
    RateLimitMiddleware,
    assert_rate_limiter_production_safe,
    build_rate_limiter_backend,
)
from app.middleware.request_id import RequestIdMiddleware

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("agentshield.email")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events management for startup and graceful shutdown."""
    settings = get_settings()
    logger.info(f"Starting AgentShield Email Security (Env: {settings.APP_ENV})")

    # --- Production safety assertions (run before accepting any traffic) ---
    if settings.APP_ENV == "production":
        if settings.USE_MOCK_INTEGRATIONS:
            raise RuntimeError(
                "SECURITY CONFIGURATION ERROR: USE_MOCK_INTEGRATIONS=True is forbidden "
                "in production. Set USE_MOCK_INTEGRATIONS=False."
            )
        if not settings.POLICY_SERVICE_URL:
            raise RuntimeError(
                "SECURITY CONFIGURATION ERROR: POLICY_SERVICE_URL must be configured in production."
            )
        if not settings.INSPECTION_SERVICE_URL:
            raise RuntimeError(
                "SECURITY CONFIGURATION ERROR: INSPECTION_SERVICE_URL must be configured in production."
            )
        if not settings.AUDIT_SERVICE_URL:
            raise RuntimeError(
                "SECURITY CONFIGURATION ERROR: AUDIT_SERVICE_URL must be configured in production."
            )
        assert_rate_limiter_production_safe(app.state.rate_limiter_backend)
        logger.info("[PRODUCTION] Startup security assertions passed.")
    else:
        if settings.USE_MOCK_INTEGRATIONS:
            logger.warning(
                "[%s] Mock security integrations are ACTIVE. "
                "This configuration must never be used in production.",
                settings.APP_ENV.upper(),
            )

    # Automatically create tables in local SQLite development/testing
    if "sqlite" in settings.DATABASE_URL or settings.APP_ENV in ("development", "test"):
        logger.info("Initializing database schema...")
        await init_db()

    yield

    logger.info("Shutting down AgentShield Email Security service...")
    await close_db()


def create_app() -> FastAPI:
    """Create and configure FastAPI application with security middleware and routes."""
    settings = get_settings()

    app = FastAPI(
        title="AgentShield Email Security",
        description=(
            "Independently deployable email security gateway for authorized AI agents. "
            "Enforces zero-trust policy authorization, outbound DLP inspection, "
            "recipient and attachment validation, and Google OAuth 2.0 integration."
        ),
        version="1.0.0",
        docs_url="/docs" if settings.APP_ENV != "production" else None,
        redoc_url="/redoc" if settings.APP_ENV != "production" else None,
        lifespan=lifespan,
    )

    # 1. Request ID correlation middleware
    app.add_middleware(RequestIdMiddleware)

    # 2. Gateway identity context authentication middleware
    app.add_middleware(GatewayAuthenticationMiddleware)

    # 3. Server-side rate limiting (per-agent and per-tenant)
    rate_limiter_backend = build_rate_limiter_backend(settings)
    app.state.rate_limiter_backend = rate_limiter_backend
    app.add_middleware(RateLimitMiddleware, backend=rate_limiter_backend)

    # 3. Global Exception Handlers for structured, secure error handling
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        req_id = getattr(request.state, "request_id", "unknown")
        # Sanitize errors to prevent reflection of sensitive payload data
        clean_errors = []
        for err in exc.errors():
            loc = err.get("loc", [])
            msg = err.get("msg", "Invalid field")
            clean_errors.append({"field": ".".join(str(l) for l in loc), "issue": msg})

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "REQUEST_VALIDATION_ERROR",
                    "message": "The request payload failed schema validation",
                    "request_id": req_id,
                    "details": clean_errors,
                }
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        req_id = getattr(request.state, "request_id", "unknown")
        logger.exception(f"Unhandled error processing request {req_id}: {exc}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected server error occurred. This incident has been logged.",
                    "request_id": req_id,
                }
            },
        )

    # 4. Include Route Handlers
    app.include_router(health_routes.router)
    app.include_router(oauth_routes.router)
    app.include_router(email_routes.router)

    return app


app = create_app()

