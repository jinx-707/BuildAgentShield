from __future__ import annotations

import hashlib
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api_auth import router as auth_router
from .api_dashboard import router as dashboard_router
from .api_runtime import liveness, metrics, readiness, router as runtime_router
from .config import Settings, get_settings
from .runtime import build_runtime

logger = logging.getLogger("agentshield")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    runtime = build_runtime(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await runtime.startup()
        try:
            yield
        finally:
            await runtime.shutdown()

    app = FastAPI(
        title="AgentShield Execution Gateway",
        version=settings.version,
        description=(
            "Fail-closed security gateway, approval workflow, tenant-isolated "
            "dashboard API, hash-chained audit log, and safe mock P1/P2/P3 integrations."
        ),
        lifespan=lifespan,
    )
    app.state.runtime = runtime
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Agent-Key", "X-Approval-Token"],
        expose_headers=["X-Request-ID"],
    )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:20]}"
        started = time.perf_counter()
        path = request.url.path
        if path not in {"/health", "/ready", "/metrics", "/docs", "/openapi.json"}:
            identity = (
                request.headers.get("X-Agent-Key")
                or request.headers.get("Authorization")
                or (request.client.host if request.client else "unknown")
            )
            hashed = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
            allowed, remaining = await runtime.coordination.rate_limit(
                hashed, settings.rate_limit_per_minute
            )
            if not allowed:
                return JSONResponse(
                    {"detail": "Rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": "60", "X-Request-ID": request_id},
                )
        else:
            remaining = settings.rate_limit_per_minute
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("Unhandled request error")
            duration = time.perf_counter() - started
            runtime.metrics.observe(500, duration)
            response = JSONResponse({"detail": "Internal server error"}, status_code=500)
        duration = time.perf_counter() - started
        runtime.metrics.observe(response.status_code, duration)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        errors = [
            {"loc": list(error.get("loc", [])), "msg": error.get("msg", "invalid")}
            for error in exc.errors()[:5]
        ]
        return JSONResponse({"detail": "Request validation failed", "errors": errors}, status_code=422)

    @app.get("/")
    async def root() -> dict:
        return {
            "name": settings.app_name,
            "version": settings.version,
            "docs": "/docs",
            "health": "/health",
            "api": "/api/v1",
        }

    app.add_api_route("/health", liveness, methods=["GET"], include_in_schema=False)
    app.add_api_route("/ready", readiness, methods=["GET"], include_in_schema=False)
    app.add_api_route("/metrics", metrics, methods=["GET"], include_in_schema=False)
    app.include_router(runtime_router, prefix="/v1")
    app.include_router(auth_router, prefix="/v1")
    app.include_router(dashboard_router, prefix="/v1")
    app.include_router(runtime_router, prefix="/api/v1", include_in_schema=False)
    app.include_router(auth_router, prefix="/api/v1", include_in_schema=False)
    app.include_router(dashboard_router, prefix="/api/v1", include_in_schema=False)
    return app


app = create_app()
