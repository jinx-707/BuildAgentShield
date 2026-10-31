"""
AgentShield Offline Security Module — Standalone FastAPI Application.

⚠️  DEVELOPMENT / STANDALONE API ⚠️

This application is the standalone development interface for Person 2's
Offline Security Module. It is intended to be used for:
  - Independent testing before the main AgentShield gateway is available.
  - Integration testing with mock adapters.
  - Demo and example scripts.

In production, this application will be mounted as a sub-application or
its routers will be imported by AgentShield's central gateway (Person 4).
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import documents, environment, filesystem, nemo, p1, system_files, terminal
from app.core.configuration import get_settings
from app.utils.structured_logging import configure_logging

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(debug=settings.debug)
    log.info(
        "agentshield_offline_starting",
        version=settings.app_version,
        environment=settings.environment,
        note="STANDALONE DEVELOPMENT API — not for production use without gateway integration",
    )
    # Eagerly initialise NeMo engine if enabled (startup cost paid once)
    if settings.nemo_enabled:
        from app.api.dependencies import get_nemo_engine
        engine = get_nemo_engine()
        if engine is not None:
            log.info(
                "nemo_engine_startup_complete",
                available=engine.is_available(),
                profile=settings.nemo_profile,
            )
    yield
    log.info("agentshield_offline_shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(debug=settings.debug)

    app = FastAPI(
        title="AgentShield Offline Security Module",
        description=(
            "**STANDALONE DEVELOPMENT API** — Person 2's Offline Security Module.\n\n"
            "Provides document analysis, system file protection, local file access control, "
            "environment/secret isolation, and sandboxed terminal execution.\n\n"
            "⚠️ This is a standalone development interface. In production it will be "
            "mounted by AgentShield's central API gateway."
        ),
        version=settings.app_version,
        docs_url="/offline/docs",
        redoc_url="/offline/redoc",
        openapi_url="/offline/openapi.json",
        lifespan=lifespan,
    )

    # CORS — restrict in production
    if settings.environment == "development":
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000", "http://localhost:8000"],
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    # Mount all offline routers under /offline prefix
    prefix = settings.api_prefix

    app.include_router(documents.router, prefix=prefix)
    app.include_router(filesystem.router, prefix=prefix)
    app.include_router(system_files.router, prefix=prefix)
    app.include_router(environment.router, prefix=prefix)
    app.include_router(terminal.router, prefix=prefix)
    app.include_router(nemo.router, prefix=prefix)
    app.include_router(p1.router, prefix=prefix)

    # ---- Health & capabilities endpoints ----

    @app.get(f"{prefix}/health", tags=["Meta"])
    async def health():
        return {
            "status": "healthy",
            "module": "agentshield-offline",
            "version": settings.app_version,
            "environment": settings.environment,
            "note": "Standalone development API",
        }

    @app.get(f"{prefix}/capabilities", tags=["Meta"])
    async def capabilities():
        return {
            "module": "agentshield-offline",
            "capabilities": [
                {
                    "id": "document_analysis",
                    "endpoints": [f"{prefix}/documents/analyze"],
                    "description": "Secure document parsing, malware scanning, content inspection",
                },
                {
                    "id": "local_file_access",
                    "endpoints": [
                        f"{prefix}/files/read",
                        f"{prefix}/files/search",
                        f"{prefix}/files/list",
                        f"{prefix}/files/create",
                        f"{prefix}/files/update",
                        f"{prefix}/files/delete",
                        f"{prefix}/files/move",
                        f"{prefix}/files/copy",
                    ],
                    "description": "Workspace-scoped file access with per-operation permissions",
                },
                {
                    "id": "system_file_protection",
                    "endpoints": [f"{prefix}/system/inspect"],
                    "description": "Protected OS path enforcement",
                },
                {
                    "id": "environment_protection",
                    "endpoints": [
                        f"{prefix}/environment/inspect",
                        f"{prefix}/environment/secret",
                    ],
                    "description": "Environment variable isolation and secret brokering",
                },
                {
                    "id": "terminal_execution",
                    "endpoints": [f"{prefix}/terminal/execute"],
                    "description": "Sandboxed command execution via Docker",
                },
            ],
        }

    # ---- Global exception handler ----

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        log.error("unhandled_exception", error=str(exc), path=request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "detail": "An unexpected error occurred. Check server logs.",
            },
        )

    return app


app = create_app()


def main():
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level="debug" if settings.debug else "info",
    )


if __name__ == "__main__":
    main()
