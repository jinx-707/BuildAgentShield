"""
AgentShield Online Security Module — FastAPI Application
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import browser, downloads, email, external_apis, mcp, payments
from app.core.configuration import get_settings
from app.core.exceptions import AgentShieldError
from app.core.runtime import runtime
from app.db import init_db
from app.integrations.local_audit_adapter import LocalAuditAdapter
from app.integrations.local_approval_adapter import LocalApprovalAdapter
from app.integrations.local_policy_adapter import LocalPolicyAdapter
from app.integrations.local_security_adapter import (
    LocalContentInspectionAdapter,
    LocalDataInspectionAdapter,
)
from app.integrations.secret_provider import LocalEnvSecretProvider

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    settings = get_settings()
    logger.info("AgentShield Online starting (env=%s)", settings.app_env)

    # Enforce test-only payment mode
    if settings.payment_mode != "test":
        raise RuntimeError("CRITICAL: payment_mode must be 'test'")

    # Initialize local adapters
    # In production, these are replaced by Person 1 and Person 4 implementations
    runtime.content_inspector = LocalContentInspectionAdapter()
    runtime.data_inspector = LocalDataInspectionAdapter()
    runtime.policy = LocalPolicyAdapter()
    runtime.approval = LocalApprovalAdapter()
    runtime.audit = LocalAuditAdapter()
    runtime.secret_provider = LocalEnvSecretProvider()

    # Initialize database
    await init_db()

    runtime.mark_ready()
    logger.info("AgentShield Online ready — all adapters initialized (LOCAL DEV MODE)")

    yield

    logger.info("AgentShield Online shutting down")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="AgentShield Online Security Module",
        description=(
            "Controls browser access, email operations, file downloads, "
            "external APIs, MCP tools and financial transactions for AI agents.\n\n"
            "**TEST MODE ONLY** — No real money is processed."
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS (restrictive defaults)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:8000"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["X-Agent-Id", "X-Tenant-Id", "X-Api-Key", "Content-Type"],
    )

    # Error handlers
    @app.exception_handler(AgentShieldError)
    async def agentshield_error_handler(
        request: Request, exc: AgentShieldError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": exc.code,
                "message": exc.message,
                "request_id": request.headers.get("X-Request-Id", ""),
            },
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        # Never expose internal exception details
        logger.error("Unhandled error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "INTERNAL_ERROR",
                "message": "An internal error occurred. Check server logs.",
            },
        )

    # Mount routes
    prefix = "/online"
    app.include_router(browser.router, prefix=prefix)
    app.include_router(email.router, prefix=prefix)
    app.include_router(downloads.router, prefix=prefix)
    app.include_router(external_apis.router, prefix=prefix)
    app.include_router(mcp.router, prefix=prefix)
    app.include_router(payments.router, prefix=prefix)

    # Health and capabilities
    @app.get("/online/health", tags=["general"])
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "ready": runtime.is_ready(),
            "payment_mode": settings.payment_mode,
            "env": settings.app_env,
            "adapters": {
                "content_inspector": type(runtime.content_inspector).__name__,
                "data_inspector": type(runtime.data_inspector).__name__,
                "policy": type(runtime.policy).__name__,
                "approval": type(runtime.approval).__name__,
                "audit": type(runtime.audit).__name__,
            },
        }

    @app.get("/online/capabilities", tags=["general"])
    async def capabilities() -> dict[str, Any]:
        return {
            "capabilities": [
                {
                    "id": "browser",
                    "description": "Web search and browser automation",
                    "endpoints": [
                        "/online/browser/search",
                        "/online/browser/navigate",
                        "/online/browser/extract",
                        "/online/browser/action",
                    ],
                },
                {
                    "id": "email",
                    "description": "Email access and communication security",
                    "endpoints": [
                        "/online/email/search",
                        "/online/email/read",
                        "/online/email/draft",
                        "/online/email/send",
                    ],
                },
                {
                    "id": "downloads",
                    "description": "Secure file downloads",
                    "endpoints": [
                        "/online/downloads/request",
                        "/online/downloads/{id}/status",
                    ],
                },
                {
                    "id": "external_apis",
                    "description": "External API connector registry",
                    "endpoints": ["/online/apis/execute"],
                },
                {
                    "id": "mcp",
                    "description": "MCP tool security gateway",
                    "endpoints": [
                        "/online/mcp/servers",
                        "/online/mcp/tools",
                        "/online/mcp/invoke",
                    ],
                },
                {
                    "id": "payments",
                    "description": "Payment security (TEST MODE ONLY)",
                    "endpoints": [
                        "/online/payments/validate",
                        "/online/payments/request-approval",
                        "/online/payments/create-order",
                        "/online/payments/webhook",
                        "/online/payments/{id}/status",
                    ],
                    "warning": "TEST MODE ONLY — no real money",
                },
            ]
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.app_env == "development",
        log_level=settings.log_level.lower(),
    )
