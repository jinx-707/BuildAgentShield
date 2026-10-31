"""Gateway context authentication and caller identity derivation middleware."""

import logging
from typing import Optional
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from app.config import get_settings
from app.schemas.security import SecurityContext

logger = logging.getLogger("agentshield.middleware.auth")

HEADER_TENANT_ID = "X-Tenant-ID"
HEADER_AGENT_ID = "X-Agent-ID"
HEADER_AUTHORIZATION = "Authorization"

# Unauthenticated public endpoints
EXEMPT_PATHS = {
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/online/email/oauth/google/callback",
}


class GatewayAuthenticationMiddleware(BaseHTTPMiddleware):
    """Enforces that identity is strictly derived from the trusted API gateway."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        # Allow exempt endpoints
        if path in EXEMPT_PATHS:
            # Set default context if available
            request.state.security_context = SecurityContext(
                tenant_id="public",
                agent_id="gateway",
                request_id=getattr(request.state, "request_id", "unauthenticated"),
                authenticated=True,
            )
            return await call_next(request)

        settings = get_settings()
        auth_header = request.headers.get(HEADER_AUTHORIZATION, "")
        tenant_id = request.headers.get(HEADER_TENANT_ID)
        agent_id = request.headers.get(HEADER_AGENT_ID)
        request_id = getattr(request.state, "request_id", "req-unknown")

        # Validate Bearer service token if gateway authentication is required or in production
        is_token_valid = False
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token and token == settings.INTERNAL_SERVICE_TOKEN:
                is_token_valid = True

        strict_mode = settings.REQUIRE_GATEWAY_AUTH or settings.APP_ENV == "production"

        if strict_mode:
            if not is_token_valid:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={
                        "error": {
                            "code": "INVALID_GATEWAY_CREDENTIALS",
                            "message": "Missing or invalid internal gateway service token",
                            "request_id": request_id,
                        }
                    },
                )
            if not tenant_id or not agent_id:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={
                        "error": {
                            "code": "MISSING_GATEWAY_IDENTITY",
                            "message": "Missing required X-Tenant-ID or X-Agent-ID gateway headers",
                            "request_id": request_id,
                        }
                    },
                )
        else:
            # In non-strict development/test mode, fall back to dev defaults if headers omitted
            if not tenant_id:
                tenant_id = "tenant-dev-default"
            if not agent_id:
                agent_id = "agent-dev-default"

        request.state.security_context = SecurityContext(
            tenant_id=tenant_id,
            agent_id=agent_id,
            request_id=request_id,
            authenticated=True,
        )

        return await call_next(request)


def get_security_context(request: Request) -> SecurityContext:
    """Dependency for extracting verified SecurityContext from request state."""
    context: Optional[SecurityContext] = getattr(request.state, "security_context", None)
    if not context:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated gateway identity context not found",
        )
    return context

