"""
FastAPI dependency injection.
Provides gateway instances and authentication context from the runtime.
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from app.core.configuration import get_settings
from app.core.runtime import runtime
from app.core.security_context import build_security_context
from app.core.contracts import SecurityContext

logger = logging.getLogger(__name__)


async def get_auth_context(
    x_agent_id: str = Header(default="agent_test"),
    x_tenant_id: str = Header(default="tenant_test"),
    x_api_key: str = Header(default=""),
) -> SecurityContext:
    """
    Local development authentication.
    In production, replaced by Person 4's JWT validation middleware.

    Validates the dev API key from headers.
    Returns a SecurityContext with verified agent/tenant identity.
    """
    settings = get_settings()

    if settings.local_auth_enabled:
        if x_api_key and x_api_key != settings.local_dev_api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
    else:
        # Auth is handled externally (Person 4) — trust headers
        if not x_agent_id or not x_tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Agent and tenant identity required",
            )

    return build_security_context(
        agent_id=x_agent_id,
        tenant_id=x_tenant_id,
        capability="unknown",
        operation="unknown",
    )


AuthContext = Annotated[SecurityContext, Depends(get_auth_context)]


def get_runtime():
    """Returns the application runtime (for advanced DI)."""
    return runtime
