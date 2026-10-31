"""
Runtime security context — builds SecurityContext from verified auth tokens.
This is the layer replaced by Person 4's centralized auth in production.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from app.core.contracts import SecurityContext


def build_security_context(
    agent_id: str,
    tenant_id: str,
    capability: str,
    operation: str,
    resource: str | None = None,
    session_id: str | None = None,
) -> SecurityContext:
    """
    Construct a SecurityContext from already-verified identity claims.
    In production, agent_id and tenant_id come from Person 4's JWT validation.
    """
    return SecurityContext(
        request_id=f"req_{uuid.uuid4().hex[:16]}",
        agent_id=agent_id,
        tenant_id=tenant_id,
        capability=capability,
        operation=operation,
        resource=resource,
        session_id=session_id,
        timestamp=datetime.utcnow(),
    )
