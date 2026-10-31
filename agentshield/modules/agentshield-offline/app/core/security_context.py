"""
AgentShield Offline — Security context management.

The security context carries authenticated identity (agent_id, tenant_id)
that has been verified by the runtime layer. It must never be populated
from LLM-generated request bodies.

In the standalone development API, identity is derived from the verified
API key header. In production, Person 4's gateway will inject an already-
authenticated context.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class RuntimeSecurityContext:
    """
    Immutable, authenticated security context.
    Created once per request by the trusted middleware layer.
    """

    agent_id: str
    tenant_id: str
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    authenticated: bool = True
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    # Additional claims (e.g. roles, workspace) injected by auth layer
    claims: dict = field(default_factory=dict)

    def workspace(self) -> Optional[str]:
        return self.claims.get("workspace")

    def has_role(self, role: str) -> bool:
        return role in self.claims.get("roles", [])


# ---------------------------------------------------------------------------
# Development identity factory
# Used only in the standalone API; replace with Person 4's auth in production.
# ---------------------------------------------------------------------------


def create_dev_context(
    agent_id: str = "dev-agent",
    tenant_id: str = "dev-tenant",
    workspace: str = "/workspace",
) -> RuntimeSecurityContext:
    """
    Create a development security context.
    NOT for production use — no real authentication is performed.
    """
    return RuntimeSecurityContext(
        agent_id=agent_id,
        tenant_id=tenant_id,
        claims={"workspace": workspace, "roles": ["agent"]},
    )
