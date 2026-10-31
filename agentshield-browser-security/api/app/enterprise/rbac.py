"""Role-based access control for AgentShield enterprise platform.

Roles define a set of permissions. Permissions are checked against the
authenticated principal's organization membership and role.
"""

from typing import Optional

from fastapi import HTTPException, status

# Canonical role definitions with their permissions.
ROLE_PERMISSIONS = {
    "owner": {
        "org:read",
        "org:write",
        "org:delete",
        "user:read",
        "user:write",
        "user:delete",
        "membership:read",
        "membership:write",
        "membership:delete",
        "agent:read",
        "agent:write",
        "agent:delete",
        "agent:credentials",
        "session:read",
        "session:write",
        "session:delete",
        "policy:read",
        "policy:write",
        "policy:delete",
        "audit:read",
        "incident:read",
        "incident:write",
        "deployment:read",
        "deployment:write",
        "deployment:delete",
        "config:read",
        "config:write",
    },
    "administrator": {
        "org:read",
        "org:write",
        "user:read",
        "user:write",
        "membership:read",
        "membership:write",
        "agent:read",
        "agent:write",
        "agent:delete",
        "agent:credentials",
        "session:read",
        "session:write",
        "session:delete",
        "policy:read",
        "policy:write",
        "policy:delete",
        "audit:read",
        "incident:read",
        "incident:write",
        "deployment:read",
        "deployment:write",
        "config:read",
    },
    "security_analyst": {
        "org:read",
        "user:read",
        "agent:read",
        "session:read",
        "policy:read",
        "audit:read",
        "incident:read",
        "incident:write",
        "deployment:read",
    },
    "operator": {
        "org:read",
        "agent:read",
        "agent:write",
        "session:read",
        "session:write",
        "session:delete",
        "policy:read",
        "audit:read",
        "deployment:read",
    },
    "viewer": {
        "org:read",
        "user:read",
        "agent:read",
        "session:read",
        "policy:read",
        "audit:read",
        "incident:read",
        "deployment:read",
    },
    # Agent SDK role — scoped to the org's own agent actions
    "agent": {
        "session:read",
        "session:write",
        "audit:read",
        "agent:action",
    },
}


def role_has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


class Principal:
    """Authenticated principal bound to an organization."""

    def __init__(
        self,
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        organization_id: str,
        role: str,
        permissions: set[str],
    ):
        self.user_id = user_id
        self.agent_id = agent_id
        self.organization_id = organization_id
        self.role = role
        self.permissions = permissions

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def require_permission(self, permission: str) -> None:
        if not self.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "INSUFFICIENT_PERMISSIONS",
                    "message": f"permission required: {permission}",
                },
            )


def get_role_permissions(role: str) -> set[str]:
    return set(ROLE_PERMISSIONS.get(role, set()))


def principal_from_membership(
    *,
    user_id: str,
    organization_id: str,
    role: str,
) -> Principal:
    return Principal(
        user_id=user_id,
        organization_id=organization_id,
        role=role,
        permissions=get_role_permissions(role),
    )


def principal_from_agent(
    *,
    agent_id: str,
    organization_id: str,
) -> Principal:
    # Agents get a limited permission set by default.
    return Principal(
        agent_id=agent_id,
        organization_id=organization_id,
        role="agent",
        permissions={
            "session:read",
            "session:write",
            "audit:read",
        },
    )
