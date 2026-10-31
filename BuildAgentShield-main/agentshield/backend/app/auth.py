from __future__ import annotations

from typing import Callable

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from .contracts import AuthContext, PrincipalType, UserRole
from .db import Agent, AgentKey, User
from .runtime import Runtime
from .security import decode_user_token, parse_agent_key, verify_api_key


bearer = HTTPBearer(auto_error=False)

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "stats.read",
        "agents.read",
        "agents.manage",
        "approvals.read",
        "approvals.approve",
        "approvals.reject",
        "audit.read",
        "audit.export",
        "audit.verify",
        "quarantine.read",
        "quarantine.manage",
        "policies.read",
        "policies.manage",
        "simulator.run",
        "workspace.manage",
        "tools.read",
        "gateway.execute",
    },
    "security_analyst": {
        "stats.read",
        "agents.read",
        "approvals.read",
        "audit.read",
        "audit.export",
        "audit.verify",
        "quarantine.read",
        "quarantine.manage",
        "policies.read",
        "simulator.run",
        "tools.read",
    },
    "approver": {
        "stats.read",
        "agents.read",
        "approvals.read",
        "approvals.approve",
        "approvals.reject",
        "audit.read",
        "quarantine.read",
        "policies.read",
        "simulator.run",
        "tools.read",
    },
    "viewer": {
        "stats.read",
        "agents.read",
        "approvals.read",
        "audit.read",
        "quarantine.read",
        "policies.read",
        "tools.read",
    },
    "auditor": {
        "stats.read",
        "agents.read",
        "audit.read",
        "audit.export",
        "audit.verify",
        "policies.read",
    },
}


def get_runtime(request: Request) -> Runtime:
    return request.app.state.runtime


async def get_dashboard_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> AuthContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    runtime = get_runtime(request)
    try:
        payload = decode_user_token(runtime.settings, credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    if payload.get("type") != "dashboard":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong token type")
    async with runtime.database.session() as session:
        user = await session.get(User, str(payload["sub"]))
    if user is None or not user.active or user.tenant_id != payload.get("tid"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User is not active")
    role = user.role if user.role in ROLE_PERMISSIONS else "viewer"
    return AuthContext(
        tenant_id=user.tenant_id,
        principal_id=user.id,
        principal_type=PrincipalType.USER,
        role=UserRole(role),
        permissions=sorted(ROLE_PERMISSIONS[role]),
        roles=[role],
    )


async def get_agent_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> AuthContext:
    runtime = get_runtime(request)
    key = request.headers.get("X-Agent-Key")
    if not key and credentials and credentials.credentials.startswith("ash_"):
        key = credentials.credentials
    if not key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing agent key")
    prefix = parse_agent_key(key)
    if prefix is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid agent key")
    async with runtime.database.session() as session:
        result = await session.execute(
            select(AgentKey, Agent)
            .join(Agent, Agent.id == AgentKey.agent_id)
            .where(
                AgentKey.key_prefix == prefix,
                AgentKey.active.is_(True),
                Agent.tenant_id == AgentKey.tenant_id,
            )
        )
        row = result.first()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid agent key")
    agent_key, agent = row
    if not verify_api_key(runtime.settings, key, agent_key.key_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid agent key")
    if agent.status != "Active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Agent is disabled")
    return AuthContext(
        tenant_id=agent.tenant_id,
        principal_id=agent.id,
        principal_type=PrincipalType.AGENT,
        agent_id=agent.id,
        permissions=list(agent.permissions),
        roles=["agent"],
        scopes=dict(agent.scopes),
    )


def require_dashboard(permission: str) -> Callable:
    async def dependency(auth: AuthContext = Depends(get_dashboard_auth)) -> AuthContext:
        if permission not in auth.permissions:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permission")
        return auth

    return dependency


def require_agent(auth: AuthContext = Depends(get_agent_auth)) -> AuthContext:
    return auth
