from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from .api_common import agent_dict
from .auth import ROLE_PERMISSIONS, get_dashboard_auth
from .contracts import AuthContext, LoginRequest, LoginResponse
from .db import Agent, User
from .runtime import Runtime
from .security import create_user_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request) -> LoginResponse:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        users = (
            await session.scalars(
                select(User).where(User.email == payload.email.strip().lower())
            )
        ).all()
        active = [user for user in users if user.active]
        if len(active) != 1 or not verify_password(payload.password, active[0].password_hash):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
        user = active[0]
        token, expires = create_user_token(
            runtime.settings,
            user_id=user.id,
            tenant_id=user.tenant_id,
            role=user.role,
            email=user.email,
        )
        await runtime.audit.append(
            session,
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="auth.login",
            decision="ALLOW",
            risk_level="low",
            details={"summary": "Dashboard sign-in", "email": user.email},
        )
        await session.commit()
    return LoginResponse(
        access_token=token,
        expires_in=expires,
        user={
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "tenant_id": user.tenant_id,
            "permissions": sorted(ROLE_PERMISSIONS.get(user.role, ROLE_PERMISSIONS["viewer"])),
        },
    )


@router.get("/me")
async def me(
    auth: AuthContext = Depends(get_dashboard_auth), request: Request = None
) -> dict:
    runtime: Runtime = request.app.state.runtime
    async with runtime.database.session() as session:
        user = await session.get(User, auth.principal_id)
        agents = (
            await session.scalars(
                select(Agent).where(Agent.tenant_id == auth.tenant_id).order_by(Agent.created_at)
            )
        ).all()
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "tenant_id": auth.tenant_id,
        "permissions": auth.permissions,
        "agents": [agent_dict(agent, index) for index, agent in enumerate(agents)],
    }


@router.post("/logout")
async def logout() -> dict:
    return {"ok": True}
