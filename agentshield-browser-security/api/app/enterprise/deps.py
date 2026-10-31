"""FastAPI dependencies for enterprise authentication and authorization.

Provides:
- get_current_principal: resolves a JWT bearer token or API key to a Principal
- require_permission: dependency factory that checks a permission
- get_db: database session dependency
"""

from typing import Optional, Callable
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.db.base import get_db_session, Session as DBSession
from app.enterprise.auth import (
    decode_access_token,
    verify_api_key,
    verify_agent_credentials,
    authenticate_user,
)
from app.enterprise.rbac import (
    Principal,
    principal_from_membership,
    principal_from_agent,
    role_has_permission,
    get_role_permissions,
)
from app.db.models import User, OrganizationUser, Agent

security = HTTPBearer(auto_error=False)


def get_db() -> Optional[DBSession]:
    """Return a database session, or None when the database is not initialized.

    When DATABASE_URL is not configured (legacy/dev mode), callers must handle
    a None session and avoid tenant-scoped DB queries.
    """
    try:
        db = get_db_session()
    except RuntimeError:
        yield None
        return
    try:
        yield db
    finally:
        db.close()


async def get_current_principal(
    request: Request,
    db: Session = Depends(get_db),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Principal:
    """Resolve the authenticated principal from a JWT token or API key.

    Authentication methods (in order of preference):
    1. Bearer JWT token (user or agent login)
    2. Bearer API key (agent or user API access)
    3. X-Agent-ID header (legacy, development-only)
    """
    result = _resolve_principal_from_credentials(request, db, credentials)
    if result is not None:
        return result

    # Legacy: X-Agent-ID header (development-only, no org binding)
    agent_id = request.headers.get("X-Agent-ID")
    if agent_id:
        agent = (
            db.query(Agent)
            .filter(Agent.agent_id == agent_id, Agent.status == "active")
            .first()
        )
        if agent:
            return principal_from_agent(
                agent_id=agent.agent_id,
                organization_id=agent.organization_id,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_AGENT_ID", "message": "unknown agent"},
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "AUTHENTICATION_REQUIRED", "message": "no credentials provided"},
    )


async def get_current_principal_optional(
    request: Request,
    db: Session = Depends(get_db),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[Principal]:
    """Resolve the authenticated principal if enterprise credentials are present.

    Returns None when no JWT token or API key is provided. This lets browser
    routes operate in legacy mode (X-Agent-ID only) when enterprise auth is not
    configured, while still supporting org-scoped access when JWT/API-key auth
    is used.
    """
    return _resolve_principal_from_credentials(request, db, credentials)


def _resolve_principal_from_credentials(
    request: Request,
    db: Session,
    credentials: Optional[HTTPAuthorizationCredentials],
) -> Optional[Principal]:
    """Shared principal resolution used by both required and optional paths."""
    token = credentials.credentials if credentials else None
    if not token:
        return None

    # If simple token auth was already validated by middleware, skip further processing
    if getattr(request.state, "simple_auth_validated", False):
        return None

    # Try JWT first
    payload = decode_access_token(token)
    if payload:
        sub = payload.get("sub")
        org_id = payload.get("org")
        roles = payload.get("roles", [])
        if not sub or not org_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "INVALID_TOKEN", "message": "token missing claims"},
            )
        permissions = set()
        for role in roles:
            permissions.update(get_role_permissions(role))
        return Principal(
            user_id=sub if not sub.startswith("agent-") else None,
            agent_id=sub if sub.startswith("agent-") else None,
            organization_id=org_id,
            role=roles[0] if roles else "viewer",
            permissions=permissions,
        )

    # Try API key (requires a database session)
    if db is not None:
        api_key = verify_api_key(db, token)
        if api_key:
            return Principal(
                user_id=api_key.user_id,
                organization_id=api_key.organization_id,
                role="viewer",
                permissions={"session:read", "audit:read", "org:read"},
            )

    return None


def require_permission(permission: str) -> Callable:
    """Dependency factory: require the principal to have a permission."""

    def checker(principal: Principal = Depends(get_current_principal)) -> Principal:
        principal.require_permission(permission)
        return principal

    return checker


def require_organization_access() -> Callable:
    """Dependency: require the principal's org to match the org_id path param.

    Reads ``organization_id`` from the request path parameters so the org scope
    is always derived from the URL, never trusted from the client body.
    """

    def checker(
        request: Request,
        principal: Principal = Depends(get_current_principal),
    ) -> Principal:
        org_id = request.path_params.get("org_id")
        if not org_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "MISSING_ORGANIZATION",
                    "message": "organization_id is required",
                },
            )
        if principal.organization_id != org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "CROSS_TENANT_ACCESS",
                    "message": "access to another organization is not permitted",
                },
            )
        return principal

    return checker
