"""Enterprise API routes for AgentShield control plane.

Endpoint groups:
- /v1/auth — login, logout, register, token refresh
- /v1/organizations — organization CRUD and membership
- /v1/users — user management (scoped to org)
- /v1/agents — agent registration, credentials, revocation
- /v1/policies — organization and agent policies, versions
- /v1/audit — persistent audit events
- /v1/security — security incidents

Existing /v1/browser routes are preserved and extended with organization context.
"""

from typing import Optional
from datetime import datetime, timezone, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.enterprise.deps import (
    get_current_principal,
    require_permission,
    require_organization_access,
    get_db,
    Principal,
)
from app.enterprise.auth import (
    authenticate_user,
    create_access_token,
    decode_access_token,
    create_user,
    create_organization,
    get_user_organizations,
    create_agent,
    verify_agent_credentials,
    create_api_key,
    verify_api_key,
    hash_password,
)
from app.db.models import (
    User,
    Organization,
    OrganizationUser,
    Agent,
    APIKey,
    BrowserSession,
    Policy,
    PolicyVersion,
    AuditEvent,
    SecurityIncident,
    Deployment,
    Capability,
    AgentCapability,
    ApprovalRequest,
)

router = APIRouter(prefix="/v1", tags=["enterprise"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    organization_id: str
    organization_name: str
    role: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    organization_name: str
    organization_slug: str


class RegisterResponse(BaseModel):
    user_id: UUID
    organization_id: UUID
    organization_slug: str


class OrganizationOut(BaseModel):
    id: UUID
    name: str
    slug: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class MembershipOut(BaseModel):
    id: UUID
    user_id: UUID
    organization_id: UUID
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class UserOut(BaseModel):
    id: UUID
    email: str
    full_name: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class AgentOut(BaseModel):
    id: UUID
    agent_id: str
    name: str
    status: str
    created_at: datetime
    last_activity_at: Optional[datetime]
    permissions: Optional[list[str]] = None
    scopes: Optional[dict] = None

    class Config:
        from_attributes = True


class AgentCreateRequest(BaseModel):
    name: str


class AgentCredentialResponse(BaseModel):
    agent_id: str
    name: str
    secret: str  # returned only once


class PolicyOut(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    description: Optional[str]
    version: int
    is_active: bool
    is_default: bool
    allowed_domains: list[str]
    blocked_domains: list[str]
    default_domain_policy: str
    allowed_ports: list[str]
    allow_private_networks: bool
    agent_id: Optional[UUID]
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    allowed_domains: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    default_domain_policy: str = Field(default="deny")
    allowed_ports: list[str] = Field(default_factory=list)
    allow_private_networks: bool = False
    agent_id: Optional[str] = None
    is_default: bool = False


class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    allowed_domains: Optional[list[str]] = None
    blocked_domains: Optional[list[str]] = None
    default_domain_policy: Optional[str] = None
    allowed_ports: Optional[list[str]] = None
    allow_private_networks: Optional[bool] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None


class AuditEventOut(BaseModel):
    id: UUID
    event_type: str
    event_category: Optional[str]
    actor: Optional[str]
    session_id: Optional[str]
    agent_id: Optional[str]
    target: Optional[str]
    decision: Optional[str]
    reason: Optional[str]
    severity: str
    request_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class IncidentOut(BaseModel):
    id: UUID
    title: str
    description: Optional[str]
    severity: str
    status: str
    event_type: Optional[str]
    source_agent: Optional[str]
    destination: Optional[str]
    enforcement_decision: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyVersionOut(BaseModel):
    id: UUID
    policy_id: UUID
    version: int
    allowed_domains: list[str]
    blocked_domains: list[str]
    default_domain_policy: str
    allowed_ports: list[str]
    allow_private_networks: bool
    change_reason: Optional[str]
    changed_by_user_id: Optional[UUID]
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyValidateRequest(BaseModel):
    allowed_domains: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    default_domain_policy: str = Field(default="deny")
    allowed_ports: list[str] = Field(default_factory=list)
    allow_private_networks: bool = False


class PolicyActivateRequest(BaseModel):
    is_active: bool


class DeploymentOut(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    deployment_id: str
    status: str
    control_plane_url: Optional[str]
    enrolled_at: Optional[datetime]
    last_heartbeat_at: Optional[datetime]
    is_connected: bool
    created_at: datetime

    class Config:
        from_attributes = True


class DashboardOut(BaseModel):
    registered_agents: int
    active_sessions: int
    total_requests: int
    allowed_requests: int
    blocked_requests: int
    policy_violations: int
    security_incidents: int
    service_health: dict

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@router.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, payload.email, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_CREDENTIALS", "message": "invalid email or password"},
        )

    memberships = get_user_organizations(db, user.id)
    if not memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NO_ORGANIZATION", "message": "user is not a member of any organization"},
        )

    # Use the first (primary) organization
    primary = memberships[0]
    org_id = str(primary.organization_id)
    org = db.query(Organization).filter(Organization.id == primary.organization_id).first()

    token = create_access_token(
        subject=str(user.id),
        organization_id=org_id,
        roles=[primary.role],
    )
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    return LoginResponse(
        access_token=token,
        organization_id=org_id,
        organization_name=org.name if org else "",
        role=primary.role,
    )


@router.post("/auth/logout")
def logout(principal: Principal = Depends(get_current_principal)):
    # JWT is stateless; client discards the token. Record audit event.
    return {"message": "logged out"}


@router.post("/auth/register", response_model=RegisterResponse)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    try:
        user = create_user(db, email=payload.email, password=payload.password, full_name=payload.full_name)
        org = create_organization(
            db, name=payload.organization_name, slug=payload.organization_slug, owner_user_id=user.id
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"code": "REGISTRATION_FAILED", "message": str(exc)})
    return RegisterResponse(user_id=user.id, organization_id=org.id, organization_slug=org.slug)


@router.get("/auth/me")
def get_me(principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    user = None
    if principal.user_id:
        user = db.query(User).filter(User.id == principal.user_id).first()
    return {
        "user_id": principal.user_id,
        "agent_id": principal.agent_id,
        "organization_id": principal.organization_id,
        "role": principal.role,
        "email": user.email if user else None,
        "full_name": user.full_name if user else None,
    }


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------


@router.get("/organizations", response_model=list[OrganizationOut])
def list_organizations(principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    memberships = get_user_organizations(db, principal.user_id) if principal.user_id else []
    org_ids = [m.organization_id for m in memberships]
    orgs = db.query(Organization).filter(Organization.id.in_(org_ids)).all() if org_ids else []
    return orgs


@router.get("/organizations/{org_id}", response_model=OrganizationOut)
def get_organization(
    org_id: str,
    principal: Principal = Depends(require_organization_access()),
    db: Session = Depends(get_db),
):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "organization not found"})
    return org


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@router.get("/organizations/{org_id}/users", response_model=list[UserOut])
def list_org_users(
    org_id: str,
    principal: Principal = Depends(require_organization_access()),
    db: Session = Depends(get_db),
):
    memberships = (
        db.query(OrganizationUser)
        .filter(OrganizationUser.organization_id == org_id, OrganizationUser.is_active == True)  # noqa: E712
        .all()
    )
    user_ids = [m.user_id for m in memberships]
    users = db.query(User).filter(User.id.in_(user_ids)).all() if user_ids else []
    return users


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


@router.get("/organizations/{org_id}/agents", response_model=list[AgentOut])
def list_agents(
    org_id: str,
    principal: Principal = Depends(require_organization_access()),
    db: Session = Depends(get_db),
):
    agents = db.query(Agent).filter(Agent.organization_id == org_id).all()
    return agents


@router.post("/organizations/{org_id}/agents", response_model=AgentCredentialResponse, status_code=201)
def create_org_agent(
    org_id: str,
    payload: AgentCreateRequest,
    principal: Principal = Depends(require_permission("agent:write")),
    db: Session = Depends(get_db),
):
    agent = create_agent(db, organization_id=org_id, name=payload.name, created_by_user_id=principal.user_id)
    secret = getattr(agent, "_raw_secret", None)
    if not secret:
        raise HTTPException(status_code=500, detail={"code": "CREDENTIAL_ERROR", "message": "failed to issue agent secret"})

    # Ensure capabilities exist for the organization, then create default
    # (disabled) AgentCapability records for the new agent.
    org_caps = (
        db.query(Capability)
        .filter(Capability.organization_id == org_id, Capability.is_active == True)  # noqa: E712
        .all()
    )
    if not org_caps:
        _seed_default_capabilities(db, org_id)
        org_caps = (
            db.query(Capability)
            .filter(Capability.organization_id == org_id, Capability.is_active == True)  # noqa: E712
            .all()
        )
    for cap in org_caps:
        db.add(
            AgentCapability(
                organization_id=org_id,
                agent_id=agent.id,
                capability_id=cap.id,
                enabled=False,
                allowed_tools=list(cap.tools or []),
                resource_scope=[],
                allowed_domains=[],
                require_approval=False,
                payment_budget=None,
            )
        )
    db.commit()

    return AgentCredentialResponse(agent_id=agent.agent_id, name=agent.name, secret=secret)


@router.post("/agents/{agent_id}/revoke")
def revoke_agent(
    agent_id: str,
    principal: Principal = Depends(require_permission("agent:delete")),
    db: Session = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "agent not found"})
    principal.require_permission("agent:delete")
    if principal.organization_id != agent.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot revoke agent from another organization"},
        )
    agent.status = "revoked"
    db.commit()
    return {"message": "agent revoked"}


# ---------------------------------------------------------------------------
# Capability permission schemas
# ---------------------------------------------------------------------------


class CapabilityOut(BaseModel):
    id: UUID
    organization_id: UUID
    key: str
    name: str
    description: Optional[str]
    tools: list[str]
    is_system: bool
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class AgentCapabilityOut(BaseModel):
    id: UUID
    organization_id: UUID
    agent_id: UUID
    capability_id: UUID
    capability_key: Optional[str]
    capability_name: Optional[str]
    enabled: bool
    allowed_tools: list[str]
    resource_scope: list[str]
    allowed_domains: list[str]
    require_approval: bool
    payment_budget: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AgentCapabilityUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    allowed_tools: Optional[list[str]] = None
    resource_scope: Optional[list[str]] = None
    allowed_domains: Optional[list[str]] = None
    require_approval: Optional[bool] = None
    payment_budget: Optional[int] = None


class AgentPermissionsPatch(BaseModel):
    permissions: Optional[list[str]] = None
    scopes: Optional[dict] = None


class ApprovalRequestOut(BaseModel):
    id: UUID
    organization_id: UUID
    agent_id: UUID
    capability_id: UUID
    tool_name: str
    tool_args: dict
    target: Optional[str]
    status: str
    requested_by: Optional[str]
    approved_by: Optional[str]
    requested_at: datetime
    approved_at: Optional[datetime]
    reason: Optional[str]

    class Config:
        from_attributes = True


class ApprovalActionRequest(BaseModel):
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Agent capability endpoints
# ---------------------------------------------------------------------------


@router.patch("/agents/{agent_id}", response_model=AgentOut)
def update_agent_capabilities(
    agent_id: str,
    payload: AgentPermissionsPatch,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """Update an agent's permissions and scopes.

    Permissions are stored as a JSON list on the Agent model. Scopes are
    stored as a JSON object. Both fields are organization-scoped.
    """
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "agent not found"})
    if principal.organization_id != agent.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot modify agent from another organization"},
        )

    if payload.permissions is not None:
        agent.permissions = payload.permissions
    if payload.scopes is not None:
        agent.scopes = payload.scopes

    db.commit()
    db.refresh(agent)
    return agent


@router.get(
    "/organizations/{org_id}/capabilities",
    response_model=list[CapabilityOut],
)
def list_capabilities(
    org_id: str,
    principal: Principal = Depends(require_organization_access()),
    db: Session = Depends(get_db),
):
    """List all capabilities defined for an organization. Seeds defaults if none exist."""
    if principal.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot list capabilities for another organization"},
        )
    capabilities = (
        db.query(Capability)
        .filter(Capability.organization_id == org_id, Capability.is_active == True)  # noqa: E712
        .all()
    )
    if not capabilities:
        _seed_default_capabilities(db, org_id)
        capabilities = (
            db.query(Capability)
            .filter(Capability.organization_id == org_id, Capability.is_active == True)  # noqa: E712
            .all()
        )
    return capabilities


def _seed_default_capabilities(db: Session, org_id: str) -> None:
    """Seed default capability definitions for an organization."""
    defaults = [
        {
            "key": "documents",
            "name": "Documents",
            "description": "Read and analyze agent-accessible documents",
            "tools": ["documents.read"],
        },
        {
            "key": "local_files",
            "name": "Local files",
            "description": "Scoped access to workspace files and folders",
            "tools": ["local_files.read", "files.delete"],
        },
        {
            "key": "system_files",
            "name": "System files",
            "description": "Protected operating system resources",
            "tools": ["system_files.read"],
        },
        {
            "key": "environment",
            "name": "Environment & secrets",
            "description": "Controlled access to environment variables",
            "tools": ["environment.read"],
        },
        {
            "key": "terminal",
            "name": "Terminal",
            "description": "Sandboxed command execution",
            "tools": ["terminal.run"],
        },
        {
            "key": "browser",
            "name": "Browser",
            "description": "Search, browse, and interact with the web",
            "tools": ["browser.read"],
        },
        {
            "key": "email",
            "name": "Email",
            "description": "Read, draft, and send messages",
            "tools": ["email.send"],
        },
        {
            "key": "dlp",
            "name": "Data loss prevention",
            "description": "Inspect, redact, and safely export data",
            "tools": ["dlp.export"],
        },
        {
            "key": "downloads",
            "name": "Downloads",
            "description": "Inspect and quarantine downloaded files",
            "tools": ["downloads.write"],
        },
        {
            "key": "payments",
            "name": "Payments",
            "description": "Budget-controlled sandbox transactions",
            "tools": ["payments.execute"],
        },
        {
            "key": "external_api",
            "name": "External APIs",
            "description": "Authorized API and MCP connections",
            "tools": ["external_api.call", "mcp.call"],
        },
    ]
    for d in defaults:
        cap = Capability(
            organization_id=org_id,
            key=d["key"],
            name=d["name"],
            description=d["description"],
            tools=d["tools"],
            is_system=True,
            is_active=True,
        )
        db.add(cap)
    db.commit()


@router.get(
    "/agents/{agent_id}/capabilities",
    response_model=list[AgentCapabilityOut],
)
def get_agent_capabilities(
    agent_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """Retrieve an agent's capability permissions."""
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "agent not found"})
    if principal.organization_id != agent.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot access agent capabilities from another organization"},
        )

    caps = (
        db.query(AgentCapability, Capability)
        .join(Capability, AgentCapability.capability_id == Capability.id)
        .filter(AgentCapability.agent_id == agent.id)
        .all()
    )
    results = []
    for ac, cap in caps:
        results.append(
            AgentCapabilityOut(
                id=ac.id,
                organization_id=ac.organization_id,
                agent_id=ac.agent_id,
                capability_id=ac.capability_id,
                capability_key=cap.key,
                capability_name=cap.name,
                enabled=ac.enabled,
                allowed_tools=ac.allowed_tools or [],
                resource_scope=ac.resource_scope or [],
                allowed_domains=ac.allowed_domains or [],
                require_approval=ac.require_approval,
                payment_budget=ac.payment_budget,
                created_at=ac.created_at,
                updated_at=ac.updated_at,
            )
        )
    return results


@router.patch(
    "/agents/{agent_id}/capabilities/{capability_key}",
    response_model=AgentCapabilityOut,
)
def update_agent_capability(
    agent_id: str,
    capability_key: str,
    payload: AgentCapabilityUpdateRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """Update an agent's capability configuration (enabled state, tools, scope, domains, approval)."""
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "agent not found"})
    if principal.organization_id != agent.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot modify agent capabilities from another organization"},
        )

    capability = (
        db.query(Capability)
        .filter(Capability.key == capability_key, Capability.organization_id == agent.organization_id)
        .first()
    )
    if not capability:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "capability not found"})

    agent_cap = (
        db.query(AgentCapability)
        .filter(AgentCapability.agent_id == agent.id, AgentCapability.capability_id == capability.id)
        .first()
    )
    if not agent_cap:
        agent_cap = AgentCapability(
            organization_id=agent.organization_id,
            agent_id=agent.id,
            capability_id=capability.id,
            enabled=False,
            allowed_tools=list(capability.tools or []),
            resource_scope=[],
            allowed_domains=[],
            require_approval=False,
            payment_budget=None,
        )
        db.add(agent_cap)
        db.flush()

    if payload.enabled is not None:
        agent_cap.enabled = payload.enabled
    if payload.allowed_tools is not None:
        agent_cap.allowed_tools = payload.allowed_tools
    if payload.resource_scope is not None:
        agent_cap.resource_scope = payload.resource_scope
    if payload.allowed_domains is not None:
        agent_cap.allowed_domains = payload.allowed_domains
    if payload.require_approval is not None:
        agent_cap.require_approval = payload.require_approval
    if payload.payment_budget is not None:
        agent_cap.payment_budget = payload.payment_budget

    # Keep agent.permissions in sync with enabled capabilities
    enabled_caps = (
        db.query(AgentCapability)
        .filter(AgentCapability.agent_id == agent.id, AgentCapability.enabled == True)  # noqa: E712
        .all()
    )
    agent.permissions = sorted(
        set(
            p
            for ac in enabled_caps
            for p in (ac.allowed_tools or [])
        )
    )

    db.commit()
    db.refresh(agent_cap)
    return AgentCapabilityOut(
        id=agent_cap.id,
        organization_id=agent_cap.organization_id,
        agent_id=agent_cap.agent_id,
        capability_id=agent_cap.capability_id,
        capability_key=capability.key,
        capability_name=capability.name,
        enabled=agent_cap.enabled,
        allowed_tools=agent_cap.allowed_tools or [],
        resource_scope=agent_cap.resource_scope or [],
        allowed_domains=agent_cap.allowed_domains or [],
        require_approval=agent_cap.require_approval,
        payment_budget=agent_cap.payment_budget,
        created_at=agent_cap.created_at,
        updated_at=agent_cap.updated_at,
    )


# ---------------------------------------------------------------------------
# Approval queue endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/organizations/{org_id}/approvals",
    response_model=list[ApprovalRequestOut],
)
def list_approval_requests(
    org_id: str,
    principal: Principal = Depends(require_organization_access()),
    db: Session = Depends(get_db),
    status_filter: Optional[str] = Query(default="pending", alias="status"),
):
    """List approval requests for an organization."""
    if principal.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot list approvals for another organization"},
        )
    query = db.query(ApprovalRequest).filter(ApprovalRequest.organization_id == org_id)
    if status_filter:
        query = query.filter(ApprovalRequest.status == status_filter)
    return query.order_by(ApprovalRequest.requested_at.desc()).all()


@router.post(
    "/approvals/{approval_id}/approve",
    response_model=ApprovalRequestOut,
)
def approve_request(
    approval_id: str,
    payload: ApprovalActionRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """Approve a pending approval request."""
    approval = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_id).first()
    if not approval:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "approval request not found"})
    if principal.organization_id != approval.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot approve request from another organization"},
        )
    if approval.status != "pending":
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_STATUS", "message": f"approval request is already {approval.status}"},
        )
    approval.status = "approved"
    approval.approved_by = str(principal.user_id or principal.agent_id or "system")
    approval.approved_at = datetime.now(timezone.utc)
    approval.reason = payload.reason
    db.commit()
    db.refresh(approval)
    return approval


@router.post(
    "/approvals/{approval_id}/reject",
    response_model=ApprovalRequestOut,
)
def reject_request(
    approval_id: str,
    payload: ApprovalActionRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """Reject a pending approval request."""
    approval = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_id).first()
    if not approval:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "approval request not found"})
    if principal.organization_id != approval.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot reject request from another organization"},
        )
    if approval.status != "pending":
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_STATUS", "message": f"approval request is already {approval.status}"},
        )
    approval.status = "rejected"
    approval.approved_by = str(principal.user_id or principal.agent_id or "system")
    approval.approved_at = datetime.now(timezone.utc)
    approval.reason = payload.reason
    db.commit()
    db.refresh(approval)
    return approval


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.get("/organizations/{org_id}/policies", response_model=list[PolicyOut])
def list_policies(
    org_id: str,
    principal: Principal = Depends(require_organization_access()),
    db: Session = Depends(get_db),
):
    policies = db.query(Policy).filter(Policy.organization_id == org_id).all()
    return policies


@router.post("/organizations/{org_id}/policies", response_model=PolicyOut, status_code=201)
def create_policy(
    org_id: str,
    payload: PolicyCreateRequest,
    principal: Principal = Depends(require_permission("policy:write")),
    db: Session = Depends(get_db),
):
    principal.require_permission("policy:write")
    if principal.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot create policy for another organization"},
        )

    policy = Policy(
        organization_id=org_id,
        name=payload.name,
        description=payload.description,
        allowed_domains=payload.allowed_domains,
        blocked_domains=payload.blocked_domains,
        default_domain_policy=payload.default_domain_policy,
        allowed_ports=payload.allowed_ports,
        allow_private_networks=payload.allow_private_networks,
        agent_id=payload.agent_id,
        is_active=True,
        is_default=payload.is_default,
        created_by_user_id=principal.user_id,
    )
    db.add(policy)
    db.flush()

    version = PolicyVersion(
        policy_id=policy.id,
        version=1,
        allowed_domains=payload.allowed_domains,
        blocked_domains=payload.blocked_domains,
        default_domain_policy=payload.default_domain_policy,
        allowed_ports=payload.allowed_ports,
        allow_private_networks=payload.allow_private_networks,
        change_reason="initial version",
        changed_by_user_id=principal.user_id,
    )
    db.add(version)
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/policies/{policy_id}", response_model=PolicyOut)
def get_policy(
    policy_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "policy not found"})
    principal.require_permission("policy:read")
    if principal.organization_id != policy.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot access policy from another organization"},
        )
    return policy


@router.patch("/policies/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: str,
    payload: PolicyUpdateRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "policy not found"})
    principal.require_permission("policy:write")
    if principal.organization_id != policy.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot modify policy from another organization"},
        )

    # Create a new version before modifying
    new_version = policy.version + 1
    version = PolicyVersion(
        policy_id=policy.id,
        version=new_version,
        allowed_domains=payload.allowed_domains if payload.allowed_domains is not None else policy.allowed_domains,
        blocked_domains=payload.blocked_domains if payload.blocked_domains is not None else policy.blocked_domains,
        default_domain_policy=payload.default_domain_policy if payload.default_domain_policy is not None else policy.default_domain_policy,
        allowed_ports=payload.allowed_ports if payload.allowed_ports is not None else policy.allowed_ports,
        allow_private_networks=payload.allow_private_networks if payload.allow_private_networks is not None else policy.allow_private_networks,
        change_reason="policy updated via API",
        changed_by_user_id=principal.user_id,
    )
    db.add(version)

    if payload.name is not None:
        policy.name = payload.name
    if payload.description is not None:
        policy.description = payload.description
    if payload.allowed_domains is not None:
        policy.allowed_domains = payload.allowed_domains
    if payload.blocked_domains is not None:
        policy.blocked_domains = payload.blocked_domains
    if payload.default_domain_policy is not None:
        policy.default_domain_policy = payload.default_domain_policy
    if payload.allowed_ports is not None:
        policy.allowed_ports = payload.allowed_ports
    if payload.allow_private_networks is not None:
        policy.allow_private_networks = payload.allow_private_networks
    if payload.is_active is not None:
        policy.is_active = payload.is_active
    if payload.is_default is not None:
        policy.is_default = payload.is_default
    policy.version = new_version

    db.commit()
    db.refresh(policy)
    return policy


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


@router.get("/organizations/{org_id}/audit", response_model=list[AuditEventOut])
def list_audit_events(
    org_id: str,
    principal: Principal = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    principal.require_permission("audit:read")
    if principal.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "cannot access audit events from another organization"},
        )
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.organization_id == org_id)
        .order_by(AuditEvent.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return events


# ---------------------------------------------------------------------------
# Security incidents
# ---------------------------------------------------------------------------


@router.get("/organizations/{org_id}/incidents", response_model=list[IncidentOut])
def list_incidents(
    org_id: str,
    principal: Principal = Depends(require_permission("incident:read")),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    incidents = (
        db.query(SecurityIncident)
        .filter(SecurityIncident.organization_id == org_id)
        .order_by(SecurityIncident.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return incidents


# ---------------------------------------------------------------------------
# Policy version history, rollback, activate/deactivate
# ---------------------------------------------------------------------------


@router.get("/organizations/{org_id}/policies/{policy_id}/versions", response_model=list[PolicyVersionOut])
def list_policy_versions(
    org_id: str,
    policy_id: str,
    principal: Principal = Depends(require_organization_access()),
    db: Session = Depends(get_db),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "policy not found"})
    if str(policy.organization_id) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "policy belongs to another organization"},
        )
    versions = (
        db.query(PolicyVersion)
        .filter(PolicyVersion.policy_id == policy_id)
        .order_by(PolicyVersion.version.desc())
        .all()
    )
    return versions


@router.post("/organizations/{org_id}/policies/{policy_id}/rollback", response_model=PolicyOut)
def rollback_policy(
    org_id: str,
    policy_id: str,
    payload: PolicyVersionOut,
    principal: Principal = Depends(require_permission("policy:write")),
    db: Session = Depends(get_db),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "policy not found"})
    principal.require_permission("policy:write")
    if str(policy.organization_id) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "policy belongs to another organization"},
        )

    target = (
        db.query(PolicyVersion)
        .filter(PolicyVersion.policy_id == policy_id, PolicyVersion.version == payload.version)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail={"code": "VERSION_NOT_FOUND", "message": "policy version not found"})

    new_version = policy.version + 1
    version = PolicyVersion(
        policy_id=policy.id,
        version=new_version,
        allowed_domains=target.allowed_domains,
        blocked_domains=target.blocked_domains,
        default_domain_policy=target.default_domain_policy,
        allowed_ports=target.allowed_ports,
        allow_private_networks=target.allow_private_networks,
        change_reason=f"rollback to version {payload.version}",
        changed_by_user_id=principal.user_id,
    )
    db.add(version)

    policy.allowed_domains = target.allowed_domains
    policy.blocked_domains = target.blocked_domains
    policy.default_domain_policy = target.default_domain_policy
    policy.allowed_ports = target.allowed_ports
    policy.allow_private_networks = target.allow_private_networks
    policy.version = new_version
    db.commit()
    db.refresh(policy)
    return policy


@router.post("/organizations/{org_id}/policies/{policy_id}/activate", response_model=PolicyOut)
def activate_policy(
    org_id: str,
    policy_id: str,
    principal: Principal = Depends(require_permission("policy:write")),
    db: Session = Depends(get_db),
):
    return _set_policy_active(org_id, policy_id, True, principal, db)


@router.post("/organizations/{org_id}/policies/{policy_id}/deactivate", response_model=PolicyOut)
def deactivate_policy(
    org_id: str,
    policy_id: str,
    principal: Principal = Depends(require_permission("policy:write")),
    db: Session = Depends(get_db),
):
    return _set_policy_active(org_id, policy_id, False, principal, db)


def _set_policy_active(org_id, policy_id, is_active, principal, db):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "policy not found"})
    principal.require_permission("policy:write")
    if str(policy.organization_id) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "policy belongs to another organization"},
        )
    policy.is_active = is_active
    db.commit()
    db.refresh(policy)
    return policy


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------


@router.get("/organizations/{org_id}/deployments", response_model=list[DeploymentOut])
def list_deployments(
    org_id: str,
    principal: Principal = Depends(require_organization_access()),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    deployments = (
        db.query(Deployment)
        .filter(Deployment.organization_id == org_id)
        .order_by(Deployment.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return deployments


@router.post("/organizations/{org_id}/deployments", response_model=DeploymentOut, status_code=201)
def create_deployment(
    org_id: str,
    payload: dict,
    principal: Principal = Depends(require_permission("deployment:write")),
    db: Session = Depends(get_db),
):
    principal.require_permission("deployment:write")
    if str(principal.organization_id) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CROSS_TENANT_ACCESS", "message": "deployment belongs to another organization"},
        )
    import uuid

    deployment_id = f"dep-{uuid.uuid4().hex[:12]}"
    deployment = Deployment(
        organization_id=org_id,
        name=payload.get("name", deployment_id),
        deployment_id=deployment_id,
        status="pending",
        control_plane_url=payload.get("control_plane_url"),
    )
    db.add(deployment)
    db.commit()
    db.refresh(deployment)
    return deployment


# ---------------------------------------------------------------------------
# Dashboard metrics
# ---------------------------------------------------------------------------


@router.get("/organizations/{org_id}/dashboard", response_model=DashboardOut)
def get_dashboard(
    org_id: str,
    principal: Principal = Depends(require_organization_access()),
    db: Session = Depends(get_db),
):
    agents = db.query(Agent).filter(Agent.organization_id == org_id).all()
    registered_agents = len(agents)
    active_sessions = (
        db.query(BrowserSession)
        .filter(BrowserSession.organization_id == org_id, BrowserSession.is_active == True)  # noqa: E712
        .count()
    )
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.organization_id == org_id)
        .all()
    )
    total_requests = len(events)
    allowed_requests = len([e for e in events if e.decision == "allow"])
    blocked_requests = len([e for e in events if e.decision == "deny"])
    policy_violations = len([e for e in events if e.decision == "deny"])
    security_incidents = (
        db.query(SecurityIncident)
        .filter(SecurityIncident.organization_id == org_id)
        .count()
    )
    return DashboardOut(
        registered_agents=registered_agents,
        active_sessions=active_sessions,
        total_requests=total_requests,
        allowed_requests=allowed_requests,
        blocked_requests=blocked_requests,
        policy_violations=policy_violations,
        security_incidents=security_incidents,
        service_health={
            "api": "ok",
            "worker": "ok",
            "policy_engine": "ok",
        },
    )
