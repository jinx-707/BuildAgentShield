"""Enterprise database models for AgentShield."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy import JSON
from sqlalchemy.orm import relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    return str(uuid.uuid4())


class TimestampMixin:
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False, unique=True, index=True)
    slug = Column(String(255), nullable=False, unique=True, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    settings = Column(JSON, nullable=True)

    users = relationship("OrganizationUser", back_populates="organization")
    agents = relationship("Agent", back_populates="organization")
    sessions = relationship("BrowserSession", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    audit_events = relationship("AuditEvent", back_populates="organization")
    incidents = relationship("SecurityIncident", back_populates="organization")
    deployments = relationship("Deployment", back_populates="organization")
    api_keys = relationship("APIKey", back_populates="organization")


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), nullable=False, unique=True, index=True)
    email_verified = Column(Boolean, nullable=False, default=False)
    password_hash = Column(String(255), nullable=True)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    memberships = relationship("OrganizationUser", back_populates="user")
    api_keys = relationship("APIKey", back_populates="user")

    def __repr__(self):
        return f"<User id={self.id} email={self.email}>"


class OrganizationUser(Base, TimestampMixin):
    __tablename__ = "organization_users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role = Column(String(50), nullable=False, default="viewer")
    is_active = Column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_user"),
        Index("ix_org_user_role", "organization_id", "role"),
    )

    organization = relationship("Organization", back_populates="users")
    user = relationship("User", back_populates="memberships")


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(50), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    permissions = Column(JSON, nullable=False, default=list)
    is_system = Column(Boolean, nullable=False, default=False)

    __table_args__ = ()


class Permission(Base, TimestampMixin):
    __tablename__ = "permissions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False, unique=True, index=True)
    resource = Column(String(100), nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("resource", "action", name="uq_permission_resource_action"),
        Index("ix_permissions_resource_action", "resource", "action"),
    )


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    agent_id = Column(String(255), nullable=False, unique=True, index=True)
    status = Column(String(50), nullable=False, default="active")
    credentials_hash = Column(String(255), nullable=True)
    permissions = Column(JSON, nullable=False, default=list)
    scopes = Column(JSON, nullable=True)
    last_activity_at = Column(DateTime(timezone=True), nullable=True)
    created_by_user_id = Column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )

    organization = relationship("Organization", back_populates="agents")
    sessions = relationship("BrowserSession", back_populates="agent")
    creator = relationship("User")
    capabilities = relationship("AgentCapability", back_populates="agent", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_agents_org_status", "organization_id", "status"),
    )


class Capability(Base, TimestampMixin):
    """A named, organization-scoped capability (e.g. "terminal", "browser")."""

    __tablename__ = "capabilities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key = Column(String(100), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    tools = Column(JSON, nullable=False, default=list)
    is_system = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True)

    organization = relationship("Organization")
    agent_capabilities = relationship(
        "AgentCapability", back_populates="capability", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "key", name="uq_capability_org_key"
        ),
        Index("ix_capabilities_org_key", "organization_id", "key"),
    )


class AgentCapability(Base, TimestampMixin):
    """Agent-scoped capability configuration: enabled state, allowed tools, scope, domains, approval."""

    __tablename__ = "agent_capabilities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    capability_id = Column(
        String(36),
        ForeignKey("capabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    enabled = Column(Boolean, nullable=False, default=False)
    allowed_tools = Column(JSON, nullable=False, default=list)
    resource_scope = Column(JSON, nullable=False, default=list)
    allowed_domains = Column(JSON, nullable=False, default=list)
    require_approval = Column(Boolean, nullable=False, default=False)
    payment_budget = Column(Integer, nullable=True)

    organization = relationship("Organization")
    agent = relationship("Agent", back_populates="capabilities")
    capability = relationship("Capability", back_populates="agent_capabilities")

    __table_args__ = (
        UniqueConstraint(
            "agent_id", "capability_id", name="uq_agent_capability"
        ),
    )


class ApprovalRequest(Base, TimestampMixin):
    """Human approval request for a capability tool invocation."""

    __tablename__ = "approval_requests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    capability_id = Column(
        String(36),
        ForeignKey("capabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tool_name = Column(String(100), nullable=False, index=True)
    tool_args = Column(JSON, nullable=False, default=dict)
    target = Column(String(500), nullable=True)
    status = Column(String(20), nullable=False, default="pending", index=True)
    requested_by = Column(String(255), nullable=True)
    approved_by = Column(String(255), nullable=True)
    requested_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    reason = Column(Text, nullable=True)

    organization = relationship("Organization")
    agent = relationship("Agent")
    capability = relationship("Capability")


class APIKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False, index=True)
    key_prefix = Column(String(20), nullable=False, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="api_keys")
    user = relationship("User", back_populates="api_keys")

    __table_args__ = (Index("ix_api_keys_org_active", "organization_id", "is_active"),)


class BrowserSession(Base, TimestampMixin):
    __tablename__ = "browser_sessions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_token = Column(String(255), nullable=False, unique=True, index=True)
    status = Column(String(50), nullable=False, default="active")
    current_url = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_activity_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    organization = relationship("Organization", back_populates="sessions")
    agent = relationship("Agent", back_populates="sessions")

    __table_args__ = (
        Index("ix_browser_sessions_org_status", "organization_id", "status"),
        Index("ix_browser_sessions_agent", "agent_id"),
    )


class Policy(Base, TimestampMixin):
    __tablename__ = "policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    version = Column(Integer, nullable=False, default=1)
    is_active = Column(Boolean, nullable=False, default=False)
    is_default = Column(Boolean, nullable=False, default=False)
    allowed_domains = Column(JSON, nullable=False, default=list)
    blocked_domains = Column(JSON, nullable=False, default=list)
    default_domain_policy = Column(String(20), nullable=False, default="deny")
    allowed_ports = Column(JSON, nullable=False, default=list)
    allow_private_networks = Column(Boolean, nullable=False, default=False)
    agent_id = Column(
        String(36),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    created_by_user_id = Column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )

    organization = relationship("Organization", back_populates="policies")
    agent = relationship("Agent")

    __table_args__ = (
        Index("ix_policies_org_active", "organization_id", "is_active"),
        Index("ix_policies_agent", "agent_id"),
        Index("ix_policies_org_default", "organization_id", "is_default"),
    )


class PolicyVersion(Base, TimestampMixin):
    __tablename__ = "policy_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    policy_id = Column(
        String(36),
        ForeignKey("policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version = Column(Integer, nullable=False)
    allowed_domains = Column(JSON, nullable=False, default=list)
    blocked_domains = Column(JSON, nullable=False, default=list)
    default_domain_policy = Column(String(20), nullable=False, default="deny")
    allowed_ports = Column(JSON, nullable=False, default=list)
    allow_private_networks = Column(Boolean, nullable=False, default=False)
    change_reason = Column(Text, nullable=True)
    changed_by_user_id = Column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )

    policy = relationship("Policy")

    __table_args__ = (
        UniqueConstraint("policy_id", "version", name="uq_policy_version"),
        Index("ix_policy_versions_policy", "policy_id"),
    )


class AuditEvent(Base, TimestampMixin):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor = Column(String(255), nullable=True, index=True)
    actor_type = Column(String(50), nullable=True)
    event_type = Column(String(100), nullable=False, index=True)
    event_category = Column(String(50), nullable=True, index=True)
    session_id = Column(String(255), nullable=True, index=True)
    agent_id = Column(String(255), nullable=True, index=True)
    target = Column(Text, nullable=True)
    decision = Column(String(50), nullable=True, index=True)
    reason = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="info")
    request_id = Column(String(255), nullable=True, index=True)
    event_metadata = Column("metadata", JSON, nullable=False, default=dict)
    ip_address = Column(String(64), nullable=True)

    organization = relationship("Organization", back_populates="audit_events")

    __table_args__ = (
        Index("ix_audit_events_org_type", "organization_id", "event_type"),
        Index("ix_audit_events_org_time", "organization_id", "created_at"),
        Index("ix_audit_events_org_decision", "organization_id", "decision"),
    )


class SecurityIncident(Base, TimestampMixin):
    __tablename__ = "security_incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="medium")
    status = Column(String(50), nullable=False, default="open")
    event_type = Column(String(100), nullable=True, index=True)
    source_agent = Column(String(255), nullable=True, index=True)
    destination = Column(Text, nullable=True)
    enforcement_decision = Column(String(50), nullable=True)
    evidence = Column(JSON, nullable=False, default=dict)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by_user_id = Column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )

    organization = relationship("Organization", back_populates="incidents")

    __table_args__ = (
        Index("ix_incidents_org_status", "organization_id", "status"),
        Index("ix_incidents_org_severity", "organization_id", "severity"),
    )


class Deployment(Base, TimestampMixin):
    __tablename__ = "deployments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    deployment_id = Column(String(255), nullable=False, unique=True, index=True)
    # Deployment profile: saas | hybrid | self_hosted
    profile = Column(String(50), nullable=False, default="hybrid")
    status = Column(String(50), nullable=False, default="pending_enrollment")
    control_plane_url = Column(Text, nullable=True)
    location_label = Column(String(255), nullable=True)
    data_plane_version = Column(String(128), nullable=True)
    # Enrollment: token hash stored (never plaintext), plus expiry.
    enrollment_token_hash = Column(String(64), nullable=True)
    enrollment_token_expires_at = Column(DateTime(timezone=True), nullable=True)
    enrolled_at = Column(DateTime(timezone=True), nullable=True)
    # Deployment secret hash (HMAC key for signed policy packages).
    # The raw secret is returned once at enrollment and never stored.
    deployment_secret_hash = Column(String(64), nullable=True)
    # Policy sync state
    current_policy_version = Column(String(255), nullable=True)
    current_policy_sequence = Column(Integer, nullable=False, default=0)
    last_policy_sync_at = Column(DateTime(timezone=True), nullable=True)
    # Connectivity
    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    is_connected = Column(Boolean, nullable=False, default=False)
    disconnected_since = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="deployments")

    __table_args__ = (Index("ix_deployments_org_status", "organization_id", "status"),)


class SystemConfig(Base, TimestampMixin):
    __tablename__ = "system_config"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    key = Column(String(255), nullable=False, unique=True, index=True)
    value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    is_sensitive = Column(Boolean, nullable=False, default=False)

    __table_args__ = ()
