"""Hybrid deployment data models.

Defines the structures exchanged between the central control plane and
customer-hosted data planes.  These are intentionally separate from the
ORM models to keep the sync protocol portable and testable without a DB.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class DeploymentProfile(str, enum.Enum):
    SAAS = "saas"          # fully hosted by AgentShield
    HYBRID = "hybrid"      # control plane hosted, data plane in customer VPC
    SELF_HOSTED = "self_hosted"  # both planes in customer infrastructure


class DeploymentStatus(str, enum.Enum):
    PENDING_ENROLLMENT = "pending_enrollment"
    ACTIVE = "active"
    DEGRADED = "degraded"          # operating but with issues
    DISCONNECTED = "disconnected"  # cannot reach control plane
    REVOKED = "revoked"


class PolicySigningAlgorithm(str, enum.Enum):
    HMAC_SHA256 = "hmac-sha256"    # symmetric; keyed to deployment secret
    ECDSA_P256 = "ecdsa-p256"      # asymmetric; future extension


# ── Enrollment ──────────────────────────────────────────────────────────────

class EnrollmentRequest(BaseModel):
    """Sent by a data plane to the control plane during first-time registration."""
    deployment_name: str = Field(..., min_length=1, max_length=128)
    profile: DeploymentProfile = DeploymentProfile.HYBRID
    # Operators generate an enrollment token from the control-plane UI or CLI.
    enrollment_token: str = Field(..., min_length=32)
    # Semantic version of the data-plane software.
    data_plane_version: str = Field(default="unknown")
    # Human-readable location label for the deployment.
    location_label: Optional[str] = None
    # Public key material for future mTLS upgrade (PEM, optional).
    public_key_pem: Optional[str] = None


class EnrollmentResponse(BaseModel):
    """Returned by the control plane on successful enrollment."""
    deployment_id: str
    # Long-lived deployment secret used to sign/verify policy packages.
    deployment_secret: str = Field(..., min_length=32)
    # Initial policy package to bootstrap the data plane before it completes
    # its first full sync cycle.
    initial_policy: Optional["PolicyPackage"] = None
    # How often the data plane should poll for policy updates (seconds).
    sync_interval_seconds: int = Field(default=300, ge=30)
    # Control-plane endpoint for subsequent sync calls.
    control_plane_url: str


# ── Policy synchronization ───────────────────────────────────────────────────

class PolicySpec(BaseModel):
    """The effective policy for a deployment.

    Sensitive values (tokens, passwords) must never appear here.
    """
    allowed_domains: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    default_domain_policy: str = Field(default="deny")
    allowed_ports: str = Field(default="80,443")
    max_redirects: int = Field(default=5, ge=0, le=20)
    block_https_downgrade: bool = True
    allow_private_networks: bool = False
    # AI security controls
    dlp_enabled: bool = True
    threat_detection_enabled: bool = True
    risk_threshold_deny: float = Field(default=75.0, ge=0.0, le=100.0)
    risk_threshold_review: float = Field(default=50.0, ge=0.0, le=100.0)
    # Session controls
    session_max_age_seconds: int = Field(default=3600, ge=60)
    session_idle_timeout_seconds: int = Field(default=300, ge=30)
    # Tool governance
    allowed_tool_categories: list[str] = Field(
        default_factory=lambda: ["read", "search", "extract"]
    )

    class Config:
        extra = "forbid"


class PolicyPackage(BaseModel):
    """A signed, versioned policy bundle distributed to data planes.

    The signature covers version_id + deployment_id + created_at (ISO8601) +
    the canonical JSON of PolicySpec (keys sorted, no whitespace).  The data
    plane MUST verify this signature before applying the policy.
    """
    # Unique, monotonically increasing version identifier.
    version_id: str = Field(..., min_length=1)
    deployment_id: str
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    spec: PolicySpec
    # Hex-encoded HMAC-SHA256 over the canonical payload (see signing module).
    signature: str
    signing_algorithm: PolicySigningAlgorithm = PolicySigningAlgorithm.HMAC_SHA256
    # Sequence number for replay protection.  Data planes reject packages with
    # a sequence_number ≤ the last accepted number.
    sequence_number: int = Field(default=0, ge=0)
    # The policy is valid until this time even if the control plane is
    # unreachable (offline grace period).
    valid_until: Optional[datetime] = None


class PolicySyncRequest(BaseModel):
    """Data plane → control plane: request the latest policy."""
    deployment_id: str
    current_version_id: Optional[str] = None  # None = no policy yet
    current_sequence_number: int = 0


class PolicySyncResponse(BaseModel):
    """Control plane → data plane: current policy package (or no-change)."""
    has_update: bool
    package: Optional[PolicyPackage] = None
    # When True, the control plane is explicitly telling the data plane to
    # roll back to last_known_good_version.
    rollback_requested: bool = False
    last_known_good_version: Optional[str] = None


# ── Telemetry ────────────────────────────────────────────────────────────────

class TelemetryEvent(BaseModel):
    """A single security event from the data plane.

    Sensitive browser content (cookies, form data, raw HTML) MUST NOT appear
    in telemetry that is transmitted to the control plane.
    """
    event_id: str
    deployment_id: str
    occurred_at: datetime
    event_type: str
    # Severity: info / low / medium / high / critical
    severity: str = "info"
    # Summary string — no raw page content.
    summary: str = Field(..., max_length=512)
    # Structured metadata — validated to not contain sensitive fields.
    metadata: dict[str, Any] = Field(default_factory=dict)
    session_id: Optional[str] = None
    agent_id: Optional[str] = None


class TelemetryBatch(BaseModel):
    """Batch of telemetry events sent from data plane to control plane."""
    deployment_id: str
    batch_id: str
    events: list[TelemetryEvent]
    # Checkpoint: the data plane advances this after the control plane ACKs.
    checkpoint: str


class TelemetryAck(BaseModel):
    """Control plane acknowledges receipt of a telemetry batch."""
    batch_id: str
    accepted_count: int
    rejected_count: int
    # The data plane should advance its checkpoint to this value.
    next_checkpoint: str


# ── Health ───────────────────────────────────────────────────────────────────

class DataPlaneHealth(BaseModel):
    """Data plane health report sent to the control plane."""
    deployment_id: str
    reported_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    status: DeploymentStatus
    # Seconds since last successful policy sync.
    seconds_since_policy_sync: Optional[float] = None
    current_policy_version: Optional[str] = None
    # Whether the data plane is currently operating in disconnected mode.
    disconnected_mode: bool = False
    # Component health flags.
    api_healthy: bool = True
    worker_healthy: bool = True
    proxy_healthy: bool = True
    db_healthy: bool = True
    # Counters (reset on restart).
    sessions_active: int = 0
    events_buffered: int = 0
    policy_rejections: int = 0
