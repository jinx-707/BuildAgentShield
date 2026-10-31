from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    BLOCK = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    QUARANTINE = "QUARANTINE"
    REDACT = "REDACT"

    @classmethod
    def _missing_(cls, value: object) -> "Decision | None":
        if isinstance(value, str) and value.upper() == "BLOCK":
            return cls.DENY
        return None


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"
    SECRET = "secret"


class PrincipalType(str, Enum):
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"


class UserRole(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    APPROVER = "approver"
    VIEWER = "viewer"
    AUDITOR = "auditor"


class Finding(StrictModel):
    code: str = Field(min_length=1, max_length=100)
    severity: RiskLevel
    reason: str = Field(min_length=1, max_length=500)
    evidence: str = Field(default="", max_length=500)
    location: str = Field(default="request", max_length=200)


class Provenance(StrictModel):
    source: str = Field(default="unknown", min_length=1, max_length=200)
    trust: TrustLevel = TrustLevel.UNKNOWN
    data_classification: DataClassification = DataClassification.INTERNAL
    tainted: bool = False
    chain: list[str] = Field(default_factory=list, max_length=32)
    origin: str = Field(default="", max_length=200)
    taint_labels: list[str] = Field(default_factory=list, max_length=32)


class AuthContext(StrictModel):
    tenant_id: str
    principal_id: str
    principal_type: PrincipalType
    role: UserRole | None = None
    agent_id: str | None = None
    request_id: str | None = None
    permissions: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    scopes: dict[str, Any] = Field(default_factory=dict)


class SecurityVerdict(StrictModel):
    decision: Decision
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    reason: str = Field(min_length=1, max_length=1000)
    findings: list[Finding] = Field(default_factory=list)
    policy_id: str | None = None
    requires_approval: bool = False
    sanitized_arguments: dict[str, Any] | None = None
    redacted_payload: dict[str, Any] | None = None


class ToolRequest(StrictModel):
    request_id: str = Field(min_length=8, max_length=100)
    tool_name: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Field(default_factory=Provenance)
    reason: str = Field(default="", max_length=500)
    session_id: str | None = Field(default=None, max_length=100)
    idempotency_key: str | None = Field(default=None, max_length=200)
    user_intent: str = Field(default="", max_length=1000)
    approval_token: str | None = Field(default=None, max_length=2000)

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, separators=(",", ":"), default=str)
        if len(encoded.encode("utf-8")) > 64_000:
            raise ValueError("arguments exceed 64 KB")
        return value

    @model_validator(mode="after")
    def validate_request_id(self) -> "ToolRequest":
        if any(ch.isspace() for ch in self.request_id):
            raise ValueError("request_id must not contain whitespace")
        return self


class ApprovalChallenge(StrictModel):
    id: str
    status: str
    expires_at: datetime
    action_hash: str
    action_summary: str
    token: str | None = None


class ToolResponse(StrictModel):
    request_id: str
    decision: Decision
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    executed: bool
    result: dict[str, Any] | None = None
    findings: list[Finding] = Field(default_factory=list)
    reason: str
    approval: ApprovalChallenge | None = None
    audit_id: str | None = None
    quarantine_id: str | None = None
    idempotent_replay: bool = False
    status: str = "completed"
    tool: str = ""
    execution_id: str | None = None
    approval_id: str | None = None
    result_provenance: Provenance | None = None

    def model_post_init(self, __context: Any) -> None:
        if self.approval is not None and self.approval_id is None:
            self.approval_id = self.approval.id
        if self.status != "completed":
            return
        if self.decision == Decision.REQUIRE_APPROVAL:
            self.status = "pending_approval"
        elif self.decision == Decision.QUARANTINE:
            self.status = "quarantined"
        elif self.decision == Decision.DENY:
            self.status = "blocked"
        elif self.decision == Decision.REDACT:
            self.status = "redacted"


class AdapterResult(StrictModel):
    success: bool
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    sanitized: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance | None = None


class ToolSpec(StrictModel):
    name: str
    category: str
    description: str
    permission: str
    risk_score: int = Field(ge=0, le=100)
    requires_approval: bool = False
    supports_egress: bool = False
    input_schema: dict[str, Any] = Field(default_factory=dict)


class HealthComponent(StrictModel):
    name: str
    status: Literal["REAL", "MOCK", "UNAVAILABLE", "UNHEALTHY"]
    detail: str = ""


class HealthResponse(StrictModel):
    status: Literal["ok", "degraded", "unhealthy"]
    version: str
    mode: str
    components: list[HealthComponent]
    timestamp: datetime


class LoginRequest(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class LoginResponse(StrictModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict[str, Any]


class AgentCreate(StrictModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]+$")
    role: str = Field(default="Custom", max_length=100)
    permissions: list[str] = Field(default_factory=list)
    scopes: dict[str, Any] = Field(default_factory=dict)


class AgentUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=80)
    role: str | None = Field(default=None, max_length=100)
    status: Literal["Active", "Disabled"] | None = None
    permissions: list[str] | None = None
    scopes: dict[str, Any] | None = None


class AgentKeyResponse(StrictModel):
    agent_id: str
    api_key: str
    key_prefix: str
    message: str = "Store this key once. It cannot be retrieved again."


class ApprovalDecision(StrictModel):
    comment: str = Field(default="", max_length=1000)


class PolicyUpdate(StrictModel):
    active: bool


class PolicyCreate(StrictModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=1000)
    category: str = Field(default="Custom policy", max_length=100)
    rule: str = Field(min_length=1, max_length=4000)


class QuarantineRelease(StrictModel):
    comment: str = Field(default="", max_length=1000)


class SimulatorRunRequest(StrictModel):
    scenario_ids: list[str] = Field(default_factory=list, max_length=20)


class SimulatorScenarioResult(StrictModel):
    id: str
    name: str
    expected: str
    actual: str
    passed: bool
    risk: int
    executed: bool
    reason: str
    audit_id: str | None = None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def action_hash(tool_name: str, arguments: dict[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json({"tool": tool_name, "arguments": arguments}).encode("utf-8")
    ).hexdigest()


class WorkspaceUpdate(StrictModel):
    name: str = Field(min_length=2, max_length=160)

