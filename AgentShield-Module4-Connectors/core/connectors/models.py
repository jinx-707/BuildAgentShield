"""
AgentShield Connector & External Tool Data Models.
Pydantic domain models, enums, and exceptions for external REST APIs and MCP connectors.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.schemas import (
    Action,
    AgentShieldError,
    DetectionFinding,
    GuardrailContext,
    RiskLevel,
    RiskScore,
)


# ============================================================================
# Enums
# ============================================================================

class ConnectorType(str, Enum):
    """Supported connector protocol architectures."""
    REST_API = "rest_api"
    MCP = "mcp"


class HttpMethod(str, Enum):
    """Supported HTTP methods for REST API endpoints."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class AuthType(str, Enum):
    """Supported authentication mechanisms for external services."""
    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC = "basic"
    CUSTOM_HEADER = "custom_header"
    OAUTH2 = "oauth2"


class PermissionAction(str, Enum):
    """Access policy decision for agent-to-tool permissions."""
    ALLOW = "allow"
    DENY = "deny"


class PermissionScope(str, Enum):
    """Granular operation scopes for agent permissions."""
    READ_ONLY = "read_only"       # GET, HEAD only
    READ_WRITE = "read_write"     # GET, POST, PUT, PATCH
    ADMIN = "admin"               # Full access including DELETE
    CUSTOM = "custom"             # Explicit method/tool lists


class SecurityDecision(str, Enum):
    """Central gateway security decisions."""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    MASK = "mask"


class ExecutionStatus(str, Enum):
    """Status of an external connector execution."""
    SUCCESS = "success"
    REJECTED = "rejected"
    FAILED = "failed"


# ============================================================================
# Exceptions
# ============================================================================

class ConnectorError(AgentShieldError):
    """Base exception for connector gateway errors."""
    pass


class UnregisteredConnectorError(ConnectorError):
    """Raised when attempting to execute against an unregistered connector."""
    pass


class UnregisteredEndpointError(ConnectorError):
    """Raised when attempting to call an unregistered REST API endpoint or method."""
    pass


class UnregisteredToolError(ConnectorError):
    """Raised when attempting to call an unregistered or unapproved MCP tool."""
    pass


class PermissionDeniedError(ConnectorError):
    """Raised when an agent lacks permission to access a connector or tool."""
    pass


class PermissionEscalationError(ConnectorError):
    """Raised when an agent attempts to escalate its privileges via argument tampering."""
    pass


class SSRFSecurityError(ConnectorError):
    """Raised when an outbound URL violates SSRF, loopback, or private network policy."""
    pass


class RateLimitExceededError(ConnectorError):
    """Raised when rate limits per agent, connector, or tool are exceeded."""
    pass


class SchemaValidationError(ConnectorError):
    """Raised when request arguments or responses violate registered schemas."""
    pass


class GatewaySecurityViolationError(ConnectorError):
    """Raised when the SecurityEngine blocks outbound request or inbound response."""
    def __init__(
        self,
        message: str,
        stage: str,
        findings: list[DetectionFinding] | None = None,
        risk_score: float = 1.0,
        action: Action = Action.BLOCK,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.stage = stage
        self.findings = findings or []
        self.risk_score = risk_score
        self.action = action


class ConnectorExecutionError(ConnectorError):
    """Raised when an external REST API or MCP execution fails."""
    pass



# ============================================================================
# Connector & Tool Definitions
# ============================================================================

class AuthenticationConfig(BaseModel):
    """Authentication configuration for an external connector."""
    model_config = ConfigDict(extra="ignore")

    auth_type: AuthType = AuthType.NONE
    secret_id: str | None = Field(default=None, description="Secret Broker key ID")
    header_name: str = Field(default="Authorization", description="Header name for token or key")
    token_prefix: str = Field(default="Bearer ", description="Prefix before token in header")
    query_param_name: str | None = Field(default=None, description="Query param name if auth via URL")
    custom_headers: dict[str, str] = Field(default_factory=dict, description="Static non-secret headers")


class EndpointDefinition(BaseModel):
    """Specification for a registered REST API endpoint."""
    model_config = ConfigDict(extra="ignore")

    path: str = Field(..., description="Endpoint path, e.g. '/v1/weather' or '/users/{id}'")
    methods: list[HttpMethod] = Field(default_factory=lambda: [HttpMethod.GET])
    description: str = ""
    input_schema: dict[str, Any] | None = Field(default=None, description="JSON Schema for query/body")
    output_schema: dict[str, Any] | None = Field(default=None, description="JSON Schema for response")
    rate_limit_rpm: int | None = Field(default=None, ge=1)
    timeout_seconds: float | None = Field(default=None, ge=0.1)

    @field_validator("methods")
    @classmethod
    def validate_methods(cls, methods: list[HttpMethod]) -> list[HttpMethod]:
        if not methods:
            raise ValueError("Endpoint must support at least one HTTP method")
        return list(dict.fromkeys(methods))


class McpToolDefinition(BaseModel):
    """Specification for a discovered or registered MCP tool."""
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Tool name exposed by MCP server")
    description: str = Field(default="", description="Untrusted description provided by MCP server")
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}},
        description="JSON Schema for tool arguments"
    )
    output_schema: dict[str, Any] | None = Field(default=None, description="JSON Schema for tool result")
    is_approved: bool = Field(default=False, description="Whether tool has been verified and approved")
    rate_limit_rpm: int | None = Field(default=None, ge=1)
    timeout_seconds: float | None = Field(default=None, ge=0.1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConnectorRegistration(BaseModel):
    """Central registration model for an external REST API or MCP server."""
    model_config = ConfigDict(extra="ignore")

    connector_id: str = Field(..., description="Unique alphanumeric identifier")
    name: str = Field(..., description="Human-readable connector name")
    connector_type: ConnectorType
    base_url: str | None = Field(default=None, description="Base URL for REST API (https://...)")
    mcp_server_url: str | None = Field(default=None, description="MCP Server URL or transport URI")
    allowed_endpoints: list[EndpointDefinition] = Field(default_factory=list)
    allowed_tools: list[McpToolDefinition] = Field(default_factory=list)
    auth_config: AuthenticationConfig = Field(default_factory=AuthenticationConfig)
    enabled: bool = Field(default=True)
    max_payload_size_bytes: int = Field(default=1_048_576, ge=1024, le=52_428_800)  # 1MB default, 50MB max
    default_timeout_seconds: float = Field(default=10.0, ge=0.5, le=120.0)
    max_retries: int = Field(default=2, ge=0, le=5)
    retry_backoff_factor: float = Field(default=0.5, ge=0.0)
    rate_limit_rpm: int | None = Field(default=None, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("connector_id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("connector_id cannot be empty")
        return clean


# ============================================================================
# Permissions Model
# ============================================================================

class AgentPermissionRule(BaseModel):
    """Access control rule governing an agent's access to a connector or tool."""
    model_config = ConfigDict(extra="ignore")

    agent_id: str
    connector_id: str
    action: PermissionAction = PermissionAction.ALLOW
    scope: PermissionScope = PermissionScope.READ_WRITE
    allowed_tools: list[str] | None = Field(
        default=None,
        description="Explicit allowed tools. If None, permitted tools follow scope."
    )
    denied_tools: list[str] = Field(default_factory=list)
    allowed_methods: list[HttpMethod] | None = Field(
        default=None,
        description="Explicit allowed HTTP methods. If None, follows scope."
    )
    denied_methods: list[HttpMethod] = Field(default_factory=list)
    argument_constraints: dict[str, Any] = Field(
        default_factory=dict,
        description="Restrictions on tool arguments to prevent privilege escalation"
    )
    forbidden_argument_keys: list[str] = Field(
        default_factory=lambda: ["role", "admin", "privilege", "sudo", "override", "bypass"],
        description="Parameter keys that trigger escalation block if modified"
    )


# ============================================================================
# Gateway Execution Request & Response
# ============================================================================

class ExecutionRequest(BaseModel):
    """Request submitted to the AgentShield Gateway for external execution."""
    model_config = ConfigDict(extra="ignore")

    agent_id: str
    connector_id: str
    endpoint: str | None = Field(default=None, description="Path for REST API, e.g. '/v1/data'")
    method: HttpMethod = Field(default=HttpMethod.GET, description="HTTP method for REST API")
    tool_name: str | None = Field(default=None, description="Tool name for MCP or named tool")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Tool arguments or query/body parameters")
    body: Any | None = Field(default=None, description="Explicit request body for POST/PUT/PATCH")
    headers: dict[str, str] = Field(default_factory=dict, description="Caller-supplied headers")
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConnectorAuditRecord(BaseModel):
    """Structured audit log entry for external tool interactions."""
    model_config = ConfigDict(frozen=True)

    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    connector_id: str
    tool_name: str | None = None
    http_method: str | None = None
    endpoint: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    security_decision: SecurityDecision
    execution_status: ExecutionStatus
    rejection_reason: str | None = None
    duration_ms: float = Field(ge=0.0)
    findings_count: int = 0
    risk_score: float = 0.0
    provenance_record_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutionResponse(BaseModel):
    """Safe response returned to the agent after full gateway inspection."""
    model_config = ConfigDict(extra="ignore")

    status: ExecutionStatus
    security_decision: SecurityDecision
    allowed: bool
    data: Any | None = None
    sanitized_data: Any | None = None
    rejection_reason: str | None = None
    audit_record: ConnectorAuditRecord | None = None
    latency_ms: float = 0.0
    findings: list[DetectionFinding] = Field(default_factory=list)
