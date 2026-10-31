"""
AgentShield Core Schemas & Domain Models.
Production-grade Pydantic models, Enums, and custom exceptions for the
AgentShield Runtime Security Gateway.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Enums
# ============================================================================

class RiskLevel(str, Enum):
    """Categorical risk classifications."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """Action decisions executed by guardrails."""
    ALLOW = "allow"
    WARN = "warn"
    MASK = "mask"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class DetectorType(str, Enum):
    """Identifier for security sub-engine detectors."""
    INJECTION = "injection"
    PII = "pii"
    SECRET = "secret"
    DLP = "dlp"
    PROVENANCE = "provenance"


class SensitivityLevel(str, Enum):
    """Data classification levels for Data Loss Prevention (DLP)."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class PIIType(str, Enum):
    """Supported Personally Identifiable Information types."""
    EMAIL = "email"
    PHONE_NUMBER = "phone_number"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    US_PASSPORT = "us_passport"
    DATE_OF_BIRTH = "date_of_birth"
    PERSON = "person"
    LOCATION = "location"
    AADHAAR = "aadhaar"
    PAN = "pan"
    DRIVER_LICENSE = "driver_license"


class SecretType(str, Enum):
    """Supported high-entropy credentials & secret types."""
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    OPENAI_API_KEY = "openai_api_key"
    GITHUB_PAT = "github_pat"
    SLACK_TOKEN = "slack_token"
    SSH_PRIVATE_KEY = "ssh_private_key"
    JWT_TOKEN = "jwt_token"
    DATABASE_CREDENTIALS = "database_credentials"
    PASSWORD = "password"
    BEARER_TOKEN = "bearer_token"
    GENERIC_SECRET = "generic_secret"
    HIGH_ENTROPY = "high_entropy"


class RedactionMode(str, Enum):
    """Strategy for redacting sensitive content."""
    MASK = "mask"
    HASH = "hash"
    TOKEN = "token"
    FULL_REDACT = "full_redact"


class SourceType(str, Enum):
    """Origin sources for content ingestion and provenance tracking."""
    USER = "user"
    FILE = "file"
    WEBSITE = "website"
    TOOL_OUTPUT = "tool_output"
    SYSTEM = "system"
    AGENT = "agent"


class TrustLevel(str, Enum):
    """Trust hierarchy for provenance sources and content origins."""
    TRUSTED = "trusted"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNTRUSTED = "untrusted"


# ============================================================================
# Exceptions
# ============================================================================

class AgentShieldError(Exception):
    """Base exception for all AgentShield errors."""
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(AgentShieldError):
    """Raised when configuration parameters or environment variables are invalid."""
    pass


class GuardrailViolationError(AgentShieldError):
    """Raised when an input or output prompt is actively BLOCKED by policy."""
    def __init__(
        self,
        message: str,
        action: Action = Action.BLOCK,
        risk_score: float = 1.0,
        findings: list[DetectionFinding] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.action = action
        self.risk_score = risk_score
        self.findings = findings or []


class InjectionDetectedError(GuardrailViolationError):
    """Raised when prompt injection or jailbreak behavior is blocked."""
    pass


class SecretLeakError(GuardrailViolationError):
    """Raised when an unredacted secret or API credential is leaked."""
    pass


class PIIViolationError(GuardrailViolationError):
    """Raised when PII policy is violated in blocking mode."""
    pass


class DLPViolationError(GuardrailViolationError):
    """Raised when corporate DLP policy is violated in blocking mode."""
    pass


class RiskThresholdExceededError(GuardrailViolationError):
    """Raised when compound risk score exceeds the acceptable threshold."""
    pass


class ProvenanceVerificationError(AgentShieldError):
    """Raised when cryptographic provenance or audit chain verification fails."""
    pass


# ============================================================================
# Core Detection Schemas
# ============================================================================

class DetectionFinding(BaseModel):
    """Individual security detection finding."""
    model_config = ConfigDict(frozen=True)

    detector: DetectorType
    rule_id: str
    description: str
    risk_score: float = Field(ge=0.0, le=1.0)
    start_index: int | None = Field(default=None, ge=0)
    end_index: int | None = Field(default=None, ge=0)
    redacted_value: str | None = None
    match_preview: str | None = None  # Safe masked preview; never raw credential
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("end_index")
    @classmethod
    def validate_indices(cls, v: int | None, info: Any) -> int | None:
        start = info.data.get("start_index")
        if start is not None and v is not None and v < start:
            raise ValueError(f"end_index ({v}) cannot be less than start_index ({start})")
        return v


class InjectionAnalysisResult(BaseModel):
    """Result emitted by the Prompt Injection Detector."""
    is_injection: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_patterns: list[str] = Field(default_factory=list)
    attack_categories: list[str] = Field(default_factory=list)
    findings: list[DetectionFinding] = Field(default_factory=list)
    obfuscation_detected: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class PIIAnalysisResult(BaseModel):
    """Result emitted by the Personally Identifiable Information (PII) Detector."""
    has_pii: bool = False
    pii_count: int = 0
    findings: list[DetectionFinding] = Field(default_factory=list)
    sanitized_text: str
    replacement_map: dict[str, str] = Field(default_factory=dict)


class SecretAnalysisResult(BaseModel):
    """Result emitted by the Secret Scanner."""
    has_secrets: bool = False
    secret_count: int = 0
    findings: list[DetectionFinding] = Field(default_factory=list)
    sanitized_text: str


class DLPAnalysisResult(BaseModel):
    """Result emitted by the Data Loss Prevention (DLP) Engine."""
    violates_policy: bool = False
    highest_sensitivity: SensitivityLevel = SensitivityLevel.PUBLIC
    findings: list[DetectionFinding] = Field(default_factory=list)
    sanitized_text: str


# ============================================================================
# Risk & Provenance Schemas
# ============================================================================

class RiskScore(BaseModel):
    """Aggregated risk assessment calculated across all detectors."""
    overall_score: float = Field(ge=0.0, le=1.0)
    level: RiskLevel
    component_scores: dict[str, float] = Field(default_factory=dict)
    factors: list[str] = Field(default_factory=list)
    recommended_action: Action
    context_multiplier: float = Field(default=1.0, ge=0.5, le=3.0)


class ProvenanceRecord(BaseModel):
    """Cryptographic tamper-evident audit ledger record."""
    model_config = ConfigDict(frozen=True)

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sequence_number: int = Field(ge=0)
    parent_hash: str | None = None
    current_hash: str
    session_id: str | None = None
    agent_id: str | None = None
    input_hash: str
    output_hash: str | None = None
    action_taken: Action
    risk_level: RiskLevel
    signature: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_type: SourceType = SourceType.USER
    trust_level: TrustLevel = TrustLevel.MEDIUM
    source_uri: str | None = None
    parent_id: str | None = None
    parent_ids: list[str] = Field(default_factory=list)


# ============================================================================
# Guardrail Request & Response Envelopes
# ============================================================================

class GuardrailContext(BaseModel):
    """Contextual metadata accompanying an agent interaction."""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = "default_agent"
    user_id: str | None = None
    tools_enabled: list[str] = Field(default_factory=list)
    is_privileged_agent: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GuardrailInputRequest(BaseModel):
    """Input payload submitted to the Input Guardrail."""
    prompt: str
    context: GuardrailContext = Field(default_factory=GuardrailContext)


class GuardrailInputResponse(BaseModel):
    """Validated, sanitized input response returned by the Input Guardrail."""
    allowed: bool
    action: Action
    sanitized_prompt: str
    risk_assessment: RiskScore
    findings: list[DetectionFinding] = Field(default_factory=list)
    provenance_record: ProvenanceRecord
    latency_ms: float = Field(ge=0.0)


class GuardrailOutputRequest(BaseModel):
    """Output payload generated by the LLM submitted to Output Guardrail."""
    raw_output: str
    context: GuardrailContext = Field(default_factory=GuardrailContext)
    source_input_hash: str | None = None


class GuardrailOutputResponse(BaseModel):
    """Validated, sanitized output response returned by the Output Guardrail."""
    allowed: bool
    action: Action
    sanitized_output: str
    risk_assessment: RiskScore
    findings: list[DetectionFinding] = Field(default_factory=list)
    provenance_record: ProvenanceRecord
    latency_ms: float = Field(ge=0.0)
