"""
AgentShield Offline — Core Pydantic contracts.

Every offline security request and response passes through these schemas.
Identity (agent_id, tenant_id) must come from the trusted runtime security
context, never from LLM-generated arguments.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SecurityDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REDACT = "REDACT"
    QUARANTINE = "QUARANTINE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ResponseStatus(str, Enum):
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    QUARANTINED = "QUARANTINED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ERROR = "ERROR"
    UNAVAILABLE = "UNAVAILABLE"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class OfflineModule(str, Enum):
    DOCUMENT_ANALYSIS = "document_analysis"
    SYSTEM_FILE_ACCESS = "system_file_access"
    LOCAL_FILE_ACCESS = "local_file_access"
    ENVIRONMENT_PROTECTION = "environment_protection"
    TERMINAL_EXECUTION = "terminal_execution"


class FileOperation(str, Enum):
    READ = "read"
    WRITE = "write"
    CREATE = "create"
    DELETE = "delete"
    MOVE = "move"
    COPY = "copy"
    LIST = "list"
    SEARCH = "search"


# ---------------------------------------------------------------------------
# Security context — identity from the trusted runtime, not LLM arguments
# ---------------------------------------------------------------------------


class SecurityContext(BaseModel):
    """
    Authenticated runtime identity.
    Must be injected by the trusted runtime layer, never by LLM-generated input.
    """

    agent_id: str = Field(..., description="Authenticated agent identifier")
    tenant_id: str = Field(..., description="Tenant / organisation identifier")
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Base request / response
# ---------------------------------------------------------------------------


class BaseOfflineRequest(BaseModel):
    """Root class for every offline security request."""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = Field(..., description="Caller agent ID (from security context)")
    tenant_id: str = Field(default="default", description="Tenant ID (from security context)")
    tool_name: str = Field(..., description="Name of the AgentShield tool being invoked")
    operation: str = Field(..., description="Specific operation requested")


class SecurityFinding(BaseModel):
    """A single security finding produced during inspection."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    severity: RiskLevel = RiskLevel.MEDIUM
    category: str
    description: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None


class BaseOfflineResponse(BaseModel):
    """Standard response wrapper for all offline security operations."""

    request_id: str
    status: ResponseStatus
    decision: SecurityDecision
    module: OfflineModule
    tool: str
    risk_level: RiskLevel = RiskLevel.LOW
    reason: Optional[str] = None
    execution_id: Optional[str] = None
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    result: Optional[dict[str, Any]] = None
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def is_allowed(self) -> bool:
        return self.decision == SecurityDecision.ALLOW and self.status == ResponseStatus.EXECUTED

    def is_blocked(self) -> bool:
        return self.decision == SecurityDecision.DENY


# ---------------------------------------------------------------------------
# Document contracts
# ---------------------------------------------------------------------------


class DocumentAnalysisRequest(BaseOfflineRequest):
    tool_name: str = "analyze_document"
    operation: str = "analyze"
    file_path: str = Field(..., description="Absolute path to the document file")
    extract_text: bool = True
    extract_metadata: bool = True
    run_malware_scan: bool = True


class MalwareScanStatus(str, Enum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    SUSPICIOUS = "SUSPICIOUS"
    SCAN_FAILED = "SCAN_FAILED"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"
    NOT_SCANNED = "NOT_SCANNED"


class ExtractionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class InspectionStatus(str, Enum):
    PASSED = "PASSED"
    FLAGGED = "FLAGGED"
    SKIPPED = "SKIPPED"
    INSPECTOR_UNAVAILABLE = "INSPECTOR_UNAVAILABLE"
    ERROR = "ERROR"


class DocumentAnalysisResult(BaseModel):
    document_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_format: str
    file_size: int
    content_hash: str
    extraction_status: ExtractionStatus
    malware_scan_status: MalwareScanStatus
    inspection_status: InspectionStatus
    trust_level: str = "UNTRUSTED"
    page_count: Optional[int] = None
    extracted_text_length: Optional[int] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    quarantined: bool = False
    quarantine_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Filesystem contracts
# ---------------------------------------------------------------------------


class FileAccessRequest(BaseOfflineRequest):
    tool_name: str = "file_access"
    file_path: str
    workspace_root: Optional[str] = None


class FileReadRequest(FileAccessRequest):
    operation: str = "read"
    encoding: str = "utf-8"
    max_bytes: Optional[int] = None


class FileSearchRequest(BaseOfflineRequest):
    tool_name: str = "file_search"
    operation: str = "search"
    directory: str
    pattern: str
    workspace_root: Optional[str] = None
    recursive: bool = False
    max_results: int = Field(default=100, le=1000)


class FileListRequest(BaseOfflineRequest):
    tool_name: str = "file_list"
    operation: str = "list"
    directory: str
    workspace_root: Optional[str] = None


class FileCreateRequest(FileAccessRequest):
    operation: str = "create"
    content: str = ""
    encoding: str = "utf-8"


class FileUpdateRequest(FileAccessRequest):
    operation: str = "update"
    content: str
    encoding: str = "utf-8"


class FileDeleteRequest(FileAccessRequest):
    operation: str = "delete"


class FileMoveRequest(BaseOfflineRequest):
    tool_name: str = "file_move"
    operation: str = "move"
    source_path: str
    destination_path: str
    workspace_root: Optional[str] = None


class FileCopyRequest(BaseOfflineRequest):
    tool_name: str = "file_copy"
    operation: str = "copy"
    source_path: str
    destination_path: str
    workspace_root: Optional[str] = None


# ---------------------------------------------------------------------------
# System file contracts
# ---------------------------------------------------------------------------


class SystemFileInspectRequest(BaseOfflineRequest):
    tool_name: str = "system_file_inspect"
    operation: str = "inspect"
    path: str
    access_type: FileOperation = FileOperation.READ


# ---------------------------------------------------------------------------
# Environment contracts
# ---------------------------------------------------------------------------


class EnvironmentInspectRequest(BaseOfflineRequest):
    tool_name: str = "environment_inspect"
    operation: str = "inspect"
    variable_names: list[str] = Field(default_factory=list)
    purpose: Optional[str] = None


class SecretAccessRequest(BaseOfflineRequest):
    tool_name: str = "secret_access"
    operation: str = "retrieve"
    secret_id: str
    purpose: Optional[str] = None


# ---------------------------------------------------------------------------
# Terminal contracts
# ---------------------------------------------------------------------------


class CommandRequest(BaseOfflineRequest):
    """
    Structured command request.
    LLM must NOT pass raw shell strings — only structured executable + arguments.
    """

    tool_name: str = "terminal_execute"
    operation: str = "execute"
    executable: str = Field(..., description="Executable name (e.g. 'python', 'ls')")
    arguments: list[str] = Field(default_factory=list)
    working_directory: str = Field(default="/workspace")
    timeout: int = Field(default=30, ge=1, le=300)
    environment: dict[str, str] = Field(
        default_factory=dict,
        description="Explicit env vars for the sandbox (must not include host secrets)",
    )

    @field_validator("executable")
    @classmethod
    def no_shell_metacharacters(cls, v: str) -> str:
        forbidden = set(";&|`$(){}[]<>\\!#~")
        if any(c in v for c in forbidden):
            raise ValueError(
                f"Executable contains forbidden shell metacharacters: {v!r}"
            )
        return v


class CommandExecutionResult(BaseModel):
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    executable: str
    arguments: list[str]
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    output_truncated: bool = False
    sandbox_used: bool = True
    timed_out: bool = False


# ---------------------------------------------------------------------------
# Audit event
# ---------------------------------------------------------------------------


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    agent_id: str
    tenant_id: str
    module: OfflineModule
    tool: str
    operation: str
    resource: Optional[str] = None
    decision: SecurityDecision
    risk_level: RiskLevel
    reason: Optional[str] = None
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    # NOTE: never populate this field with secret values or file contents
    metadata: dict[str, Any] = Field(default_factory=dict)
