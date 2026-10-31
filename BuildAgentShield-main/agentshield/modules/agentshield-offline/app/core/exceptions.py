"""
AgentShield Offline — Exception hierarchy.

All exceptions carry structured metadata that can be safely serialised and
returned to callers without exposing internal details or secrets.
"""

from __future__ import annotations

from typing import Any, Optional


class AgentShieldError(Exception):
    """Root exception for all AgentShield offline errors."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "AGENTSHIELD_ERROR",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details: dict[str, Any] = details or {}

    def safe_dict(self) -> dict[str, Any]:
        """Return a representation safe to expose to callers."""
        return {"code": self.code, "message": self.message}


# ---------------------------------------------------------------------------
# Policy / authorisation
# ---------------------------------------------------------------------------


class PolicyDeniedError(AgentShieldError):
    """Raised when a security policy denies a requested operation."""

    def __init__(self, message: str, *, resource: str = "", reason: str = "") -> None:
        super().__init__(message, code="POLICY_DENIED")
        self.resource = resource
        self.reason = reason


class UnauthorizedAccessError(AgentShieldError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="UNAUTHORIZED_ACCESS")


# ---------------------------------------------------------------------------
# Path / filesystem
# ---------------------------------------------------------------------------


class PathTraversalError(AgentShieldError):
    def __init__(self, message: str, *, attempted_path: str = "") -> None:
        super().__init__(message, code="PATH_TRAVERSAL")
        self.attempted_path = attempted_path


class SymlinkEscapeError(AgentShieldError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="SYMLINK_ESCAPE")


class ProtectedPathError(AgentShieldError):
    def __init__(self, message: str, *, path: str = "") -> None:
        super().__init__(message, code="PROTECTED_PATH")
        self.path = path


class WorkspaceEscapeError(AgentShieldError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="WORKSPACE_ESCAPE")


class FileOperationError(AgentShieldError):
    def __init__(self, message: str, *, operation: str = "") -> None:
        super().__init__(message, code="FILE_OPERATION_ERROR")
        self.operation = operation


# ---------------------------------------------------------------------------
# Document analysis
# ---------------------------------------------------------------------------


class DocumentParseError(AgentShieldError):
    def __init__(self, message: str, *, format: str = "") -> None:
        super().__init__(message, code="DOCUMENT_PARSE_ERROR")
        self.format = format


class UnsupportedFormatError(AgentShieldError):
    def __init__(self, message: str, *, detected_format: str = "") -> None:
        super().__init__(message, code="UNSUPPORTED_FORMAT")
        self.detected_format = detected_format


class DocumentSizeLimitError(AgentShieldError):
    def __init__(self, message: str, *, size: int = 0, limit: int = 0) -> None:
        super().__init__(message, code="DOCUMENT_SIZE_LIMIT")
        self.size = size
        self.limit = limit


class MalwareDetectedError(AgentShieldError):
    def __init__(self, message: str, *, threat_name: str = "") -> None:
        super().__init__(message, code="MALWARE_DETECTED")
        self.threat_name = threat_name


class ScannerUnavailableError(AgentShieldError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="SCANNER_UNAVAILABLE")


class QuarantineError(AgentShieldError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="QUARANTINE_ERROR")


# ---------------------------------------------------------------------------
# Environment / secrets
# ---------------------------------------------------------------------------


class SecretAccessDeniedError(AgentShieldError):
    def __init__(self, message: str, *, secret_id: str = "") -> None:
        super().__init__(message, code="SECRET_ACCESS_DENIED")
        # Do NOT store the secret value here — only the identifier
        self.secret_id = secret_id


class EnvironmentAccessDeniedError(AgentShieldError):
    def __init__(self, message: str, *, variable: str = "") -> None:
        super().__init__(message, code="ENV_ACCESS_DENIED")
        self.variable = variable


# ---------------------------------------------------------------------------
# Terminal / sandbox
# ---------------------------------------------------------------------------


class CommandDeniedError(AgentShieldError):
    def __init__(self, message: str, *, executable: str = "") -> None:
        super().__init__(message, code="COMMAND_DENIED")
        self.executable = executable


class SandboxUnavailableError(AgentShieldError):
    """Raised when the sandbox cannot be started. Never fall back to host execution."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="SANDBOX_UNAVAILABLE")


class ExecutionTimeoutError(AgentShieldError):
    def __init__(self, message: str, *, timeout_seconds: int = 0) -> None:
        super().__init__(message, code="EXECUTION_TIMEOUT")
        self.timeout_seconds = timeout_seconds


class ExecutionError(AgentShieldError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="EXECUTION_ERROR")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigurationError(AgentShieldError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="CONFIGURATION_ERROR")


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------


class InspectorUnavailableError(AgentShieldError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="INSPECTOR_UNAVAILABLE")
