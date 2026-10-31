"""
AgentShield Online — Custom exceptions.
All exceptions carry a machine-readable code for structured error responses.
"""
from __future__ import annotations


class AgentShieldError(Exception):
    """Base for all AgentShield errors."""
    code: str = "AGENTSHIELD_ERROR"

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code


# ── Security / Policy ────────────────────────────────────────────────────────

class SecurityViolationError(AgentShieldError):
    code = "SECURITY_VIOLATION"


class PolicyDeniedError(AgentShieldError):
    code = "POLICY_DENIED"


class PermissionDeniedError(AgentShieldError):
    code = "PERMISSION_DENIED"


class ApprovalRequiredError(AgentShieldError):
    code = "APPROVAL_REQUIRED"

    def __init__(self, message: str, approval_request_id: str | None = None) -> None:
        super().__init__(message)
        self.approval_request_id = approval_request_id


class ApprovalExpiredError(AgentShieldError):
    code = "APPROVAL_EXPIRED"


class ApprovalInvalidError(AgentShieldError):
    code = "APPROVAL_INVALID"


class ContentInspectionError(AgentShieldError):
    code = "CONTENT_INSPECTION_BLOCKED"


# ── Browser ──────────────────────────────────────────────────────────────────

class BrowserError(AgentShieldError):
    code = "BROWSER_ERROR"


class URLValidationError(AgentShieldError):
    code = "URL_VALIDATION_FAILED"


class SSRFAttemptError(AgentShieldError):
    code = "SSRF_ATTEMPT_BLOCKED"


class RedirectViolationError(AgentShieldError):
    code = "REDIRECT_VIOLATION"


class BrowserSessionError(AgentShieldError):
    code = "BROWSER_SESSION_ERROR"


class FormSubmissionDeniedError(AgentShieldError):
    code = "FORM_SUBMISSION_DENIED"


# ── Email ─────────────────────────────────────────────────────────────────────

class EmailError(AgentShieldError):
    code = "EMAIL_ERROR"


class UnauthorizedRecipientError(AgentShieldError):
    code = "UNAUTHORIZED_RECIPIENT"


class EmailDLPViolationError(AgentShieldError):
    code = "EMAIL_DLP_VIOLATION"


class OAuthError(AgentShieldError):
    code = "OAUTH_ERROR"


class EmailSendDeniedError(AgentShieldError):
    code = "EMAIL_SEND_DENIED"


# ── Downloads ─────────────────────────────────────────────────────────────────

class DownloadError(AgentShieldError):
    code = "DOWNLOAD_ERROR"


class DownloadSizeLimitError(AgentShieldError):
    code = "DOWNLOAD_SIZE_LIMIT"


class MalwareDetectedError(AgentShieldError):
    code = "MALWARE_DETECTED"


class FileValidationError(AgentShieldError):
    code = "FILE_VALIDATION_FAILED"


class ScannerUnavailableError(AgentShieldError):
    code = "SCANNER_UNAVAILABLE"


class QuarantinedError(AgentShieldError):
    code = "FILE_QUARANTINED"


# ── External APIs ─────────────────────────────────────────────────────────────

class APIError(AgentShieldError):
    code = "API_ERROR"


class UnknownConnectorError(AgentShieldError):
    code = "UNKNOWN_CONNECTOR"


class APISchemaValidationError(AgentShieldError):
    code = "API_SCHEMA_VALIDATION_FAILED"


class RateLimitError(AgentShieldError):
    code = "RATE_LIMIT_EXCEEDED"


class CredentialError(AgentShieldError):
    code = "CREDENTIAL_ERROR"


# ── MCP ───────────────────────────────────────────────────────────────────────

class MCPError(AgentShieldError):
    code = "MCP_ERROR"


class MCPServerUnregisteredError(AgentShieldError):
    code = "MCP_SERVER_UNREGISTERED"


class MCPToolUnauthorizedError(AgentShieldError):
    code = "MCP_TOOL_UNAUTHORIZED"


class MCPConnectionError(AgentShieldError):
    code = "MCP_CONNECTION_ERROR"


class MCPToolValidationError(AgentShieldError):
    code = "MCP_TOOL_VALIDATION_FAILED"


# ── Payments ──────────────────────────────────────────────────────────────────

class PaymentError(AgentShieldError):
    code = "PAYMENT_ERROR"


class UnauthorizedMerchantError(AgentShieldError):
    code = "UNAUTHORIZED_MERCHANT"


class SpendingLimitExceededError(AgentShieldError):
    code = "SPENDING_LIMIT_EXCEEDED"


class DuplicateTransactionError(AgentShieldError):
    code = "DUPLICATE_TRANSACTION"


class WebhookVerificationError(AgentShieldError):
    code = "WEBHOOK_VERIFICATION_FAILED"


class InvalidTransactionStateError(AgentShieldError):
    code = "INVALID_TRANSACTION_STATE"


class PaymentProviderError(AgentShieldError):
    code = "PAYMENT_PROVIDER_ERROR"


class RealMoneyProtectionError(AgentShieldError):
    """Raised if live payment mode is somehow activated."""
    code = "REAL_MONEY_PROTECTION"
