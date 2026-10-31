"""
Security decision enumerations and status codes used across all capabilities.
"""
from __future__ import annotations

from enum import Enum


class SecurityDecision(str, Enum):
    """The security enforcement decision for an operation."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    REDACT = "REDACT"
    QUARANTINE = "QUARANTINE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class OperationStatus(str, Enum):
    """Final status of an operation attempt."""
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    REDACTED = "REDACTED"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"


class TrustLevel(str, Enum):
    """Trust classification for external content."""
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    SUSPICIOUS = "suspicious"


class ContentSource(str, Enum):
    """Source classification for inspected content."""
    EXTERNAL_WEBPAGE = "external_webpage"
    EXTERNAL_EMAIL = "external_email"
    DOWNLOAD = "download"
    MCP_RESPONSE = "mcp_response"
    API_RESPONSE = "api_response"
    INTERNAL = "internal"


class PaymentState(str, Enum):
    """Explicit payment transaction state machine."""
    CREATED = "CREATED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    AUTHORIZED = "AUTHORIZED"
    CHECKOUT_PENDING = "CHECKOUT_PENDING"
    PROCESSING = "PROCESSING"
    PAID = "PAID"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    REFUNDED = "REFUNDED"
    BLOCKED = "BLOCKED"


# Valid state transitions — prevents arbitrary jumps to PAID
VALID_PAYMENT_TRANSITIONS: dict[PaymentState, set[PaymentState]] = {
    PaymentState.CREATED: {
        PaymentState.APPROVAL_PENDING,
        PaymentState.BLOCKED,
        PaymentState.EXPIRED,
    },
    PaymentState.APPROVAL_PENDING: {
        PaymentState.AUTHORIZED,
        PaymentState.BLOCKED,
        PaymentState.EXPIRED,
        PaymentState.CANCELLED,
    },
    PaymentState.AUTHORIZED: {
        PaymentState.CHECKOUT_PENDING,
        PaymentState.CANCELLED,
        PaymentState.EXPIRED,
    },
    PaymentState.CHECKOUT_PENDING: {
        PaymentState.PROCESSING,
        PaymentState.FAILED,
        PaymentState.EXPIRED,
        PaymentState.CANCELLED,
    },
    PaymentState.PROCESSING: {
        PaymentState.PAID,
        PaymentState.FAILED,
    },
    PaymentState.PAID: {
        PaymentState.REFUNDED,
    },
    PaymentState.FAILED: set(),
    PaymentState.EXPIRED: set(),
    PaymentState.CANCELLED: set(),
    PaymentState.REFUNDED: set(),
    PaymentState.BLOCKED: set(),
}


def is_valid_transition(current: PaymentState, next_state: PaymentState) -> bool:
    return next_state in VALID_PAYMENT_TRANSITIONS.get(current, set())
