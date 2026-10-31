"""Module-specific exceptions for secure downloads.

These are configuration, lifecycle, storage, tenant-boundary, and network-security failures.
They are not HTTP exceptions and do not implement file scanning.
"""

from __future__ import annotations


class DownloadError(ValueError):
    """Base error for the downloads package."""


class DownloadSettingsError(DownloadError):
    """Invalid or unsafe download-module configuration."""


class InvalidStateTransitionError(DownloadError):
    """Raised when a download lifecycle transition is not permitted."""


class StatusZoneConstraintError(DownloadError):
    """Raised when lifecycle status and storage zone are inconsistent."""


class StorageError(DownloadError):
    """Invalid storage operation or isolation violation."""


class TenantIsolationError(DownloadError):
    """Raised when a download is accessed outside its tenant/agent boundary."""


class FilenameError(DownloadError):
    """Raised when a user-supplied filename cannot be safely retained as metadata."""


# ── Phase C: network-security errors ─────────────────────────────────────────


class NetworkSecurityError(DownloadError):
    """Base class for all network/SSRF security violations.

    Attributes
    ----------
    code:
        Machine-readable error code (e.g. ``INVALID_URL``).
    message:
        Human-readable description suitable for logging (not exposed to
        external callers verbatim).
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:  # pragma: no cover
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


class InvalidURLError(NetworkSecurityError):
    """The supplied URL is malformed, uses an unsupported scheme, contains
    embedded credentials, or cannot be normalised safely."""


class SSRFBlockedError(NetworkSecurityError):
    """The destination address is in a prohibited range (loopback, private,
    link-local, cloud-metadata, etc.)."""


class DNSResolutionError(NetworkSecurityError):
    """The hostname could not be resolved or returned an empty answer."""


class DNSRebindingError(NetworkSecurityError):
    """DNS returned a mix of public and prohibited addresses."""


class RedirectError(NetworkSecurityError):
    """A redirect was refused (loop, limit exceeded, unsafe target, scheme
    downgrade, or sensitive-header leak)."""


class ConnectionPinningError(NetworkSecurityError):
    """The HTTP connection could not be bound to the validated IP address."""


# ── Canonical error codes ─────────────────────────────────────────────────────

INVALID_URL = "INVALID_URL"
UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
EMBEDDED_CREDENTIALS = "EMBEDDED_CREDENTIALS"
INVALID_PORT = "INVALID_PORT"
AMBIGUOUS_HOST = "AMBIGUOUS_HOST"

SSRF_BLOCKED = "SSRF_BLOCKED"
LOOPBACK_BLOCKED = "LOOPBACK_BLOCKED"
PRIVATE_RANGE_BLOCKED = "PRIVATE_RANGE_BLOCKED"
LINK_LOCAL_BLOCKED = "LINK_LOCAL_BLOCKED"
CLOUD_METADATA_BLOCKED = "CLOUD_METADATA_BLOCKED"
RESERVED_HOSTNAME_BLOCKED = "RESERVED_HOSTNAME_BLOCKED"
UNSPECIFIED_ADDRESS_BLOCKED = "UNSPECIFIED_ADDRESS_BLOCKED"
MULTICAST_BLOCKED = "MULTICAST_BLOCKED"
IPV4_MAPPED_BLOCKED = "IPV4_MAPPED_BLOCKED"

DNS_RESOLUTION_FAILED = "DNS_RESOLUTION_FAILED"
DNS_EMPTY_RESPONSE = "DNS_EMPTY_RESPONSE"
DNS_MIXED_RESPONSE = "DNS_MIXED_RESPONSE"

REDIRECT_LOOP = "REDIRECT_LOOP"
REDIRECT_LIMIT_EXCEEDED = "REDIRECT_LIMIT_EXCEEDED"
REDIRECT_UNSAFE_TARGET = "REDIRECT_UNSAFE_TARGET"
REDIRECT_SCHEME_DOWNGRADE = "REDIRECT_SCHEME_DOWNGRADE"
REDIRECT_MISSING_LOCATION = "REDIRECT_MISSING_LOCATION"

CONNECTION_PIN_FAILED = "CONNECTION_PIN_FAILED"
