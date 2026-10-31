"""Module 3 — Secure File Downloads.

Phase B: persistence, configuration, lifecycle constraints, and storage zones.
Phase C: URL validation, DNS resolution, SSRF protection, DNS pinning, and
         redirect security.
"""

from app.downloads.config import DownloadSettings, get_download_settings
from app.downloads.dns_resolver import ResolvedTarget, SecureDNSResolver
from app.downloads.enums import DownloadStatus, StorageZone
from app.downloads.exceptions import (
    ConnectionPinningError,
    DNSRebindingError,
    DNSResolutionError,
    DownloadError,
    DownloadSettingsError,
    FilenameError,
    InvalidStateTransitionError,
    InvalidURLError,
    NetworkSecurityError,
    RedirectError,
    SSRFBlockedError,
    StorageError,
    TenantIsolationError,
)
from app.downloads.ip_policy import assert_ip_allowed, check_address_string, is_ip_allowed
from app.downloads.models import SecureDownload
from app.downloads.pinned_transport import PinnedTransport, build_pinned_client
from app.downloads.redirect_handler import DownloadFetcher, RedirectHandler
from app.downloads.storage import StorageZones, ensure_storage_zones, sanitize_filename
from app.downloads.url_validator import URLValidator, ValidatedURL

__all__ = [
    # Phase B
    "DownloadError",
    "DownloadSettings",
    "DownloadSettingsError",
    "DownloadStatus",
    "FilenameError",
    "InvalidStateTransitionError",
    "SecureDownload",
    "StorageError",
    "StorageZone",
    "StorageZones",
    "TenantIsolationError",
    "ensure_storage_zones",
    "get_download_settings",
    "sanitize_filename",
    # Phase C
    "ConnectionPinningError",
    "DNSRebindingError",
    "DNSResolutionError",
    "DownloadFetcher",
    "InvalidURLError",
    "NetworkSecurityError",
    "PinnedTransport",
    "RedirectError",
    "RedirectHandler",
    "ResolvedTarget",
    "SSRFBlockedError",
    "SecureDNSResolver",
    "URLValidator",
    "ValidatedURL",
    "assert_ip_allowed",
    "build_pinned_client",
    "check_address_string",
    "is_ip_allowed",
]
