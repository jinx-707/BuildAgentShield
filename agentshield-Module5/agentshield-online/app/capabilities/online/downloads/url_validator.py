"""
Download-specific URL validator (reuses browser url_validator with download settings).
"""
from __future__ import annotations

from typing import Any

from app.capabilities.online.browser.url_validator import validate_url
from app.core.exceptions import SSRFAttemptError, URLValidationError


def validate_download_url(
    url: str,
    domain_allowlist: list[str] | None = None,
    domain_blocklist: list[str] | None = None,
) -> dict[str, Any]:
    """
    Validate a URL for safe downloading.
    Only https and http are allowed.
    Private IPs and cloud metadata are always blocked.
    """
    return validate_url(
        url=url,
        allowed_schemes=["https", "http"],
        domain_allowlist=domain_allowlist,
        domain_blocklist=domain_blocklist,
        resolve_dns=True,
    )
