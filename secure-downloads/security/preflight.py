"""
Download preflight check: URL validation + SSRF guard combined.

DownloadPreflight is the single entry point for all pre-download security
checks.  It combines:
  1. DownloadUrlValidator — syntactic URL validation.
  2. SsrfGuard            — DNS resolution and IP policy enforcement.

Returns a ValidatedDownloadUrl on success.  Raises DownloadSecurityError on
any violation.
"""
from __future__ import annotations

from security.ssrf import ResolvedAddresses, SsrfGuard
from security.url_validator import DownloadUrlValidator, ValidatedDownloadUrl


class DownloadPreflight:
    def __init__(
        self,
        *,
        url_validator: DownloadUrlValidator,
        ssrf_guard: SsrfGuard,
        dns_enabled: bool = True,
    ) -> None:
        self._validator = url_validator
        self._ssrf = ssrf_guard
        self._dns_enabled = dns_enabled

    async def validate(
        self, raw_url: str
    ) -> tuple[ValidatedDownloadUrl, ResolvedAddresses | None]:
        """
        Full pre-flight check on raw_url.

        Returns
        -------
        (ValidatedDownloadUrl, ResolvedAddresses | None)
        ResolvedAddresses is None when dns_enabled=False (test mode only).
        """
        validated = self._validator.validate(raw_url)
        resolved: ResolvedAddresses | None = None
        if self._dns_enabled:
            resolved = await self._ssrf.resolve_and_validate(validated)
        return validated, resolved
