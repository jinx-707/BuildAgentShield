"""
Download redirect validator — validates each redirect hop.
"""
from __future__ import annotations

from app.capabilities.online.browser.redirect_validator import validate_redirect_chain


async def validate_download_redirects(
    url: str,
    max_redirects: int = 3,
    domain_allowlist: list[str] | None = None,
    domain_blocklist: list[str] | None = None,
) -> dict:
    """Validate redirect chain for a download URL."""
    return await validate_redirect_chain(
        url=url,
        allowed_schemes=["https", "http"],
        domain_allowlist=domain_allowlist,
        domain_blocklist=domain_blocklist,
        max_redirects=max_redirects,
    )
