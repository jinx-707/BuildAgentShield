"""
Redirect chain validator — validates every hop in a redirect chain for SSRF.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.capabilities.online.browser.url_validator import validate_url
from app.core.exceptions import RedirectViolationError, SSRFAttemptError, URLValidationError

logger = logging.getLogger(__name__)

MAX_REDIRECTS = 5


async def validate_redirect_chain(
    url: str,
    allowed_schemes: list[str] | None = None,
    domain_allowlist: list[str] | None = None,
    domain_blocklist: list[str] | None = None,
    allowed_ports: list[int] | None = None,
    max_redirects: int = MAX_REDIRECTS,
) -> dict[str, Any]:
    """
    Follow and validate every redirect hop for the given URL.

    Returns:
        {"final_url": str, "hops": list[str], "hop_count": int}

    Raises:
        RedirectViolationError if any redirect destination is unsafe.
    """
    current_url = url
    hops: list[str] = [url]

    # Validate the initial URL
    validate_url(
        current_url,
        allowed_schemes=allowed_schemes,
        domain_allowlist=domain_allowlist,
        domain_blocklist=domain_blocklist,
        allowed_ports=allowed_ports,
    )

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0),
            verify=True,
        ) as client:
            for _ in range(max_redirects):
                resp = await client.get(current_url)
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break

                location = resp.headers.get("location", "")
                if not location:
                    break

                # Resolve relative redirect
                if location.startswith("/"):
                    from urllib.parse import urlparse, urlunparse
                    parsed = urlparse(current_url)
                    location = urlunparse((
                        parsed.scheme, parsed.netloc, location, "", "", ""
                    ))

                try:
                    validate_url(
                        location,
                        allowed_schemes=allowed_schemes,
                        domain_allowlist=domain_allowlist,
                        domain_blocklist=domain_blocklist,
                        allowed_ports=allowed_ports,
                    )
                except (SSRFAttemptError, URLValidationError) as e:
                    raise RedirectViolationError(
                        f"Redirect to unsafe destination blocked: {location} — {e}"
                    ) from e

                hops.append(location)
                current_url = location
            else:
                raise RedirectViolationError(
                    f"Too many redirects (>{max_redirects}) following: {url}"
                )
    except (httpx.ConnectError, httpx.TimeoutException):
        # Network errors during redirect probing — return what we have
        logger.debug("Redirect probe network error for %s (non-fatal)", url)

    return {
        "final_url": current_url,
        "hops": hops,
        "hop_count": len(hops) - 1,
    }
