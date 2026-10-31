"""
Egress-proxy attestation: verify the proxy is in enforcing mode.

What this module provides
-------------------------
* ``assert_proxy_enforcing(health_url)`` — fetches the proxy's health endpoint
  and requires ``status == "ok"`` and ``mode == "enforcing"``.  Anything else
  (non-200, unreadable JSON, degraded status, a missing ``mode`` field, or any
  mode other than ``enforcing``) raises
  ``DownloadSecurityError(EGRESS_PROXY_UNAVAILABLE)``.
* ``EnforcingProxyTransport`` — an httpx transport that runs that check before
  every request, with a short result cache so a download does not issue one
  health request per redirect.

What this actually guarantees
-----------------------------
This verifies the proxy's *self-reported* state.  It is an attestation check,
not enforcement: a proxy that reports ``mode="enforcing"`` while forwarding
traffic without policy checks cannot be detected from here.  The real IP/domain
policy enforcement on the proxied path lives in the proxy itself.

What it protects against is the failure mode that matters operationally: the
proxy being down, misconfigured into a permissive/passthrough mode, or having
flipped out of enforcing mode *during* a download.  Without the per-request
check, a proxy that was enforcing at preflight time could go permissive and the
remainder of the download would still be sent through it.

Fail-closed rule
----------------
``DownloadStreamer`` refuses to run when ``require_proxy`` is set and no health
URL is configured, because there would then be no way to confirm the proxy's
mode.  ``EnforcingProxyTransport`` with an empty ``health_url`` performs no
check — it is only ever constructed with a non-empty one.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

from security.errors import EGRESS_PROXY_UNAVAILABLE, DownloadSecurityError

logger = logging.getLogger(__name__)

# Default lifetime of a successful attestation result.
DEFAULT_HEALTH_CACHE_TTL_SECONDS = 5.0
HEALTH_CHECK_TIMEOUT_SECONDS = 5.0

# A health document is a small JSON object.  Bounding the read keeps a
# compromised or malfunctioning proxy from turning attestation into a memory
# exhaustion vector.
_MAX_HEALTH_RESPONSE_BYTES = 64 * 1024


def _evaluate_health_payload(body: Any) -> None:
    """Raise unless the payload reports a healthy, explicitly enforcing proxy."""
    if not isinstance(body, dict):
        raise DownloadSecurityError(
            EGRESS_PROXY_UNAVAILABLE,
            "Egress proxy health response is not a JSON object.",
        )

    if body.get("status") != "ok":
        raise DownloadSecurityError(
            EGRESS_PROXY_UNAVAILABLE,
            "Egress proxy reports degraded status.",
        )

    # Fail closed: the mode field must be present and must say "enforcing".
    # A proxy that does not advertise its mode cannot be trusted to enforce it.
    mode = body.get("mode")
    if mode != "enforcing":
        raise DownloadSecurityError(
            EGRESS_PROXY_UNAVAILABLE,
            f"Egress proxy is not enforcing (mode={mode!r}). "
            f"Download blocked to prevent bypass.",
        )


async def assert_proxy_enforcing(
    health_url: str,
    *,
    timeout: float = HEALTH_CHECK_TIMEOUT_SECONDS,
) -> None:
    """
    Check the egress proxy health endpoint and require enforcing mode.

    Raises DownloadSecurityError(EGRESS_PROXY_UNAVAILABLE) on any failure,
    including an unreachable endpoint or a payload without an enforcing mode.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            async with client.stream(
                "GET", health_url, follow_redirects=False
            ) as resp:
                if resp.status_code != 200:
                    raise DownloadSecurityError(
                        EGRESS_PROXY_UNAVAILABLE,
                        f"Egress proxy health check returned HTTP {resp.status_code}.",
                    )

                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > _MAX_HEALTH_RESPONSE_BYTES:
                        raise DownloadSecurityError(
                            EGRESS_PROXY_UNAVAILABLE,
                            "Egress proxy health response is too large.",
                        )
                    chunks.append(chunk)

                try:
                    body = json.loads(b"".join(chunks))
                except ValueError as exc:
                    raise DownloadSecurityError(
                        EGRESS_PROXY_UNAVAILABLE,
                        "Egress proxy health response is not valid JSON.",
                    ) from exc
    except httpx.HTTPError as exc:
        # Do not interpolate the transport exception: it can contain the health
        # URL, which may embed proxy credentials.
        raise DownloadSecurityError(
            EGRESS_PROXY_UNAVAILABLE,
            f"Egress proxy health check failed ({type(exc).__name__}).",
        ) from exc

    _evaluate_health_payload(body)


class EnforcingProxyTransport(httpx.AsyncBaseTransport):
    """
    Wraps an httpx proxy transport and verifies proxy enforcement mode before
    each request.

    Parameters
    ----------
    wrapped:          The underlying httpx transport to delegate to.
    health_url:       The proxy health endpoint URL.
    health_cache_ttl: How long to cache a successful check (seconds).
    """

    def __init__(
        self,
        *,
        wrapped: httpx.AsyncBaseTransport,
        health_url: str,
        health_cache_ttl: float = DEFAULT_HEALTH_CACHE_TTL_SECONDS,
    ) -> None:
        self._wrapped = wrapped
        self._health_url = health_url
        self._cache_ttl = health_cache_ttl
        self._cache_time: float = 0.0
        self._cache_ok: bool = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await self._verify_enforcing()
        return await self._wrapped.handle_async_request(request)

    async def aclose(self) -> None:
        await self._wrapped.aclose()

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _verify_enforcing(self) -> None:
        """Check the proxy health endpoint, cached with a short TTL."""
        if not self._health_url:
            # No attestation endpoint: nothing to verify.  DownloadStreamer
            # refuses to build this configuration when a proxy is required.
            logger.warning("proxy_attestation_skipped", extra={"reason": "no health_url"})
            return

        now = time.monotonic()
        if self._cache_ok and (now - self._cache_time) < self._cache_ttl:
            return

        await assert_proxy_enforcing(self._health_url)

        # Only successful checks are cached; failures are never memoised.
        self._cache_time = now
        self._cache_ok = True
