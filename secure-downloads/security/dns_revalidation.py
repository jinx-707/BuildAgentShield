"""
Connection-level DNS re-validation for httpx.

What this module actually does
------------------------------
``DnsRevalidatingTransport`` wraps an ``httpx.AsyncBaseTransport`` and, before
each request is dispatched, resolves the request hostname again and validates
every A/AAAA record against the IP policy.  If any address is blocked the
request is rejected with ``DownloadSecurityError`` and the wrapped transport is
never called.

This is a *gate check*, not DNS pinning.  The validated addresses are
deliberately discarded (see "Why the validated addresses are not used" below).
The wrapped transport performs its own, independent name resolution when it
opens the TCP connection.

What this does NOT do
---------------------
It does **not** pin the connection to a validated IP, and therefore does not
eliminate the DNS-rebinding (TOCTOU) window.  Between the moment this check
returns and the moment the underlying stack resolves the name for ``connect()``,
a hostile or unstable authoritative nameserver can return a different answer.
The window is milliseconds rather than the whole preflight-plus-connect
sequence, which is a meaningful reduction — but it is not zero, and a
sufficiently short-TTL / round-robin rebinding target can still land the
connection on an address that was never validated.  In that case the connection
goes to an address the policy never approved, and nothing in this module stops
it.

Why the validated addresses are not used
----------------------------------------
Rewriting the request URL to an IP literal would change the value httpx and
httpcore derive for:
  * the TLS ``server_hostname`` (SNI and certificate hostname verification),
  * the HTTP ``Host`` header,
  * the authority used by an egress proxy when it applies its own domain
    policy and when it opens the CONNECT tunnel.
Preserving those would require per-request SNI overrides and a different
connection path (see the feasibility analysis in README "Connection security
model").  That is not implemented here, so this module makes no pinning claim.

Redirects
---------
The downloader follows redirects manually (``follow_redirects=False``) and runs
the full preflight on every destination.  This transport adds a second check at
dispatch time, so a redirect destination is validated twice.

Placement in the transport chain
--------------------------------
``DownloadStreamer`` builds the chain as

    EnforcingProxyTransport(DnsRevalidatingTransport(AsyncHTTPTransport(proxy=...)))

so both the proxy-attestation check and the DNS re-validation run per request.
"""
from __future__ import annotations

import logging
from typing import Protocol

import httpx

from security.errors import PRIVATE_IP_BLOCKED, DownloadSecurityError
from security.ip_policy import is_blocked_ip, parse_ip
from security.ssrf import SsrfGuard
from security.url_validator import ValidatedDownloadUrl

logger = logging.getLogger(__name__)


class DnsRevalidatingTransport(httpx.AsyncBaseTransport):
    """
    Wraps an httpx transport and re-resolves + re-validates DNS before each
    request is dispatched.

    Parameters
    ----------
    wrapped:        The underlying httpx transport to delegate to.
    ssrf_guard:     The SsrfGuard used for DNS resolution and IP validation.
    allow_private:  Whether private IPs are permitted (passed to is_blocked_ip).

    Residual gap: the wrapped transport resolves the hostname again on its own.
    A rebinding answer that arrives after this check, but before the socket
    connect, is not caught.  See the module docstring.
    """

    def __init__(
        self,
        *,
        wrapped: httpx.AsyncBaseTransport,
        ssrf_guard: SsrfGuard,
        allow_private: bool = False,
    ) -> None:
        self._wrapped = wrapped
        self._ssrf_guard = ssrf_guard
        self._allow_private = allow_private

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """
        Re-validate DNS for the request hostname before delegating.

        Raises DownloadSecurityError(PRIVATE_IP_BLOCKED) if the hostname
        resolves to any blocked IP at dispatch time.
        """
        hostname = self._extract_hostname(request)
        if hostname is not None:
            await self._validate_dns(hostname)

        return await self._wrapped.handle_async_request(request)

    async def aclose(self) -> None:
        await self._wrapped.aclose()

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_hostname(request: httpx.Request) -> str | None:
        """Extract the target hostname from the request URL."""
        host = request.url.host
        if host is None:
            return None
        # Normalize: strip brackets from IPv6, lowercase.
        host = host.strip("[]").lower()
        return host if host else None

    async def _validate_dns(self, hostname: str) -> None:
        """
        Re-resolve the hostname and validate every returned IP.

        A second lookup narrows the rebinding window; it does not close it,
        because the address actually connected to is resolved by the wrapped
        transport afterwards.

        For literal IP targets (already validated by the URL validator) no DNS
        lookup is needed — the IP policy is checked directly.
        """
        if parse_ip(hostname) is not None:
            # Literal IP target — validate directly without DNS.
            if is_blocked_ip(hostname, allow_private=self._allow_private):
                raise DownloadSecurityError(
                    PRIVATE_IP_BLOCKED,
                    f"Connection-time check: target IP {hostname!r} is in a "
                    f"restricted range.",
                )
            return

        # Hostname target — resolve and validate all A/AAAA records.
        try:
            resolved = await self._ssrf_guard.resolve_and_validate(
                ValidatedDownloadUrl(
                    url="",
                    scheme="https",
                    hostname=hostname,
                    port=443,
                    is_ip=False,
                )
            )
        except DownloadSecurityError:
            raise
        except Exception as exc:
            raise DownloadSecurityError(
                PRIVATE_IP_BLOCKED,
                f"Connection-time DNS validation failed for {hostname!r}: {exc}",
            ) from exc

        logger.debug(
            "dns_revalidation_ok",
            extra={
                "hostname": hostname,
                "addresses": resolved.addresses,
            },
        )
