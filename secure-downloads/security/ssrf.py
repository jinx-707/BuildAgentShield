"""
SSRF guard: DNS resolution and IP-policy validation.

This module provides the preflight DNS check used by DownloadPreflight.
Connection-level re-validation is provided separately by
DnsRevalidatingTransport (see security/dns_revalidation.py).

Enforcement model
------------------
1. Preflight check (SsrfGuard.resolve_and_validate)
   Resolves the hostname and verifies all returned A/AAA records against
   the IP policy before any network activity.  Catches blocked destinations
   early and rejects the request before it reaches the network layer.

2. Connection-level re-validation (DnsRevalidatingTransport)
   Wraps the httpx transport and re-resolves the hostname before each request
   (including redirect destinations), rejecting the request if any answer is
   blocked.  This is a second *lookup*, not pinning: the addresses validated
   here are not the addresses the socket connects to.  The underlying transport
   resolves the name again on its own, so a DNS answer that changes between
   this check and that lookup is not caught.

3. Egress proxy enforcement (when configured)
   The egress proxy independently resolves DNS and validates IPs at TCP
   connection time.  On the proxied path the proxy — not this process — is the
   authoritative enforcement boundary, because the proxy is the party that
   actually opens the connection.  Checks 1 and 2 are defence-in-depth.

A DNS preflight check followed by an ordinary HTTP request through the OS
resolver is NOT sufficient because DNS rebinding can change the resolution
between the check and the connection.  Re-validation shrinks that window to a
few milliseconds; eliminating it requires resolving once and connecting to the
validated address, which the current httpx transport stack does not do.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field

from security.errors import (
    DNS_RESOLUTION_FAILED,
    PRIVATE_IP_BLOCKED,
    SSRF_BLOCKED,
    DownloadSecurityError,
)
from security.ip_policy import is_blocked_ip, parse_ip
from security.url_validator import ValidatedDownloadUrl


@dataclass
class ResolvedAddresses:
    hostname: str
    addresses: list[str] = field(default_factory=list)


class DnsResolverProtocol:
    """Protocol for DNS resolution — injectable for tests."""

    async def resolve(self, hostname: str) -> list[str]:
        raise NotImplementedError


class SystemDnsResolver(DnsResolverProtocol):
    """Resolves hostnames using the system resolver (getaddrinfo via asyncio)."""

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self._timeout = timeout_seconds

    async def resolve(self, hostname: str) -> list[str]:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self._resolve_sync, hostname),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            raise DownloadSecurityError(
                DNS_RESOLUTION_FAILED,
                f"DNS resolution for {hostname!r} timed out.",
            ) from exc
        except Exception as exc:
            raise DownloadSecurityError(
                DNS_RESOLUTION_FAILED,
                f"DNS resolution for {hostname!r} failed: {exc}",
            ) from exc
        return result

    @staticmethod
    def _resolve_sync(hostname: str) -> list[str]:
        results = socket.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        seen: list[str] = []
        for r in results:
            addr = r[4][0]
            if addr not in seen:
                seen.append(addr)
        return seen


class SsrfGuard:
    """
    Validates that a download URL is safe to connect to.

    This is the preflight check.  Connection-level re-validation is provided
    separately by DnsRevalidatingTransport (security/dns_revalidation.py),
    which resolves and validates again immediately before each request.

    Usage
    -----
    guard = SsrfGuard(resolver=SystemDnsResolver())
    resolved = await guard.resolve_and_validate(validated_url)
    # resolved.addresses contains the validated IPs from the preflight check.
    # DnsRevalidatingTransport re-checks resolution before dispatch; neither
    # step hands these addresses to the socket.
    """

    def __init__(
        self,
        *,
        resolver: DnsResolverProtocol | None = None,
        allow_private_networks: bool = False,
    ) -> None:
        self._resolver = resolver or SystemDnsResolver()
        self._allow_private = allow_private_networks

    async def resolve_and_validate(
        self, validated_url: ValidatedDownloadUrl
    ) -> ResolvedAddresses:
        """
        Resolve the hostname and validate every returned IP address.

        For literal-IP targets the URL validator already checked the address;
        here we just wrap it into a ResolvedAddresses for consistency.

        Returns ResolvedAddresses with all safe, validated IP strings.
        Raises DownloadSecurityError if any address is blocked.
        """
        hostname = validated_url.hostname

        if validated_url.is_ip:
            # Hostname is already a literal IP; validate it again for clarity.
            if is_blocked_ip(hostname, allow_private=self._allow_private):
                raise DownloadSecurityError(
                    PRIVATE_IP_BLOCKED,
                    "The target IP address is in a restricted range.",
                )
            return ResolvedAddresses(hostname=hostname, addresses=[hostname])

        addresses = await self._resolver.resolve(hostname)

        if not addresses:
            raise DownloadSecurityError(
                DNS_RESOLUTION_FAILED,
                f"The hostname {hostname!r} could not be resolved.",
            )

        for addr in addresses:
            if is_blocked_ip(addr, allow_private=self._allow_private):
                raise DownloadSecurityError(
                    PRIVATE_IP_BLOCKED,
                    f"The hostname {hostname!r} resolves to a restricted address "
                    f"({addr}). Request rejected to prevent SSRF.",
                )

        return ResolvedAddresses(hostname=hostname, addresses=addresses)

    async def validate_redirect(
        self, redirect_url_str: str, *, validator: object
    ) -> ValidatedDownloadUrl:
        """
        Validate a redirect destination URL with the same rules as the original.

        Every redirect target is treated as a fresh, untrusted URL and goes
        through the full URL validator + SSRF check.  This prevents open-redirect
        exploitation where the original URL is allowed but the final destination
        is not.
        """
        from security.url_validator import DownloadUrlValidator

        if not isinstance(validator, DownloadUrlValidator):
            raise TypeError("validator must be a DownloadUrlValidator")

        validated = validator.validate(redirect_url_str)
        await self.resolve_and_validate(validated)
        return validated
