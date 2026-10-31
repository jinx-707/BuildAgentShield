"""Secure DNS resolution for file downloads.

Resolves A and AAAA records, validates every returned address, and detects
mixed public/private DNS answers (DNS rebinding).

The resolver returns a :class:`ResolvedTarget` containing the validated
destination IP, the original hostname (for TLS SNI and Host headers), and the
port.  Callers must use :attr:`ResolvedTarget.address` for the actual socket
connection and :attr:`ResolvedTarget.hostname` for TLS negotiation — these must
never be swapped.

Design notes
------------
* All returned addresses are validated.  A single prohibited address in a
  mixed answer causes the entire response to be rejected (``DNS_MIXED_RESPONSE``).
* Empty DNS answers are a hard failure, not a soft "not found".
* DNS errors are caught and re-raised as :class:`DNSResolutionError` so the
  caller never observes a raw ``socket.gaierror``.
* The resolver protocol is injectable so tests can supply a fake without
  patching ``socket``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from app.downloads.exceptions import (
    DNS_EMPTY_RESPONSE,
    DNS_MIXED_RESPONSE,
    DNS_RESOLUTION_FAILED,
    DNSRebindingError,
    DNSResolutionError,
    SSRFBlockedError,
)
from app.downloads.ip_policy import assert_ip_allowed, parse_ip
from app.downloads.url_validator import ValidatedURL


@dataclass(frozen=True)
class ResolvedTarget:
    """A DNS-validated connection target.

    Attributes
    ----------
    hostname:
        The original hostname.  Use for TLS SNI and HTTP ``Host`` headers.
        **Never** use this for the socket connect() call.
    address:
        The validated IP address string (IPv4 or IPv6).  Use exclusively for
        the actual socket connection.  Never re-resolve ``hostname`` for the
        connection.
    port:
        Destination port.
    scheme:
        ``"https"`` or ``"http"``.
    normalized_url:
        The original normalized URL (from URL validation), for reference only.
    """

    hostname: str
    address: str
    port: int
    scheme: str
    normalized_url: str


@runtime_checkable
class DNSResolverProtocol(Protocol):
    """Injectable DNS resolver.  Implementations must return all A/AAAA records."""

    async def resolve(self, hostname: str) -> list[str]:
        """Return a list of IP address strings for *hostname*.

        Raises any exception on resolution failure; callers handle it.
        """
        ...


class SystemDNSResolver:
    """Real DNS resolver backed by ``socket.getaddrinfo``.

    Uses :func:`asyncio.to_thread` to avoid blocking the event loop.
    """

    async def resolve(self, hostname: str) -> list[str]:
        return await asyncio.to_thread(self._resolve_sync, hostname)

    @staticmethod
    def _resolve_sync(hostname: str) -> list[str]:
        try:
            results = socket.getaddrinfo(
                hostname,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise DNSResolutionError(
                DNS_RESOLUTION_FAILED,
                f"DNS resolution failed for {hostname!r}: {exc}",
            ) from exc

        seen: list[str] = []
        for result in results:
            addr = result[4][0]
            if addr not in seen:
                seen.append(addr)
        return seen


class SecureDNSResolver:
    """Validates every address returned by DNS and detects rebinding attacks.

    Parameters
    ----------
    resolver:
        The underlying DNS resolver.  Defaults to :class:`SystemDNSResolver`.
    """

    def __init__(self, *, resolver: DNSResolverProtocol | None = None) -> None:
        self._resolver: DNSResolverProtocol = resolver or SystemDNSResolver()

    async def resolve(self, validated_url: ValidatedURL) -> ResolvedTarget:
        """Resolve the hostname in *validated_url* and return a
        :class:`ResolvedTarget` with a single validated address.

        Raises
        ------
        DNSResolutionError
            The hostname could not be resolved or returned an empty answer.
        SSRFBlockedError
            Every resolved address is validated; a single blocked address
            causes the whole resolution to fail.
        DNSRebindingError
            The DNS answer contained a mix of allowed and blocked addresses
            (rebinding simulation).
        """
        hostname = validated_url.hostname

        # IP literals were validated syntactically by URLValidator; we just
        # confirm the address is allowed and skip DNS.
        if validated_url.is_ip:
            addr = parse_ip(hostname)
            if addr is None:
                raise DNSResolutionError(
                    DNS_RESOLUTION_FAILED,
                    f"Cannot parse IP literal {hostname!r}",
                )
            try:
                assert_ip_allowed(addr)
            except SSRFBlockedError:
                raise
            return ResolvedTarget(
                hostname=hostname,
                address=str(addr),
                port=validated_url.port,
                scheme=validated_url.scheme,
                normalized_url=validated_url.normalized_url,
            )

        # Perform DNS resolution.
        try:
            raw_addresses = await self._resolver.resolve(hostname)
        except (DNSResolutionError, SSRFBlockedError):
            raise
        except Exception as exc:
            raise DNSResolutionError(
                DNS_RESOLUTION_FAILED,
                f"Unexpected error resolving {hostname!r}: {exc}",
            ) from exc

        if not raw_addresses:
            raise DNSResolutionError(
                DNS_EMPTY_RESPONSE,
                f"DNS returned no addresses for {hostname!r}",
            )

        # Validate every resolved address.
        allowed: list[str] = []
        blocked: list[str] = []

        for raw in raw_addresses:
            addr = parse_ip(raw)
            if addr is None:
                # Unparseable address — treat as blocked.
                blocked.append(raw)
                continue
            try:
                assert_ip_allowed(addr)
                allowed.append(str(addr))
            except SSRFBlockedError:
                blocked.append(raw)

        # Mixed answer: rebinding attack.  Reject entirely.
        if allowed and blocked:
            raise DNSRebindingError(
                DNS_MIXED_RESPONSE,
                f"DNS answer for {hostname!r} contains both public and prohibited addresses "
                f"(allowed={allowed}, blocked={blocked}); possible rebinding attack",
            )

        # All addresses are blocked.
        if not allowed:
            # Re-raise the error from the first blocked address so we propagate
            # the specific code (loopback/private/metadata).
            first = parse_ip(raw_addresses[0])
            if first is not None:
                assert_ip_allowed(first)  # always raises
            raise DNSResolutionError(
                DNS_RESOLUTION_FAILED,
                f"All DNS answers for {hostname!r} resolve to prohibited addresses",
            )

        # Use the first validated address (prefer IPv4 for connection pinning
        # predictability, but do not re-sort — preserve resolver order).
        chosen = allowed[0]

        # Final parse to get canonical form.
        final_addr = parse_ip(chosen)
        if final_addr is None:
            raise DNSResolutionError(
                DNS_RESOLUTION_FAILED,
                f"Cannot re-parse validated address {chosen!r}",
            )

        return ResolvedTarget(
            hostname=hostname,
            address=str(final_addr),
            port=validated_url.port,
            scheme=validated_url.scheme,
            normalized_url=validated_url.normalized_url,
        )
