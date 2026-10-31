"""Trusted-proxy client identity resolution.

The direct TCP peer is authoritative. ``X-Forwarded-For`` is consulted only
when that peer is an operator-configured trusted proxy, and only the rightmost
untrusted address in the chain is accepted as the client. The leftmost entries
are never selected blindly because they are fully caller-controlled.

The proxy deployment must append the address it observed, not forward a
client-supplied header unchanged. This module cannot detect a proxy that
violates that contract.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_XFF_HEADER = "x-forwarded-for"
_MAX_ADDRESS_LENGTH = 64


class InvalidForwardedAddress(ValueError):
    """Raised when a trusted proxy supplies a malformed forwarding chain."""

    code = "INVALID_FORWARDED_FOR"
    status_code = 400

    def __init__(self, message: str = "the forwarded client address is invalid") -> None:
        super().__init__(message)


@dataclass(frozen=True)
class ClientIdentity:
    """The effective client address and how it was established."""

    address: str
    source: str
    trusted_proxy: bool = False
    forwarded_chain: tuple[str, ...] = ()

    @property
    def is_forwarded(self) -> bool:
        return self.source == "forwarded"


def parse_trusted_proxies(value: str) -> tuple[IPNetwork, ...]:
    """Parse a comma-separated IP/CIDR list.

    A bare IP is treated as a single-host network. Invalid entries fail startup
    rather than silently widening or narrowing the trust boundary.
    """

    networks: list[IPNetwork] = []
    for raw_part in str(value or "").split(","):
        part = raw_part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise ValueError(
                f"invalid trusted proxy network: {part!r}"
            ) from exc
    return tuple(networks)


def _parse_address(value: str, *, field: str) -> IPAddress:
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > _MAX_ADDRESS_LENGTH
        or "%" in candidate
        or "[" in candidate
        or "]" in candidate
    ):
        raise InvalidForwardedAddress(f"{field} is not a valid IP address")
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise InvalidForwardedAddress(f"{field} is not a valid IP address") from exc

    # Normalise IPv4-mapped IPv6 so 127.0.0.0/8 matches ::ffff:127.0.0.1.
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def _is_trusted(address: IPAddress, networks: Iterable[IPNetwork]) -> bool:
    return any(
        address.version == network.version and address in network
        for network in networks
    )


def _forwarded_chain(header: str | None, *, max_hops: int) -> tuple[IPAddress, ...]:
    if header is None:
        return ()
    parts = [part.strip() for part in header.split(",")]
    if not parts or any(not part for part in parts):
        raise InvalidForwardedAddress()
    if len(parts) > max_hops:
        raise InvalidForwardedAddress("the forwarded chain is too long")
    return tuple(
        _parse_address(part, field="forwarded address") for part in parts
    )


def resolve_client_identity(
    peer: str | None,
    forwarded_for: str | None,
    *,
    trusted_proxies: tuple[IPNetwork, ...] = (),
    max_hops: int = 10,
) -> ClientIdentity:
    """Return the effective client identity for rate-limit bucketing.

    - No trusted proxies: the direct peer is used and XFF is ignored.
    - Untrusted peer: the direct peer is used and XFF is ignored.
    - Trusted peer: XFF is parsed; walk right-to-left while the current address
      is itself a trusted proxy. The first non-trusted address is the client.
    """

    peer_raw = (peer or "").strip() or "unknown"
    try:
        peer_address = _parse_address(peer_raw, field="direct peer")
    except InvalidForwardedAddress:
        # Test transports and unusual ASGI servers may not expose an IP. With
        # no configured proxies this is a safe opaque bucket; with proxies
        # configured it is never eligible for forwarded trust.
        return ClientIdentity(address=peer_raw, source="direct")

    if not trusted_proxies or not _is_trusted(peer_address, trusted_proxies):
        return ClientIdentity(address=str(peer_address), source="direct")

    chain = _forwarded_chain(forwarded_for, max_hops=max_hops)
    if not chain:
        return ClientIdentity(
            address=str(peer_address),
            source="direct",
            trusted_proxy=True,
        )

    candidate = peer_address
    index = len(chain) - 1
    while index >= 0 and _is_trusted(candidate, trusted_proxies):
        candidate = chain[index]
        index -= 1

    return ClientIdentity(
        address=str(candidate),
        source="forwarded",
        trusted_proxy=True,
        forwarded_chain=tuple(str(item) for item in chain),
    )
