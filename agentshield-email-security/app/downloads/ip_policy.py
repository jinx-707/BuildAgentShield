"""IP address SSRF-prevention policy for secure downloads.

Rejects loopback, private, link-local, unspecified, reserved, multicast, and
cloud-metadata addresses.  IPv4-mapped and transitional IPv6 addresses are
unwrapped before classification so they cannot bypass IPv4 checks.

This module is independent of the Browser Security service and carries no
cross-repository runtime dependency.
"""

from __future__ import annotations

import ipaddress
from typing import Union

from app.downloads.exceptions import (
    CLOUD_METADATA_BLOCKED,
    IPV4_MAPPED_BLOCKED,
    LINK_LOCAL_BLOCKED,
    LOOPBACK_BLOCKED,
    MULTICAST_BLOCKED,
    PRIVATE_RANGE_BLOCKED,
    SSRF_BLOCKED,
    UNSPECIFIED_ADDRESS_BLOCKED,
    SSRFBlockedError,
)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# ── Explicit high-value cloud-metadata targets ────────────────────────────────
# These are always blocked regardless of the allow_private flag.
_ALWAYS_BLOCKED_IPS: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset(
    {
        # AWS instance metadata
        ipaddress.ip_address("169.254.169.254"),
        # AWS ECS task metadata (alternative endpoint)
        ipaddress.ip_address("169.254.170.2"),
        # Alibaba Cloud metadata
        ipaddress.ip_address("100.100.100.200"),
        # GCP internal metadata IPv6
        ipaddress.ip_address("fd00:ec2::254"),
    }
)

# ── IPv6 transition/tunnel networks that encode IPv4 ─────────────────────────
# 6to4 (2002::/16), Teredo (2001::/32), and NAT64 (64:ff9b::/96) can wrap
# private IPv4 addresses.  We block the enclosing networks entirely.
_ALWAYS_BLOCKED_NETWORKS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("2002::/16"),   # 6to4
    ipaddress.IPv6Network("2001::/32"),   # Teredo
    ipaddress.IPv6Network("64:ff9b::/96"),  # NAT64 well-known prefix
)


def unwrap_ipv6(addr: ipaddress.IPv6Address) -> IPAddress:
    """Unwrap IPv4-mapped, 6to4, and Teredo IPv6 addresses to their IPv4 form.

    Returns the original address unchanged if no embedded IPv4 is present.
    """
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr.sixtofour is not None:
        return addr.sixtofour
    teredo = addr.teredo
    if teredo is not None:
        # teredo = (server, client); client is the mapped public address
        return teredo[1]
    return addr


def parse_ip(value: str) -> IPAddress | None:
    """Parse *value* as an IP address, unwrapping IPv6 transition forms.

    Returns ``None`` if *value* is not a valid IP address string.
    """
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address):
        return unwrap_ipv6(parsed)
    return parsed


def _block(code: str, detail: str) -> SSRFBlockedError:
    return SSRFBlockedError(code, detail)


def assert_ip_allowed(addr: IPAddress) -> None:
    """Raise :class:`SSRFBlockedError` if *addr* must not be contacted.

    Checks (in order):
    1. Explicit cloud-metadata singleton IPs.
    2. IPv6 transition/tunnel networks.
    3. Loopback.
    4. Unspecified (0.0.0.0 / ::).
    5. Multicast.
    6. Link-local.
    7. Reserved (IETF / documentation / protocol-specific ranges).
    8. Private (RFC-1918 / ULA).
    9. Not globally routable for any other reason.
    """
    if addr in _ALWAYS_BLOCKED_IPS:
        raise _block(CLOUD_METADATA_BLOCKED, f"Cloud metadata endpoint {addr} is blocked")

    # Check transition networks against the *original* IPv6 address object.
    # (parse_ip already unwraps, so we need the original IPv6 check here when
    # callers pass already-parsed objects.  We re-check via network membership.)
    if isinstance(addr, ipaddress.IPv6Address):
        for net in _ALWAYS_BLOCKED_NETWORKS:
            if addr in net:
                raise _block(
                    IPV4_MAPPED_BLOCKED,
                    f"IPv6 transition address {addr} in blocked network {net}",
                )

    if addr.is_loopback:
        raise _block(LOOPBACK_BLOCKED, f"Loopback address {addr} is blocked")

    if addr.is_unspecified:
        raise _block(UNSPECIFIED_ADDRESS_BLOCKED, f"Unspecified address {addr} is blocked")

    if addr.is_multicast:
        raise _block(MULTICAST_BLOCKED, f"Multicast address {addr} is blocked")

    if addr.is_link_local:
        raise _block(LINK_LOCAL_BLOCKED, f"Link-local address {addr} is blocked")

    if addr.is_reserved:
        raise _block(SSRF_BLOCKED, f"Reserved address {addr} is blocked")

    if addr.is_private:
        raise _block(PRIVATE_RANGE_BLOCKED, f"Private address {addr} is blocked")

    if not addr.is_global:
        raise _block(SSRF_BLOCKED, f"Non-globally-routable address {addr} is blocked")


def is_ip_allowed(value: str) -> bool:
    """Return ``True`` iff *value* parses as an IP address in an allowed range."""
    addr = parse_ip(value)
    if addr is None:
        return False
    try:
        assert_ip_allowed(addr)
        return True
    except SSRFBlockedError:
        return False


def check_address_string(value: str) -> None:
    """Parse *value* as an IP string and assert it is allowed.

    Raises :class:`SSRFBlockedError` on any prohibited address.
    Raises :class:`SSRFBlockedError` with code ``SSRF_BLOCKED`` if *value* is
    not a valid IP string at all (callers should only pass pre-validated IPs).
    """
    addr = parse_ip(value)
    if addr is None:
        raise SSRFBlockedError(SSRF_BLOCKED, f"Cannot parse as an IP address: {value!r}")
    assert_ip_allowed(addr)
