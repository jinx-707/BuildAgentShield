"""
IP address policy for SSRF protection.

This is a standalone reimplementation that mirrors the logic in the browser-security
API (api/app/security/ip_policy.py) but lives independently in this module so that
secure-downloads has no import dependency on that codebase.

Blocked ranges
--------------
- Loopback           (127.0.0.0/8, ::1)
- Private            (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
- Link-local         (169.254.0.0/16, fe80::/10)
- Multicast          (224.0.0.0/4, ff00::/8)
- Reserved / unspec  (0.0.0.0, ::)
- 6to4               (2002::/16)
- Teredo             (2001::/32)
- NAT64              (64:ff9b::/96)
- Cloud metadata IPs (169.254.169.254, 169.254.170.2, 100.100.100.200, fd00:ec2::254)
"""
from __future__ import annotations

import ipaddress
from typing import Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_ALWAYS_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("2002::/16"),   # 6to4
    ipaddress.ip_network("2001::/32"),   # Teredo
    ipaddress.ip_network("64:ff9b::/96"), # NAT64
)

_ALWAYS_BLOCKED_IPS: frozenset[IPAddress] = frozenset(
    [
        ipaddress.ip_address("169.254.169.254"),  # AWS / GCP metadata
        ipaddress.ip_address("169.254.170.2"),    # ECS metadata
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud metadata
        ipaddress.ip_address("fd00:ec2::254"),    # AWS IPv6 metadata
    ]
)


def parse_ip(value: str) -> IPAddress | None:
    """
    Parse an IP address string, unwrapping IPv4-mapped / 6to4 / Teredo addresses
    to their effective IPv4 representation so policy checks are not bypassed by
    using alternative encodings.
    """
    try:
        parsed: IPAddress = ipaddress.ip_address(value)
    except ValueError:
        return None

    if isinstance(parsed, ipaddress.IPv6Address):
        if parsed.ipv4_mapped is not None:
            return parsed.ipv4_mapped
        if parsed.sixtofour is not None:
            return parsed.sixtofour
        if parsed.teredo is not None:
            return parsed.teredo[1]

    return parsed


def is_blocked_ip(value: str, *, allow_private: bool = False) -> bool:
    """
    Return True if the address must be rejected.

    When allow_private is True, private/loopback ranges are permitted, but the
    always-blocked list (cloud metadata, Teredo, etc.) is still enforced.
    """
    parsed = parse_ip(value)
    if parsed is None:
        # Unparseable string — treat as blocked (fail closed).
        return True

    if parsed in _ALWAYS_BLOCKED_IPS:
        return True

    if any(
        parsed.version == net.version and parsed in net
        for net in _ALWAYS_BLOCKED_NETWORKS
    ):
        return True

    if (
        parsed.is_unspecified
        or parsed.is_multicast
        or parsed.is_link_local
        or parsed.is_reserved
    ):
        return True

    if parsed.is_loopback or parsed.is_private:
        return not allow_private

    if not parsed.is_global:
        return not allow_private

    return False
