from __future__ import annotations

import ipaddress
from typing import Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_ALWAYS_BLOCKED_NETWORKS = (
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("2001::/32"),
    ipaddress.ip_network("64:ff9b::/96"),
)

_ALWAYS_BLOCKED_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}


def parse_ip(value: str) -> IPAddress | None:
    try:
        parsed = ipaddress.ip_address(value)
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
    parsed = parse_ip(value)
    if parsed is None:
        return True

    if parsed in _ALWAYS_BLOCKED_IPS:
        return True

    if any(
        parsed.version == network.version and parsed in network
        for network in _ALWAYS_BLOCKED_NETWORKS
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
