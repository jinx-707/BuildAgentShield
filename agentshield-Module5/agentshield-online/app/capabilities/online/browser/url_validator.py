"""
URL Validator — prevents SSRF, DNS rebinding, private IP access,
javascript: injection, and other URL-based attacks.

Does NOT rely on string matching alone.
Resolves DNS and validates the actual destination IP.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any
from urllib.parse import urlparse

from app.core.exceptions import SSRFAttemptError, URLValidationError

logger = logging.getLogger(__name__)

# Cloud metadata endpoints — always blocked
_CLOUD_METADATA_HOSTNAMES = frozenset([
    "169.254.169.254",           # AWS / Azure IMDS
    "metadata.google.internal",   # GCP
    "169.254.170.2",              # ECS task metadata
    "metadata.internal",
    "computeMetadata",
])

_CLOUD_METADATA_PREFIXES = (
    "169.254.169.",
    "fd00:ec2::",
)

_BLOCKED_SCHEMES = frozenset([
    "javascript", "file", "data", "ftp", "blob",
    "vbscript", "mailto", "tel", "about", "chrome",
])

_ALLOWED_SCHEMES = frozenset(["http", "https"])

# Private/reserved IPv4 networks
_PRIVATE_NETWORKS_V4 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),       # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),    # link-local
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),     # shared address space
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv4Network("255.255.255.255/32"),
]

_PRIVATE_NETWORKS_V6 = [
    ipaddress.IPv6Network("::1/128"),             # loopback
    ipaddress.IPv6Network("fc00::/7"),            # ULA
    ipaddress.IPv6Network("fe80::/10"),           # link-local
    ipaddress.IPv6Network("::ffff:0:0/96"),       # IPv4-mapped
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("100::/64"),
    ipaddress.IPv6Network("2001:db8::/32"),       # documentation
]


def _is_private_ip(addr_str: str) -> bool:
    """Return True if the IP address is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(addr_str)
        if isinstance(addr, ipaddress.IPv4Address):
            return any(addr in net for net in _PRIVATE_NETWORKS_V4)
        else:
            return any(addr in net for net in _PRIVATE_NETWORKS_V6)
    except ValueError:
        return False


def _is_cloud_metadata(hostname: str) -> bool:
    if hostname in _CLOUD_METADATA_HOSTNAMES:
        return True
    for prefix in _CLOUD_METADATA_PREFIXES:
        if hostname.startswith(prefix):
            return True
    return False


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses. Returns empty list on failure."""
    try:
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


def validate_url(
    url: str,
    allowed_schemes: list[str] | None = None,
    domain_allowlist: list[str] | None = None,
    domain_blocklist: list[str] | None = None,
    allowed_ports: list[int] | None = None,
    resolve_dns: bool = True,
) -> dict[str, Any]:
    """
    Validate a URL for safety.

    Returns a dict with:
        valid: bool
        reason: str (if invalid)
        scheme: str
        hostname: str
        resolved_ips: list[str]

    Raises:
        URLValidationError — on format violations
        SSRFAttemptError — on SSRF / private IP access attempts
    """
    if not url or not isinstance(url, str):
        raise URLValidationError("URL must be a non-empty string")

    url = url.strip()

    # Length limit
    if len(url) > 2048:
        raise URLValidationError("URL exceeds maximum length of 2048 characters")

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise URLValidationError(f"URL parse error: {e}")

    scheme = parsed.scheme.lower() if parsed.scheme else ""
    hostname = parsed.hostname or ""
    port = parsed.port

    # Scheme validation
    if scheme in _BLOCKED_SCHEMES:
        raise URLValidationError(
            f"Blocked URL scheme: '{scheme}'. Schemes like javascript:, file:, "
            f"data: are not permitted."
        )

    effective_allowed = [s.lower() for s in (allowed_schemes or list(_ALLOWED_SCHEMES))]
    if scheme not in effective_allowed:
        raise URLValidationError(
            f"URL scheme '{scheme}' is not in allowed schemes: {effective_allowed}"
        )

    if not hostname:
        raise URLValidationError("URL has no hostname")

    # Port validation
    if port is not None and allowed_ports:
        if port not in allowed_ports:
            raise URLValidationError(
                f"Port {port} is not in allowed ports: {allowed_ports}"
            )

    # Cloud metadata check on hostname
    if _is_cloud_metadata(hostname):
        raise SSRFAttemptError(
            f"Cloud metadata endpoint blocked: {hostname}"
        )

    # Domain blocklist
    if domain_blocklist:
        for blocked in domain_blocklist:
            if hostname == blocked or hostname.endswith(f".{blocked}"):
                raise URLValidationError(
                    f"Domain '{hostname}' is in the blocklist"
                )

    # Domain allowlist
    if domain_allowlist:
        allowed = False
        for allowed_domain in domain_allowlist:
            if hostname == allowed_domain or hostname.endswith(f".{allowed_domain}"):
                allowed = True
                break
        if not allowed:
            raise URLValidationError(
                f"Domain '{hostname}' is not in the allowlist. "
                f"Approved domains: {domain_allowlist[:5]}"
            )

    # Direct IP address check
    try:
        ip = ipaddress.ip_address(hostname)
        if _is_private_ip(str(ip)):
            raise SSRFAttemptError(
                f"Direct access to private/reserved IP address blocked: {hostname}"
            )
        resolved_ips = [str(ip)]
    except ValueError:
        # It's a hostname — resolve DNS
        resolved_ips = []
        if resolve_dns:
            resolved_ips = _resolve_hostname(hostname)
            if not resolved_ips:
                logger.warning("URL validator: could not resolve hostname '%s'", hostname)
                # Don't block on DNS resolution failure (could be network issue)
                # but flag it
                return {
                    "valid": True,
                    "scheme": scheme,
                    "hostname": hostname,
                    "resolved_ips": [],
                    "warning": f"Could not resolve DNS for {hostname}",
                }
            for ip_str in resolved_ips:
                if _is_private_ip(ip_str):
                    raise SSRFAttemptError(
                        f"DNS resolves to private IP ({ip_str}) — SSRF attempt blocked: {url}"
                    )
                if _is_cloud_metadata(ip_str):
                    raise SSRFAttemptError(
                        f"DNS resolves to cloud metadata IP ({ip_str}) — blocked: {url}"
                    )

    return {
        "valid": True,
        "scheme": scheme,
        "hostname": hostname,
        "resolved_ips": resolved_ips,
    }
