"""
URL validation for download requests.

Validates and normalises a raw URL before any network activity occurs.
This layer is purely syntactic — it does not touch the network.

Rules enforced here
-------------------
- HTTPS-only (no plain HTTP downloads by default).
- Maximum URL length.
- No backslash, whitespace, or ASCII control characters.
- No embedded credentials (user:pass@ in netloc).
- Hostname must be a valid DNS label sequence or a parseable IP address.
- No ambiguous numeric IP representations (pure decimal, octal, hex integers).
- Reserved hostnames / suffixes are blocked.
- Port must be in the policy-allowed set.
- Domain must pass the DomainPolicy evaluation.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from security.domain_policy import DomainPolicy, PortPolicy, normalize_hostname
from security.errors import (
    DOMAIN_BLOCKED,
    INVALID_URL,
    PORT_NOT_ALLOWED,
    PRIVATE_IP_BLOCKED,
    URL_SCHEME_NOT_ALLOWED,
    DownloadSecurityError,
)
from security.ip_policy import is_blocked_ip, parse_ip

_MAX_URL_LENGTH = 4096

_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

_AMBIGUOUS_IP_PATTERNS = (
    re.compile(r"^[0-9]+$"),              # pure decimal integer
    re.compile(r"^0[xX][0-9a-fA-F]+$"),  # hex integer
    re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$"),     # dotted-partial
    re.compile(r"^0[xX][0-9a-fA-F.]+$"), # mixed hex
)

_RESERVED_HOSTNAMES: frozenset[str] = frozenset(
    [
        "localhost",
        "metadata",
        "instance-data",
        "metadata.google.internal",
        "metadata.azure.com",
    ]
)

_RESERVED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".lan",
    ".corp",
    ".intranet",
)


@dataclass(frozen=True)
class ValidatedDownloadUrl:
    url: str          # canonical, normalised URL string
    scheme: str
    hostname: str
    port: int
    is_ip: bool


class DownloadUrlValidator:
    """
    Validates download URLs against a set of security policies.

    Parameters
    ----------
    allowed_ports:        Comma-separated port spec (default "443").
    allowed_domains:      Comma-separated domain allowlist.
    blocked_domains:      Comma-separated domain blocklist.
    default_domain_policy:"allow" or "deny".
    allow_private_networks: Whether private IPs may be literal targets.
    https_only:           When True (default), reject plain HTTP URLs.
    """

    def __init__(
        self,
        *,
        allowed_ports: str = "443",
        allowed_domains: str = "",
        blocked_domains: str = "",
        default_domain_policy: str = "deny",
        allow_private_networks: bool = False,
        https_only: bool = True,
    ) -> None:
        self._ports = PortPolicy(allowed_ports)
        self._domains = DomainPolicy(
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
            default_policy=default_domain_policy,
        )
        self._allow_private = allow_private_networks
        self._https_only = https_only

    def validate(self, raw_url: str) -> ValidatedDownloadUrl:
        if not isinstance(raw_url, str) or not raw_url:
            raise DownloadSecurityError(INVALID_URL, "A URL is required.")

        if len(raw_url) > _MAX_URL_LENGTH:
            raise DownloadSecurityError(INVALID_URL, "The URL is too long.")

        # Reject backslashes and ASCII control characters.
        if "\\" in raw_url or any(
            ord(c) <= 0x20 or ord(c) == 0x7F for c in raw_url
        ):
            raise DownloadSecurityError(
                INVALID_URL,
                "The URL contains whitespace or control characters.",
            )

        try:
            parsed = urlsplit(raw_url)
        except ValueError as exc:
            raise DownloadSecurityError(INVALID_URL, "The URL is malformed.") from exc

        scheme = parsed.scheme.lower()
        if self._https_only:
            if scheme != "https":
                raise DownloadSecurityError(
                    URL_SCHEME_NOT_ALLOWED,
                    "Only HTTPS URLs are permitted for file downloads.",
                )
        else:
            if scheme not in {"http", "https"}:
                raise DownloadSecurityError(
                    URL_SCHEME_NOT_ALLOWED,
                    "Only HTTP and HTTPS URLs are permitted.",
                )

        # Reject embedded credentials.
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise DownloadSecurityError(
                INVALID_URL,
                "URLs containing embedded credentials are not permitted.",
            )

        raw_hostname = parsed.hostname
        if not raw_hostname:
            raise DownloadSecurityError(INVALID_URL, "The URL must include a hostname.")

        try:
            port = parsed.port
        except ValueError as exc:
            raise DownloadSecurityError(
                INVALID_URL, "The URL contains an invalid port."
            ) from exc

        if port is None:
            port = 443 if scheme == "https" else 80

        if not (1 <= port <= 65535):
            raise DownloadSecurityError(INVALID_URL, "The URL contains an invalid port.")

        self._ports.assert_allowed(port)

        hostname = normalize_hostname(raw_hostname)
        if not hostname:
            raise DownloadSecurityError(INVALID_URL, "The URL contains an empty hostname.")

        self._validate_hostname_syntax(hostname)

        # Check reserved hostnames/suffixes (only for non-IP targets).
        is_ip = parse_ip(hostname) is not None
        if not is_ip:
            if hostname in _RESERVED_HOSTNAMES:
                raise DownloadSecurityError(
                    DOMAIN_BLOCKED,
                    "The destination hostname is reserved for internal use.",
                )
            if any(hostname.endswith(sfx) for sfx in _RESERVED_SUFFIXES):
                raise DownloadSecurityError(
                    DOMAIN_BLOCKED,
                    "The destination hostname suffix is reserved for internal use.",
                )
            self._domains.evaluate(hostname)
        else:
            # Direct IP target: enforce IP policy.
            if is_blocked_ip(hostname, allow_private=self._allow_private):
                raise DownloadSecurityError(
                    PRIVATE_IP_BLOCKED,
                    "The destination resolves to a restricted network address.",
                )

        return ValidatedDownloadUrl(
            url=raw_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            is_ip=is_ip,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _validate_hostname_syntax(self, hostname: str) -> None:
        # If it's a valid IP address, skip label validation.
        if parse_ip(hostname) is not None:
            return

        # Reject ambiguous numeric forms that could encode private addresses.
        if _AMBIGUOUS_IP_PATTERNS[0].match(hostname) or any(
            p.match(hostname) for p in _AMBIGUOUS_IP_PATTERNS
        ):
            raise DownloadSecurityError(
                INVALID_URL,
                "Ambiguous numeric IP representations are not permitted.",
            )

        # Validate each DNS label.
        for label in hostname.split("."):
            if not label or len(label) > 63 or not _LABEL_PATTERN.match(label):
                raise DownloadSecurityError(
                    INVALID_URL, "The URL contains an invalid hostname."
                )
