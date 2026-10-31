from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.security.domain_policy import DomainPolicy, normalize_hostname
from app.security.errors import (
    DOMAIN_BLOCKED,
    INVALID_URL,
    PORT_NOT_ALLOWED,
    PRIVATE_IP_BLOCKED,
    SecurityViolation,
    URL_SCHEME_NOT_ALLOWED,
)
from app.security.ip_policy import is_blocked_ip, parse_ip
from app.security.ports import PortPolicy

_MAX_URL_LENGTH = 4096
_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_AMBIGUOUS_IP_PATTERNS = (
    re.compile(r"^[0-9]+$"),
    re.compile(r"^0[xX][0-9a-fA-F]+$"),
    re.compile(r"^[0-9.]+$"),
    re.compile(r"^0[xX][0-9a-fA-F.]+$"),
)
_RESERVED_HOSTNAMES = {
    "localhost",
    "metadata",
    "instance-data",
    "metadata.google.internal",
    "metadata.azure.com",
}
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
class ValidatedUrl:
    url: str
    scheme: str
    hostname: str
    port: int
    is_ip: bool


class UrlPolicy:
    def __init__(
        self,
        *,
        allowed_ports: str = "80,443",
        allowed_domains: str = "",
        blocked_domains: str = "",
        default_domain_policy: str = "deny",
        allow_private_networks: bool = False,
    ) -> None:
        self._ports = PortPolicy(allowed_ports)
        self._domains = DomainPolicy(
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
            default_policy=default_domain_policy,
        )
        self._allow_private = allow_private_networks

    def validate(self, raw_url: str) -> ValidatedUrl:
        if not isinstance(raw_url, str) or not raw_url:
            raise SecurityViolation(INVALID_URL, "A URL is required.")

        if len(raw_url) > _MAX_URL_LENGTH:
            raise SecurityViolation(INVALID_URL, "The URL is too long.")

        if "\\" in raw_url or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in raw_url
        ):
            raise SecurityViolation(
                INVALID_URL, "The URL contains whitespace or control characters."
            )

        try:
            parsed = urlsplit(raw_url)
        except ValueError as exc:
            raise SecurityViolation(INVALID_URL, "The URL is malformed.") from exc

        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise SecurityViolation(
                URL_SCHEME_NOT_ALLOWED,
                "Only HTTP and HTTPS URLs are permitted.",
            )

        if (
            parsed.username is not None
            or parsed.password is not None
            or "@" in parsed.netloc
        ):
            raise SecurityViolation(
                INVALID_URL, "URLs containing embedded credentials are not permitted."
            )

        raw_hostname = parsed.hostname
        if not raw_hostname:
            raise SecurityViolation(INVALID_URL, "The URL must include a hostname.")

        try:
            port = parsed.port
        except ValueError as exc:
            raise SecurityViolation(INVALID_URL, "The URL contains an invalid port.") from exc

        if port is None:
            port = 443 if scheme == "https" else 80

        if port < 1 or port > 65535:
            raise SecurityViolation(INVALID_URL, "The URL contains an invalid port.")

        if not self._ports.is_allowed(port):
            raise SecurityViolation(
                PORT_NOT_ALLOWED, "The destination port is not permitted by policy."
            )

        hostname = self._normalize_hostname(raw_hostname)
        is_ip = parse_ip(hostname) is not None

        if not is_ip:
            self._reject_reserved_hostname(hostname)
        else:
            if is_blocked_ip(hostname, allow_private=self._allow_private):
                raise SecurityViolation(
                    PRIVATE_IP_BLOCKED,
                    "The destination address is not permitted by policy.",
                )

        self._domains.evaluate(hostname)

        netloc = f"[{hostname}]" if ":" in hostname else hostname
        default_port = 443 if scheme == "https" else 80
        if port != default_port:
            netloc = f"{netloc}:{port}"

        normalized_url = urlunsplit(
            (
                scheme,
                netloc,
                parsed.path or "/",
                parsed.query,
                parsed.fragment,
            )
        )

        return ValidatedUrl(
            url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            is_ip=is_ip,
        )

    @staticmethod
    def _normalize_hostname(raw_hostname: str) -> str:
        if "%" in raw_hostname:
            raise SecurityViolation(
                INVALID_URL, "Scoped IPv6 addresses are not permitted."
            )

        try:
            hostname = normalize_hostname(raw_hostname)
        except UnicodeError as exc:
            raise SecurityViolation(
                INVALID_URL, "The URL hostname is not valid IDNA."
            ) from exc

        if not hostname:
            raise SecurityViolation(INVALID_URL, "The URL must include a hostname.")

        if len(hostname) > 253:
            raise SecurityViolation(INVALID_URL, "The URL hostname is too long.")

        if parse_ip(hostname) is not None:
            return hostname

        for pattern in _AMBIGUOUS_IP_PATTERNS:
            if pattern.fullmatch(hostname):
                raise SecurityViolation(
                    INVALID_URL,
                    "Ambiguous numeric IP representations are not permitted.",
                )

        for label in hostname.split("."):
            if not label or len(label) > 63 or not _LABEL_PATTERN.fullmatch(label):
                raise SecurityViolation(
                    INVALID_URL, "The URL contains an invalid hostname."
                )

        return hostname

    @staticmethod
    def _reject_reserved_hostname(hostname: str) -> None:
        if hostname in _RESERVED_HOSTNAMES or hostname.endswith(_RESERVED_SUFFIXES):
            raise SecurityViolation(
                DOMAIN_BLOCKED,
                "The destination hostname is reserved for internal use.",
            )


def is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True
