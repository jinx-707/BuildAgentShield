"""Strict URL validation for secure file downloads.

Validates structure, scheme, credentials, port, hostname, IP literals, and
IDNA encoding.  Returns a :class:`ValidatedURL` dataclass on success or raises
a :class:`~app.downloads.exceptions.InvalidURLError` on any policy violation.

Scope: syntactic and structural checks only.  DNS resolution is handled by
:mod:`app.downloads.dns_resolver`.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.downloads.exceptions import (
    AMBIGUOUS_HOST,
    EMBEDDED_CREDENTIALS,
    INVALID_PORT,
    INVALID_URL,
    UNSUPPORTED_SCHEME,
    InvalidURLError,
    SSRFBlockedError,
)
from app.downloads.ip_policy import assert_ip_allowed, parse_ip

# ── Constants ─────────────────────────────────────────────────────────────────

_MAX_URL_LENGTH = 2048
_MAX_HOSTNAME_LENGTH = 253
_MAX_LABEL_LENGTH = 63

# RFC 1123 hostname label: a-z, 0-9, hyphen; must not start/end with hyphen.
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")

# Ambiguous numeric representations that could be parsed differently across
# HTTP client implementations (e.g. octal, hex, packed-decimal).
_AMBIGUOUS_IP_PATTERNS = (
    re.compile(r"^[0-9]+$"),                    # pure decimal integer
    re.compile(r"^0[xX][0-9a-fA-F]+$"),         # hex integer
    re.compile(r"^[0-9]+\.[0-9]+$"),            # fewer-than-four dotted decimal
    re.compile(r"^0[xX][0-9a-fA-F.]+$"),        # hex with dots
)

# Hostnames that should never be the destination of an outbound download.
_RESERVED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "metadata",
        "instance-data",
        "metadata.google.internal",
        "metadata.azure.com",
    }
)

_RESERVED_SUFFIXES: tuple[str, ...] = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".lan",
    ".corp",
    ".intranet",
    ".example",       # RFC 2606 reserved
    ".test",          # RFC 2606 reserved
    ".invalid",       # RFC 2606 reserved
)

# Default ports for supported schemes.
_DEFAULT_PORTS: dict[str, int] = {"https": 443, "http": 80}


@dataclass(frozen=True)
class ValidatedURL:
    """The result of successfully validating a raw URL string.

    Attributes
    ----------
    original_url:
        The caller-supplied raw URL (redacted of credentials if any were
        present — though their presence is already an error, kept for logging).
    normalized_url:
        The canonicalized URL safe for logging (no credentials, ASCII-only
        hostname, explicit port omitted when it equals the scheme default).
    scheme:
        ``"https"`` or ``"http"`` (lower-case).
    hostname:
        The IDNA-encoded, lower-case hostname or IP literal string.
    port:
        The resolved port number (never ``None``).
    is_ip:
        ``True`` when the host component is an IP address literal.
    """

    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int
    is_ip: bool


class URLValidator:
    """Validates and normalizes download URLs.

    Parameters
    ----------
    allow_http:
        Permit plain-HTTP URLs.  **Must never be ``True`` in production.**
        Controlled exclusively via ``DOWNLOAD_ALLOW_HTTPS_DOWNGRADE`` in
        :class:`~app.downloads.config.DownloadSettings`, which is itself
        validated to be ``False``.
    allowed_ports:
        Additional ports beyond the scheme defaults (443/https, 80/http).
        Pass an empty set to restrict to defaults only (recommended).
    """

    def __init__(
        self,
        *,
        allow_http: bool = False,
        allowed_ports: frozenset[int] | None = None,
    ) -> None:
        self._allow_http = allow_http
        # Always allow scheme-default ports; add any explicitly permitted extras.
        base = frozenset(_DEFAULT_PORTS.values())
        self._allowed_ports: frozenset[int] = base | (allowed_ports or frozenset())

    # ── Public API ────────────────────────────────────────────────────────────

    def validate(self, raw_url: str) -> ValidatedURL:
        """Validate *raw_url* and return a :class:`ValidatedURL` on success.

        Raises :class:`~app.downloads.exceptions.InvalidURLError` for any
        policy violation.  Raises
        :class:`~app.downloads.exceptions.SSRFBlockedError` when the host is
        an IP literal in a blocked range.
        """
        self._check_raw(raw_url)

        try:
            parts = urlsplit(raw_url)
        except ValueError as exc:
            raise InvalidURLError(INVALID_URL, f"Malformed URL: {exc}") from exc

        scheme = self._check_scheme(parts.scheme)
        self._check_credentials(parts)
        self._check_fragment(parts)

        raw_host = parts.hostname
        if not raw_host:
            raise InvalidURLError(INVALID_URL, "URL must include a hostname")

        hostname = self._normalize_hostname(raw_host)
        port = self._check_port(parts, scheme)
        is_ip = parse_ip(hostname) is not None

        if is_ip:
            self._check_ip_literal(hostname)
        else:
            self._check_reserved_hostname(hostname)

        normalized_url = self._build_normalized(parts, scheme, hostname, port)

        return ValidatedURL(
            original_url=raw_url,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            is_ip=is_ip,
        )

    # ── Internal checks ───────────────────────────────────────────────────────

    def _check_raw(self, raw_url: str) -> None:
        if not isinstance(raw_url, str) or not raw_url.strip():
            raise InvalidURLError(INVALID_URL, "URL must be a non-empty string")

        if len(raw_url) > _MAX_URL_LENGTH:
            raise InvalidURLError(
                INVALID_URL,
                f"URL exceeds maximum length of {_MAX_URL_LENGTH} characters",
            )

        # Reject control characters and whitespace embedded in the URL.
        for ch in raw_url:
            cp = ord(ch)
            if cp <= 0x20 or cp == 0x7F:
                raise InvalidURLError(
                    INVALID_URL,
                    "URL contains embedded whitespace or control characters",
                )

        # Reject backslashes — they confuse parser normalization across clients.
        if "\\" in raw_url:
            raise InvalidURLError(INVALID_URL, "URL contains a backslash")

    def _check_scheme(self, scheme: str) -> str:
        s = scheme.lower()
        if s == "https":
            return s
        if s == "http":
            if not self._allow_http:
                raise InvalidURLError(
                    UNSUPPORTED_SCHEME,
                    "Only HTTPS URLs are accepted; plain HTTP is not permitted",
                )
            return s
        raise InvalidURLError(
            UNSUPPORTED_SCHEME,
            f"Unsupported URL scheme {scheme!r}; only https is accepted",
        )

    @staticmethod
    def _check_credentials(parts) -> None:  # type: ignore[no-untyped-def]
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise InvalidURLError(
                EMBEDDED_CREDENTIALS,
                "URLs containing embedded credentials (username/password) are not permitted",
            )

    @staticmethod
    def _check_fragment(parts) -> None:  # type: ignore[no-untyped-def]
        # Fragments are meaningless for file downloads and can be abused for
        # cache-bypass or URL confusion.
        if parts.fragment:
            raise InvalidURLError(
                INVALID_URL,
                "URL fragments are not permitted in download URLs",
            )

    def _check_port(self, parts, scheme: str) -> int:
        try:
            port = parts.port
        except ValueError as exc:
            raise InvalidURLError(INVALID_PORT, f"URL contains an invalid port: {exc}") from exc

        if port is None:
            return _DEFAULT_PORTS[scheme]

        if port < 1 or port > 65535:
            raise InvalidURLError(INVALID_PORT, f"Port {port} is out of the valid range")

        if port not in self._allowed_ports:
            raise InvalidURLError(
                INVALID_PORT,
                f"Port {port} is not permitted; allowed: {sorted(self._allowed_ports)}",
            )
        return port

    @staticmethod
    def _normalize_hostname(raw_host: str) -> str:
        # Reject scoped IPv6 zone IDs (%xx) — not meaningful for outbound requests.
        if "%" in raw_host:
            raise InvalidURLError(INVALID_URL, "Scoped IPv6 zone IDs are not permitted")

        # Strip bracket notation from IPv6 literals before processing.
        host = raw_host.strip("[]").lower()

        try:
            # IDNA-encode international hostnames; raises UnicodeError on failure.
            encoded = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError, ValueError) as exc:
            raise InvalidURLError(
                INVALID_URL, f"Hostname is not valid IDNA: {exc}"
            ) from exc

        if not encoded:
            raise InvalidURLError(INVALID_URL, "URL hostname is empty after normalization")

        if len(encoded) > _MAX_HOSTNAME_LENGTH:
            raise InvalidURLError(
                INVALID_URL,
                f"Hostname exceeds maximum length of {_MAX_HOSTNAME_LENGTH} characters",
            )

        # If it looks like an IP address, leave further validation to _check_ip_literal.
        if parse_ip(encoded) is not None:
            return encoded

        # Reject ambiguous numeric representations that might be parsed as IPs
        # by some HTTP clients but not others.
        for pattern in _AMBIGUOUS_IP_PATTERNS:
            if pattern.fullmatch(encoded):
                raise InvalidURLError(
                    AMBIGUOUS_HOST,
                    f"Ambiguous numeric hostname {encoded!r} is not permitted",
                )

        # Validate each DNS label.
        for label in encoded.split("."):
            if not label:
                raise InvalidURLError(INVALID_URL, "Hostname contains an empty label")
            if len(label) > _MAX_LABEL_LENGTH:
                raise InvalidURLError(
                    INVALID_URL,
                    f"Hostname label {label!r} exceeds {_MAX_LABEL_LENGTH} characters",
                )
            if not _LABEL_RE.fullmatch(label):
                raise InvalidURLError(
                    INVALID_URL,
                    f"Hostname label {label!r} contains invalid characters",
                )

        return encoded

    @staticmethod
    def _check_ip_literal(hostname: str) -> None:
        """Reject IP literals in prohibited ranges."""
        try:
            assert_ip_allowed(ipaddress.ip_address(hostname))
        except SSRFBlockedError:
            raise
        except ValueError as exc:
            raise InvalidURLError(INVALID_URL, f"Invalid IP literal: {exc}") from exc

    @staticmethod
    def _check_reserved_hostname(hostname: str) -> None:
        if hostname in _RESERVED_HOSTNAMES:
            raise InvalidURLError(
                INVALID_URL,
                f"Hostname {hostname!r} is reserved and cannot be used as a download target",
            )
        for suffix in _RESERVED_SUFFIXES:
            if hostname == suffix.lstrip(".") or hostname.endswith(suffix):
                raise InvalidURLError(
                    INVALID_URL,
                    f"Hostname {hostname!r} uses a reserved suffix {suffix!r}",
                )

    @staticmethod
    def _build_normalized(parts, scheme: str, hostname: str, port: int) -> str:
        # Rebuild netloc without credentials or fragments.
        default_port = _DEFAULT_PORTS[scheme]
        netloc = f"[{hostname}]" if ":" in hostname else hostname
        if port != default_port:
            netloc = f"{netloc}:{port}"

        return urlunsplit(
            (
                scheme,
                netloc,
                parts.path if parts.path else "/",
                parts.query,
                "",  # strip fragment
            )
        )
