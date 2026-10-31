"""Redirect security for secure file downloads.

Handles HTTP redirects manually, applying the full security pipeline to every
hop:

1. URL validation (scheme, credentials, port, hostname).
2. DNS resolution and address validation (SSRF/loopback/private-range).
3. Connection pinning (the socket connects to the validated IP only).

Rules enforced
--------------
* Maximum redirect count (configurable; default 3).
* Redirect loop detection (seen-URL set).
* HTTPS → HTTP downgrade rejection.
* Authorization/Cookie/sensitive-header stripping on cross-origin redirects.
* Every hop is independently validated — passing URL validation once does not
  exempt later hops.
* File-size and timeout limits apply to every response, including intermediate
  redirect responses.

Scope note
----------
This module provides the *redirect following* scaffolding only.  Full file
streaming, SHA-256 computation, and content scanning belong to a later phase.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import httpx

from app.downloads.dns_resolver import ResolvedTarget, SecureDNSResolver
from app.downloads.exceptions import (
    REDIRECT_LIMIT_EXCEEDED,
    REDIRECT_LOOP,
    REDIRECT_MISSING_LOCATION,
    REDIRECT_SCHEME_DOWNGRADE,
    REDIRECT_UNSAFE_TARGET,
    RedirectError,
)
from app.downloads.pinned_transport import build_pinned_client
from app.downloads.url_validator import URLValidator, ValidatedURL

# Sensitive headers that must not be forwarded across origins.
_SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "cookie",
        "cookie2",
        "proxy-authorization",
        "www-authenticate",
    }
)

# Headers that are always safe to forward to the redirect destination.
_SAFE_FORWARD_HEADERS: frozenset[str] = frozenset(
    {
        "accept",
        "accept-language",
        "accept-encoding",
        "user-agent",
        "range",
    }
)


def _is_cross_origin(original: ValidatedURL, redirect: ValidatedURL) -> bool:
    """Return True if the redirect target has a different origin than the source."""
    return original.hostname != redirect.hostname or original.port != redirect.port


def _safe_headers(
    original_headers: httpx.Headers,
    origin_changed: bool,
) -> dict[str, str]:
    """Build a safe set of headers for the next hop.

    Sensitive headers (Authorization, Cookie, etc.) are stripped when the
    origin changes.  Non-sensitive, non-hop-by-hop headers are forwarded.
    """
    out: dict[str, str] = {}
    for name, value in original_headers.items():
        lower = name.lower()
        # Always drop hop-by-hop and connection-specific headers.
        if lower in {"host", "content-length", "transfer-encoding", "connection", "keep-alive"}:
            continue
        # Drop sensitive headers on origin change.
        if origin_changed and lower in _SENSITIVE_HEADERS:
            continue
        out[name] = value
    return out


class RedirectHandler:
    """Follows redirects while applying the full security pipeline to each hop.

    Parameters
    ----------
    url_validator:
        The URL validator to apply to every redirect target.
    dns_resolver:
        The DNS resolver to apply to every redirect target.
    max_redirects:
        Maximum number of redirects to follow (not counting the initial
        request).  A value of 0 disables redirect following entirely.
    connect_timeout:
        Per-hop connection timeout in seconds.
    read_timeout:
        Per-hop read timeout in seconds.
    """

    REDIRECT_STATUS_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

    def __init__(
        self,
        *,
        url_validator: URLValidator | None = None,
        dns_resolver: SecureDNSResolver | None = None,
        max_redirects: int = 3,
        connect_timeout: float = 5.0,
        read_timeout: float = 30.0,
        max_response_size: int = 25 * 1024 * 1024,
    ) -> None:
        self._url_validator = url_validator or URLValidator()
        self._dns_resolver = dns_resolver or SecureDNSResolver()
        self._max_redirects = max_redirects
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._max_response_size = max_response_size

    async def fetch(
        self,
        initial_target: ResolvedTarget,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response, ResolvedTarget]:
        """Execute a request, following redirects through the security pipeline.

        Returns
        -------
        (response, final_target):
            The final HTTP response and the :class:`ResolvedTarget` for the
            last hop.

        Raises
        ------
        RedirectError
            On loop detection, limit exceeded, unsafe redirect target, or
            scheme downgrade.
        InvalidURLError / SSRFBlockedError / DNSResolutionError:
            If any redirect target fails URL or DNS validation.
        """
        seen_urls: set[str] = set()
        current_target = initial_target
        current_headers = dict(headers or {})
        original_validated: ValidatedURL | None = None
        hop = 0

        while True:
            url_str = current_target.normalized_url
            if url_str in seen_urls:
                raise RedirectError(REDIRECT_LOOP, f"Redirect loop detected at {url_str!r}")
            seen_urls.add(url_str)

            async with build_pinned_client(
                current_target,
                connect_timeout=self._connect_timeout,
                read_timeout=self._read_timeout,
                max_response_size=self._max_response_size,
            ) as client:
                response = await client.request(
                    method=method,
                    url=url_str,
                    headers=current_headers,
                    follow_redirects=False,
                )

            if response.status_code not in self.REDIRECT_STATUS_CODES:
                # Not a redirect — return the final response.
                return response, current_target

            # ── Handle redirect ──────────────────────────────────────────────
            hop += 1
            if hop > self._max_redirects:
                raise RedirectError(
                    REDIRECT_LIMIT_EXCEEDED,
                    f"Redirect limit of {self._max_redirects} exceeded",
                )

            location = response.headers.get("location", "").strip()
            if not location:
                raise RedirectError(
                    REDIRECT_MISSING_LOCATION,
                    "Redirect response did not include a Location header",
                )

            # Resolve relative redirects against the current URL.
            redirect_url = urljoin(url_str, location)

            # Track the original validated URL for cross-origin detection.
            if original_validated is None:
                original_validated = _build_validated_url_from_target(current_target)

            # Full validation pipeline for every hop.
            redirect_validated = self._url_validator.validate(redirect_url)

            # Reject HTTPS → HTTP downgrade.
            if current_target.scheme == "https" and redirect_validated.scheme == "http":
                raise RedirectError(
                    REDIRECT_SCHEME_DOWNGRADE,
                    f"Redirect from HTTPS to HTTP is not permitted: {redirect_url!r}",
                )

            # DNS resolution + address validation for the redirect target.
            try:
                next_target = await self._dns_resolver.resolve(redirect_validated)
            except Exception as exc:
                raise RedirectError(
                    REDIRECT_UNSAFE_TARGET,
                    f"Redirect target {redirect_url!r} failed security validation: {exc}",
                ) from exc

            # Strip sensitive headers on cross-origin redirects.
            origin_changed = _is_cross_origin(original_validated, redirect_validated)
            current_headers = _safe_headers(
                response.request.headers if response.request else httpx.Headers(current_headers),
                origin_changed=origin_changed,
            )

            current_target = next_target

            # After a 303 or a redirect from a non-GET method, downgrade to GET.
            if response.status_code == 303 or method not in {"GET", "HEAD"}:
                method = "GET"


def _build_validated_url_from_target(target: ResolvedTarget) -> ValidatedURL:
    """Reconstruct a minimal :class:`ValidatedURL` from a :class:`ResolvedTarget`.

    Used for cross-origin detection only; does not re-validate the URL.
    """
    from app.downloads.url_validator import ValidatedURL  # local to avoid circular

    return ValidatedURL(
        original_url=target.normalized_url,
        normalized_url=target.normalized_url,
        scheme=target.scheme,
        hostname=target.hostname,
        port=target.port,
        is_ip=False,
    )


class DownloadFetcher:
    """High-level entry point: validate URL → resolve DNS → pin → fetch with redirect safety.

    This is the only public surface callers should use for Phase C.
    It wires together :class:`URLValidator`, :class:`SecureDNSResolver`, and
    :class:`RedirectHandler`.

    Scope
    -----
    Returns the raw :class:`httpx.Response` for the final hop.  Streaming
    the response body into storage, computing SHA-256, and running ClamAV
    belong to a later phase.
    """

    def __init__(
        self,
        *,
        url_validator: URLValidator | None = None,
        dns_resolver: SecureDNSResolver | None = None,
        max_redirects: int = 3,
        connect_timeout: float = 5.0,
        read_timeout: float = 30.0,
        max_response_size: int = 25 * 1024 * 1024,
    ) -> None:
        self._url_validator = url_validator or URLValidator()
        self._dns_resolver = dns_resolver or SecureDNSResolver()
        self._redirect_handler = RedirectHandler(
            url_validator=self._url_validator,
            dns_resolver=self._dns_resolver,
            max_redirects=max_redirects,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            max_response_size=max_response_size,
        )

    async def fetch(
        self,
        raw_url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response, ResolvedTarget]:
        """Validate, resolve, pin, and fetch *raw_url*.

        Parameters
        ----------
        raw_url:
            The original URL supplied by the caller (e.g. from an email link).
        headers:
            Optional extra request headers.  Sensitive headers on cross-origin
            redirects are automatically stripped.

        Returns
        -------
        (response, final_target):
            The HTTP response and the connection target for the final hop.
        """
        # Step 1: Validate URL structure.
        validated = self._url_validator.validate(raw_url)

        # Step 2: Resolve DNS and validate all addresses.
        target = await self._dns_resolver.resolve(validated)

        # Step 3: Fetch with redirect safety (each hop repeats steps 1 & 2).
        return await self._redirect_handler.fetch(target, headers=headers)
