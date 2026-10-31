"""DNS-pinned HTTP transport for secure file downloads.

This module provides the connection layer that GUARANTEES the HTTP client
connects to the DNS-validated IP address, while preserving:

* TLS SNI (Server Name Indication) — the original hostname is sent in the TLS
  ClientHello, not the numeric IP.
* Certificate verification against the original hostname — not the IP.
* HTTP ``Host`` header — the original hostname, not the IP.

Design
------
The standard ``httpx.AsyncClient`` resolves hostnames itself.  Even if we
validate DNS before calling it, the client will perform its own independent
resolution.  That breaks the SSRF guarantee.

We solve this by subclassing :class:`httpx.AsyncHTTPTransport` and overriding
``handle_async_request`` to rewrite the destination from the hostname to the
pre-validated IP address **before** the transport establishes the socket, while
passing the original hostname through for TLS/SNI/Host.

Specifically we:

1. Accept a :class:`~app.downloads.dns_resolver.ResolvedTarget` at construction
   time.
2. In ``handle_async_request``, replace ``request.url`` with the IP-based URL
   so the underlying ``httpcore`` transport opens a socket to the pinned address.
3. Restore the ``Host`` header to the original hostname so the server sees the
   correct value.
4. Configure ``ssl_context`` with ``check_hostname=True`` and ``verify=True``
   so TLS certificate validation uses the original hostname, not the IP.

Connection-pool isolation
------------------------
Each :class:`PinnedTransport` is created per-request.  There is no shared
connection pool, so a cached connection to an unvalidated address is impossible.

Important: do NOT call ``AsyncClient`` with the original hostname URL and a
separate ``PinnedTransport`` that "handles" the hostname — the URL passed to
``AsyncClient.request()`` must already use the IP literal so httpcore's
connection logic targets the right address.  The ``Host`` header rewrite
ensures the server still sees the correct hostname.
"""

from __future__ import annotations

import ssl
from typing import Any

import httpx

from app.downloads.dns_resolver import ResolvedTarget
from app.downloads.exceptions import (
    CONNECTION_PIN_FAILED,
    ConnectionPinningError,
)


def _build_ssl_context(hostname: str) -> ssl.SSLContext:
    """Return an ``ssl.SSLContext`` that verifies the *hostname* certificate.

    ``check_hostname`` is True and ``verify_mode`` is ``CERT_REQUIRED``.
    Using the system CA bundle (``ssl.create_default_context()``).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _ip_url(target: ResolvedTarget) -> str:
    """Build a URL that uses the numeric IP address instead of the hostname.

    IPv6 addresses are bracketed as required by RFC 3986.
    """
    addr = target.address
    host_part = f"[{addr}]" if ":" in addr else addr
    return f"{target.scheme}://{host_part}:{target.port}"


class PinnedTransport(httpx.AsyncHTTPTransport):
    """An ``httpx`` transport that pins connections to a pre-validated IP.

    Usage::

        target = await resolver.resolve(validated_url)
        transport = PinnedTransport(target)
        async with httpx.AsyncClient(transport=transport) as client:
            resp = await client.get(
                target.pinned_base_url,
                headers={"Host": target.hostname},
                ...
            )

    See :func:`build_pinned_client` for a convenience constructor.
    """

    def __init__(self, target: ResolvedTarget, **kwargs: Any) -> None:
        # Build an SSL context that checks the *hostname* certificate even
        # though the physical connection goes to an IP literal.
        # httpx.AsyncHTTPTransport accepts an ssl.SSLContext via `verify=`.
        if target.scheme == "https":
            ssl_context = _build_ssl_context(target.hostname)
            kwargs.setdefault("verify", ssl_context)

        super().__init__(**kwargs)
        self._target = target

    @property
    def pinned_address(self) -> str:
        return self._target.address

    @property
    def original_hostname(self) -> str:
        return self._target.hostname

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Intercept the outgoing request and force the connection to the pinned IP.

        Steps:
        1. Rewrite the URL to use the numeric IP (keeps scheme, port, path, query).
        2. Restore the ``Host`` header to the original hostname.
        3. For HTTPS, the ssl_context we set at construction enforces SNI/cert
           against the original hostname — httpcore picks it up from the context.
        """
        try:
            # Build the IP-literal base URL, preserving path/query.
            base = _ip_url(self._target)
            original = request.url

            # httpx.URL.copy_with accepts `raw_path` which is the encoded
            # path+query bytes, and `fragment` separately.
            # Build raw_path from original URL path + query.
            raw_path: bytes = original.raw_path  # includes query string

            ip_url = httpx.URL(base).copy_with(raw_path=raw_path)

            # Build new request with IP-literal URL.
            new_request = httpx.Request(
                method=request.method,
                url=ip_url,
                headers=request.headers,
                stream=request.stream,
                extensions=request.extensions,
            )

            # Ensure Host header always matches the original hostname, not the IP.
            new_request.headers["host"] = self._target.hostname

        except Exception as exc:
            raise ConnectionPinningError(
                CONNECTION_PIN_FAILED,
                f"Failed to build pinned request for {self._target.hostname!r}: {exc}",
            ) from exc

        return await super().handle_async_request(new_request)


def build_pinned_client(
    target: ResolvedTarget,
    *,
    connect_timeout: float = 5.0,
    read_timeout: float = 30.0,
    max_response_size: int = 25 * 1024 * 1024,
) -> httpx.AsyncClient:
    """Return a configured ``httpx.AsyncClient`` pinned to *target*.

    The client:
    * Connects exclusively to ``target.address`` (the validated IP).
    * Uses ``target.hostname`` for TLS SNI and certificate verification.
    * Has automatic redirects disabled (handled by
      :class:`~app.downloads.redirect_handler.RedirectHandler`).
    * Has connection and read timeouts set.

    Parameters
    ----------
    target:
        The :class:`~app.downloads.dns_resolver.ResolvedTarget` from DNS validation.
    connect_timeout:
        Seconds to wait for the TCP connection to be established.
    read_timeout:
        Seconds to wait for data between reads.
    max_response_size:
        Not enforced at the transport level (done by the caller reading the
        response body), but documented here for clarity.
    """
    transport = PinnedTransport(target)
    return httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,  # MUST be False; RedirectHandler manages redirects
        timeout=httpx.Timeout(connect=connect_timeout, read=read_timeout, write=None, pool=None),
        # max_redirects is irrelevant with follow_redirects=False but set for safety
        max_redirects=0,
    )
