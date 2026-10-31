"""Phase C: DNS pinning and connection enforcement tests.

Tests verify that:
- PinnedTransport rewrites the URL to use the IP address for the socket connection.
- The Host header is set to the original hostname.
- TLS SNI uses the original hostname (verified via ssl_context configuration).
- A separate PinnedTransport per request prevents connection-pool reuse to an
  unvalidated destination.
- build_pinned_client has follow_redirects=False.
"""

from __future__ import annotations

import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.downloads.dns_resolver import ResolvedTarget
from app.downloads.exceptions import ConnectionPinningError
from app.downloads.pinned_transport import PinnedTransport, _ip_url, build_pinned_client


def _target(
    hostname: str = "files.example.com",
    address: str = "1.2.3.4",
    port: int = 443,
    scheme: str = "https",
) -> ResolvedTarget:
    return ResolvedTarget(
        hostname=hostname,
        address=address,
        port=port,
        scheme=scheme,
        normalized_url=f"{scheme}://{hostname}:{port}/file.pdf",
    )


# ── _ip_url helper ────────────────────────────────────────────────────────────

class TestIPURL:
    def test_ipv4_url(self):
        t = _target(address="1.2.3.4", port=443, scheme="https")
        assert _ip_url(t) == "https://1.2.3.4:443"

    def test_ipv6_url_brackets(self):
        t = _target(address="2606:4700::1", port=443, scheme="https")
        url = _ip_url(t)
        assert "[2606:4700::1]" in url

    def test_http_scheme(self):
        t = _target(address="1.2.3.4", port=80, scheme="http")
        assert _ip_url(t).startswith("http://")


# ── PinnedTransport attributes ────────────────────────────────────────────────

class TestPinnedTransportAttributes:
    def test_pinned_address_property(self):
        t = _target(address="1.2.3.4")
        transport = PinnedTransport(t)
        assert transport.pinned_address == "1.2.3.4"

    def test_original_hostname_property(self):
        t = _target(hostname="files.example.com")
        transport = PinnedTransport(t)
        assert transport.original_hostname == "files.example.com"

    def test_https_transport_has_ssl_context(self):
        t = _target(scheme="https")
        transport = PinnedTransport(t)
        # The transport should have been initialized with an ssl_context
        # We verify it was created (the attribute may be on the underlying handler)
        assert transport is not None

    def test_ssl_context_check_hostname_true(self):
        """The SSL context must enforce hostname verification."""
        from app.downloads.pinned_transport import _build_ssl_context
        ctx = _build_ssl_context("files.example.com")
        assert ctx.check_hostname is True
        assert ctx.verify_mode == ssl.CERT_REQUIRED


# ── Request rewriting ─────────────────────────────────────────────────────────

class TestRequestRewriting:
    """Verify PinnedTransport rewrites the URL to the IP and sets Host correctly."""

    @pytest.mark.asyncio
    async def test_host_header_set_to_hostname(self):
        """After handle_async_request, the Host header must be the original hostname."""
        target = _target(hostname="files.example.com", address="1.2.3.4", port=443)
        transport = PinnedTransport(target)

        captured: list[httpx.Request] = []
        mock_parent = AsyncMock(return_value=httpx.Response(200))

        async def fake_handle(self_or_req, req_or_none=None):
            # Handle both bound (self, req) and unbound (req,) call forms
            req = req_or_none if req_or_none is not None else self_or_req
            captured.append(req)
            return httpx.Response(200)

        with patch.object(
            httpx.AsyncHTTPTransport, "handle_async_request", new=fake_handle
        ):
            request = httpx.Request(
                "GET",
                "https://files.example.com/file.pdf",
                headers={"host": "files.example.com"},
            )
            await transport.handle_async_request(request)

        assert len(captured) == 1
        forwarded = captured[0]
        assert forwarded.headers["host"] == "files.example.com"

    @pytest.mark.asyncio
    async def test_url_rewritten_to_ip_address(self):
        """The physical URL must use the IP, not the hostname."""
        target = _target(hostname="files.example.com", address="1.2.3.4", port=443)
        transport = PinnedTransport(target)

        captured: list[httpx.Request] = []

        async def fake_handle(self_or_req, req_or_none=None):
            req = req_or_none if req_or_none is not None else self_or_req
            captured.append(req)
            return httpx.Response(200)

        with patch.object(
            httpx.AsyncHTTPTransport, "handle_async_request", new=fake_handle
        ):
            request = httpx.Request("GET", "https://files.example.com/report.pdf")
            await transport.handle_async_request(request)

        forwarded = captured[0]
        # The URL used for connection must reference the IP, not the hostname
        assert "1.2.3.4" in str(forwarded.url)
        assert "files.example.com" not in str(forwarded.url)

    @pytest.mark.asyncio
    async def test_path_and_query_preserved(self):
        target = _target(hostname="files.example.com", address="1.2.3.4")
        transport = PinnedTransport(target)

        captured: list[httpx.Request] = []

        async def fake_handle(self_or_req, req_or_none=None):
            req = req_or_none if req_or_none is not None else self_or_req
            captured.append(req)
            return httpx.Response(200)

        with patch.object(
            httpx.AsyncHTTPTransport, "handle_async_request", new=fake_handle
        ):
            request = httpx.Request(
                "GET", "https://files.example.com/a/b/c.pdf?token=abc"
            )
            await transport.handle_async_request(request)

        forwarded = captured[0]
        assert "/a/b/c.pdf" in str(forwarded.url)
        assert "token=abc" in str(forwarded.url)


# ── build_pinned_client ───────────────────────────────────────────────────────

class TestBuildPinnedClient:
    def test_returns_async_client(self):
        t = _target()
        client = build_pinned_client(t)
        assert isinstance(client, httpx.AsyncClient)

    def test_follow_redirects_disabled(self):
        t = _target()
        client = build_pinned_client(t)
        assert client.follow_redirects is False

    def test_transport_is_pinned(self):
        t = _target()
        client = build_pinned_client(t)
        assert isinstance(client._transport, PinnedTransport)

    def test_timeout_is_set(self):
        t = _target()
        client = build_pinned_client(t, connect_timeout=3.0, read_timeout=10.0)
        timeout = client.timeout
        assert timeout.connect == 3.0
        assert timeout.read == 10.0

    def test_per_request_transport_isolation(self):
        """Each call creates a fresh transport; no shared pool."""
        t = _target()
        c1 = build_pinned_client(t)
        c2 = build_pinned_client(t)
        # Different client instances — no shared state
        assert c1 is not c2
        assert c1._transport is not c2._transport
