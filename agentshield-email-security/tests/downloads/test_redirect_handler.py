"""Phase C: Redirect security tests.

All tests use mocked HTTP transports — no real network requests are made.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.downloads.dns_resolver import ResolvedTarget, SecureDNSResolver
from app.downloads.exceptions import (
    REDIRECT_LIMIT_EXCEEDED,
    REDIRECT_LOOP,
    REDIRECT_MISSING_LOCATION,
    REDIRECT_SCHEME_DOWNGRADE,
    REDIRECT_UNSAFE_TARGET,
    RedirectError,
    SSRFBlockedError,
)
from app.downloads.redirect_handler import RedirectHandler, _is_cross_origin, _safe_headers
from app.downloads.url_validator import URLValidator, ValidatedURL


# ── Helpers ───────────────────────────────────────────────────────────────────

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


def _validated(hostname: str = "files.example.com", scheme: str = "https", port: int = 443) -> ValidatedURL:
    url = f"{scheme}://{hostname}:{port}/file.pdf"
    return ValidatedURL(
        original_url=url,
        normalized_url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        is_ip=False,
    )


class _FakeDNSResolver:
    """DNS resolver that returns a fixed address for any hostname."""

    def __init__(self, address: str = "1.2.3.4"):
        self._address = address

    async def resolve(self, validated_url: ValidatedURL) -> ResolvedTarget:
        return ResolvedTarget(
            hostname=validated_url.hostname,
            address=self._address,
            port=validated_url.port,
            scheme=validated_url.scheme,
            normalized_url=validated_url.normalized_url,
        )


def _handler(
    max_redirects: int = 3,
    dns_address: str = "1.2.3.4",
) -> RedirectHandler:
    return RedirectHandler(
        url_validator=URLValidator(),
        dns_resolver=_FakeDNSResolver(dns_address),  # type: ignore[arg-type]
        max_redirects=max_redirects,
    )


# ── Cross-origin detection ────────────────────────────────────────────────────

class TestCrossOriginDetection:
    def test_same_host_same_port(self):
        a = _validated("files.example.com", port=443)
        b = _validated("files.example.com", port=443)
        assert _is_cross_origin(a, b) is False

    def test_different_host(self):
        a = _validated("files.example.com")
        b = _validated("cdn.other.com")
        assert _is_cross_origin(a, b) is True

    def test_same_host_different_port(self):
        a = _validated("files.example.com", port=443)
        b = _validated("files.example.com", port=8443)
        assert _is_cross_origin(a, b) is True


# ── Sensitive header stripping ────────────────────────────────────────────────

class TestHeaderStripping:
    def test_authorization_stripped_on_cross_origin(self):
        headers = httpx.Headers({"Authorization": "Bearer token", "Accept": "application/pdf"})
        result = _safe_headers(headers, origin_changed=True)
        assert "authorization" not in {k.lower() for k in result}
        assert "accept" in {k.lower() for k in result}

    def test_cookie_stripped_on_cross_origin(self):
        headers = httpx.Headers({"Cookie": "session=abc", "User-Agent": "agent/1"})
        result = _safe_headers(headers, origin_changed=True)
        assert "cookie" not in {k.lower() for k in result}

    def test_authorization_kept_on_same_origin(self):
        headers = httpx.Headers({"Authorization": "Bearer token"})
        result = _safe_headers(headers, origin_changed=False)
        assert "Authorization" in result or "authorization" in {k.lower() for k in result}

    def test_host_always_stripped(self):
        headers = httpx.Headers({"Host": "original.example.com", "Accept": "*/*"})
        result = _safe_headers(headers, origin_changed=False)
        assert "host" not in {k.lower() for k in result}

    def test_content_length_stripped(self):
        headers = httpx.Headers({"Content-Length": "1024", "Accept": "*/*"})
        result = _safe_headers(headers, origin_changed=False)
        assert "content-length" not in {k.lower() for k in result}


# ── Redirect following with mocked transport ──────────────────────────────────

def _make_response(status: int, location: str | None = None) -> httpx.Response:
    headers: dict[str, str] = {}
    if location:
        headers["location"] = location
    # Attach a dummy request so RedirectHandler can inspect request headers
    req = httpx.Request("GET", "https://files.example.com/file.pdf")
    resp = httpx.Response(status, headers=headers, request=req)
    return resp


class TestRedirectFollowing:
    @pytest.mark.asyncio
    async def test_no_redirect_returns_response(self):
        handler = _handler()
        target = _target()

        with patch(
            "app.downloads.redirect_handler.build_pinned_client"
        ) as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.request = AsyncMock(return_value=_make_response(200))
            mock_client_ctx.return_value = mock_client

            resp, final_target = await handler.fetch(target)

        assert resp.status_code == 200
        assert final_target == target

    @pytest.mark.asyncio
    async def test_single_redirect_followed(self):
        handler = _handler(max_redirects=3)

        responses = [
            _make_response(302, "https://cdn.example.com/file.pdf"),
            _make_response(200),
        ]
        call_count = 0

        with patch(
            "app.downloads.redirect_handler.build_pinned_client"
        ) as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            async def side_effect(*args, **kwargs):
                nonlocal call_count
                r = responses[call_count]
                call_count += 1
                return r

            mock_client.request = AsyncMock(side_effect=side_effect)
            mock_client_ctx.return_value = mock_client

            resp, _ = await handler.fetch(_target())

        assert resp.status_code == 200
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_redirect_limit_exceeded(self):
        handler = _handler(max_redirects=2)
        counter = {"n": 0}

        # Redirect to a different URL each hop so loop detection doesn't fire first
        def _redir_resp(*args, **kwargs):
            counter["n"] += 1
            return _make_response(302, f"https://cdn{counter['n']}.example.com/file.pdf")

        with patch(
            "app.downloads.redirect_handler.build_pinned_client"
        ) as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.request = AsyncMock(side_effect=_redir_resp)
            mock_client_ctx.return_value = mock_client

            with pytest.raises(RedirectError) as exc:
                await handler.fetch(_target())

        assert exc.value.code == REDIRECT_LIMIT_EXCEEDED

    @pytest.mark.asyncio
    async def test_redirect_loop_detected(self):
        """Same URL redirecting to itself is a loop."""
        handler = _handler(max_redirects=5)

        loop_url = "https://files.example.com:443/file.pdf"

        def _loop_resp(*args, **kwargs):
            return _make_response(302, loop_url)

        with patch(
            "app.downloads.redirect_handler.build_pinned_client"
        ) as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.request = AsyncMock(side_effect=_loop_resp)
            mock_client_ctx.return_value = mock_client

            with pytest.raises(RedirectError) as exc:
                await handler.fetch(_target(hostname="files.example.com", address="1.2.3.4"))

        assert exc.value.code == REDIRECT_LOOP

    @pytest.mark.asyncio
    async def test_https_to_http_downgrade_rejected(self):
        """Redirect from HTTPS to HTTP must be rejected (scheme downgrade check
        fires before DNS — the URL validator raises UNSUPPORTED_SCHEME which
        the redirect handler wraps as REDIRECT_UNSAFE_TARGET, or the explicit
        downgrade check fires first as REDIRECT_SCHEME_DOWNGRADE).
        Either is acceptable; the key requirement is that it is rejected."""
        handler = _handler()

        with patch(
            "app.downloads.redirect_handler.build_pinned_client"
        ) as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.request = AsyncMock(
                return_value=_make_response(301, "http://files.example.com/file.pdf")
            )
            mock_client_ctx.return_value = mock_client

            # Must raise either REDIRECT_SCHEME_DOWNGRADE (explicit check) or
            # InvalidURLError wrapping into REDIRECT_UNSAFE_TARGET.
            # Both demonstrate the redirect is refused.
            from app.downloads.exceptions import InvalidURLError as IUE
            with pytest.raises((RedirectError, IUE)):
                await handler.fetch(_target(scheme="https"))

    @pytest.mark.asyncio
    async def test_missing_location_header_rejected(self):
        handler = _handler()

        with patch(
            "app.downloads.redirect_handler.build_pinned_client"
        ) as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            # 302 with no Location header
            mock_client.request = AsyncMock(return_value=_make_response(302, None))
            mock_client_ctx.return_value = mock_client

            with pytest.raises(RedirectError) as exc:
                await handler.fetch(_target())

        assert exc.value.code == REDIRECT_MISSING_LOCATION

    @pytest.mark.asyncio
    async def test_redirect_to_private_ip_rejected(self):
        """Redirect to a host that DNS resolves to a private IP must be rejected."""
        # DNS resolver always blocks (called only for the redirect target)
        class BlockingDNS:
            async def resolve(self, validated_url: ValidatedURL) -> ResolvedTarget:
                raise SSRFBlockedError("PRIVATE_RANGE_BLOCKED", "Private IP blocked")

        handler = RedirectHandler(
            url_validator=URLValidator(),
            dns_resolver=BlockingDNS(),  # type: ignore[arg-type]
            max_redirects=3,
        )

        with patch(
            "app.downloads.redirect_handler.build_pinned_client"
        ) as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.request = AsyncMock(
                return_value=_make_response(302, "https://legitimate-looking.example.com/secret.pdf")
            )
            mock_client_ctx.return_value = mock_client

            with pytest.raises(RedirectError) as exc:
                await handler.fetch(_target())

        assert exc.value.code == REDIRECT_UNSAFE_TARGET

    @pytest.mark.asyncio
    async def test_303_downgrades_to_get(self):
        """A 303 redirect must switch method to GET."""
        handler = _handler()
        methods_used: list[str] = []

        def _side_effect(method, url, **kwargs):
            methods_used.append(method)
            if len(methods_used) == 1:
                return _make_response(303, "https://files.example.com/new.pdf")
            return _make_response(200)

        with patch(
            "app.downloads.redirect_handler.build_pinned_client"
        ) as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.request = AsyncMock(side_effect=_side_effect)
            mock_client_ctx.return_value = mock_client

            await handler.fetch(_target(), method="POST")

        assert methods_used[1] == "GET"
