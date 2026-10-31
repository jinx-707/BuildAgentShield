"""
Tests for egress-proxy enforcement attestation (EnforcingProxyTransport).

Established behaviour:
1. A proxy whose health endpoint is unreachable, degraded, non-JSON, or whose
   payload does not explicitly say mode="enforcing" blocks the request.
2. The check runs per request (through the transport chain built by
   DownloadStreamer), with only successful results cached.
3. DownloadStreamer refuses to run a download through a configured proxy that
   has no health endpoint, and refuses to run at all without an SSRF guard.

Limitation asserted nowhere, because it is not true: these checks verify what
the proxy reports about itself.  A proxy that lies about its mode is not
detectable from here — see security/proxy_enforcement.py.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from security.dns_revalidation import DnsRevalidatingTransport
from security.errors import (
    EGRESS_PROXY_UNAVAILABLE,
    SSRF_BLOCKED,
    DownloadSecurityError,
)
from security.preflight import DownloadPreflight
from security.proxy_enforcement import EnforcingProxyTransport, assert_proxy_enforcing
from security.ssrf import SsrfGuard
from security.url_validator import DownloadUrlValidator
from tests.conftest import FakeDnsResolver


def make_validator(**kwargs) -> DownloadUrlValidator:
    defaults = dict(
        allowed_ports="443",
        allowed_domains="trusted.example.com",
        default_domain_policy="deny",
        allow_private_networks=False,
        https_only=True,
    )
    defaults.update(kwargs)
    return DownloadUrlValidator(**defaults)


def inner_transport(response: httpx.Response | None = None):
    transport = MagicMock(spec=httpx.AsyncBaseTransport)
    transport.handle_async_request = AsyncMock(
        return_value=response or httpx.Response(200, content=b"file")
    )
    return transport


class _HealthStream:
    """Async context manager standing in for httpx's streaming response."""

    def __init__(self, response: httpx.Response):
        self._response = response

    async def __aenter__(self) -> httpx.Response:
        return self._response

    async def __aexit__(self, *exc) -> bool:
        return False


class HealthPatch:
    """Patch the module-level health client used by assert_proxy_enforcing."""

    def __init__(self, response: httpx.Response | None = None, side_effect=None):
        self.response = response or httpx.Response(200, json={"status": "ok", "mode": "enforcing"})
        self.side_effect = side_effect
        self.client_cls = None

    def __enter__(self):
        patcher = patch("security.proxy_enforcement.httpx.AsyncClient")
        self.client_cls = patcher.start()
        client = self.client_cls.return_value.__aenter__.return_value
        if self.side_effect is not None:
            client.stream = MagicMock(side_effect=self.side_effect)
        else:
            client.stream = MagicMock(return_value=_HealthStream(self.response))
        self._patcher = patcher
        return self.client_cls

    def __exit__(self, *exc):
        self._patcher.stop()


# ─────────────────────────────────────────────────────────────────────────────
# 1. ATTESTATION RESULTS GATE EVERY REQUEST
# ─────────────────────────────────────────────────────────────────────────────

class TestProxyEnforcement:

    async def test_enforcing_proxy_rejects_permissive_mode(self):
        transport = EnforcingProxyTransport(
            wrapped=inner_transport(),
            health_url="http://proxy:9090/health/ready",
        )
        with HealthPatch(httpx.Response(200, json={"status": "ok", "mode": "permissive"})):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await transport.handle_async_request(
                    httpx.Request("GET", "https://example.com/file.pdf")
                )
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE
        assert "enforcing" in exc_info.value.message.lower()

    async def test_enforcing_proxy_accepts_enforcing_mode(self):
        inner = inner_transport(httpx.Response(200, content=b"file"))
        transport = EnforcingProxyTransport(
            wrapped=inner,
            health_url="http://proxy:9090/health/ready",
            health_cache_ttl=999.0,
        )
        with HealthPatch(httpx.Response(200, json={"status": "ok", "mode": "enforcing"})):
            response = await transport.handle_async_request(
                httpx.Request("GET", "https://example.com/file.pdf")
            )
        assert response.status_code == 200
        inner.handle_async_request.assert_called_once()

    async def test_enforcing_proxy_rejects_degraded_status(self):
        transport = EnforcingProxyTransport(
            wrapped=inner_transport(),
            health_url="http://proxy:9090/health/ready",
        )
        with HealthPatch(httpx.Response(200, json={"status": "degraded", "mode": "enforcing"})):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await transport.handle_async_request(
                    httpx.Request("GET", "https://example.com/file.pdf")
                )
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_enforcing_proxy_rejects_non_200_health(self):
        transport = EnforcingProxyTransport(
            wrapped=inner_transport(),
            health_url="http://proxy:9090/health/ready",
        )
        with HealthPatch(httpx.Response(503, json={})):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await transport.handle_async_request(
                    httpx.Request("GET", "https://example.com/file.pdf")
                )
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_enforcing_proxy_rejects_unreachable_health(self):
        transport = EnforcingProxyTransport(
            wrapped=inner_transport(),
            health_url="http://proxy:9090/health/ready",
        )
        with HealthPatch(side_effect=httpx.ConnectError("down")):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await transport.handle_async_request(
                    httpx.Request("GET", "https://example.com/file.pdf")
                )
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE
        inner = transport._wrapped
        inner.handle_async_request.assert_not_called()

    async def test_enforcing_proxy_rejects_missing_mode(self):
        """Fail closed: a health payload without a mode field is not proof of enforcement."""
        transport = EnforcingProxyTransport(
            wrapped=inner_transport(),
            health_url="http://proxy:9090/health/ready",
        )
        with HealthPatch(httpx.Response(200, json={"status": "ok"})):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await transport.handle_async_request(
                    httpx.Request("GET", "https://example.com/file.pdf")
                )
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_enforcing_proxy_rejects_non_json_health(self):
        transport = EnforcingProxyTransport(
            wrapped=inner_transport(),
            health_url="http://proxy:9090/health/ready",
        )
        with HealthPatch(httpx.Response(200, content=b"<html>proxy is up</html>")):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await transport.handle_async_request(
                    httpx.Request("GET", "https://example.com/file.pdf")
                )
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_no_health_url_skips_check(self):
        """
        With no attestation endpoint the transport cannot check anything, so it
        delegates.  DownloadStreamer refuses to build this configuration when a
        proxy is in use; see test_downloader_rejects_proxy_without_health_url.
        """
        inner = inner_transport(httpx.Response(200, content=b"ok"))
        transport = EnforcingProxyTransport(wrapped=inner, health_url="")
        response = await transport.handle_async_request(
            httpx.Request("GET", "https://example.com/file.pdf")
        )
        assert response.status_code == 200

    async def test_health_check_cached(self):
        """A successful attestation is cached for the configured TTL."""
        inner = inner_transport()
        transport = EnforcingProxyTransport(
            wrapped=inner,
            health_url="http://proxy:9090/health/ready",
            health_cache_ttl=999.0,
        )
        with HealthPatch() as client_cls:
            request = httpx.Request("GET", "https://example.com/file.pdf")
            await transport.handle_async_request(request)
            await transport.handle_async_request(request)
            assert client_cls.call_count == 1

    async def test_health_check_reruns_per_request_when_ttl_expired(self):
        """
        Per-connection enforcement: with no cache, every request re-attests, so
        a proxy that flips out of enforcing mode mid-download stops the next
        request instead of only the next download.
        """
        inner = inner_transport()
        transport = EnforcingProxyTransport(
            wrapped=inner,
            health_url="http://proxy:9090/health/ready",
            health_cache_ttl=0.0,
        )
        with HealthPatch() as client_cls:
            request = httpx.Request("GET", "https://example.com/file.pdf")
            await transport.handle_async_request(request)
            await transport.handle_async_request(request)
            await transport.handle_async_request(request)
            assert client_cls.call_count == 3
        assert inner.handle_async_request.call_count == 3

    async def test_failure_is_not_cached(self):
        """A rejected attestation is re-evaluated, never memoised as success."""
        transport = EnforcingProxyTransport(
            wrapped=inner_transport(),
            health_url="http://proxy:9090/health/ready",
            health_cache_ttl=999.0,
        )
        with HealthPatch(httpx.Response(200, json={"status": "ok", "mode": "permissive"})):
            with pytest.raises(DownloadSecurityError):
                await transport.handle_async_request(
                    httpx.Request("GET", "https://example.com/file.pdf")
                )
        assert transport._cache_ok is False


# ─────────────────────────────────────────────────────────────────────────────
# 2. TRANSPORT LIFECYCLE
# ─────────────────────────────────────────────────────────────────────────────

class TestTransportLifecycle:
    async def test_enforcing_proxy_aclose_delegates(self):
        mock_transport = MagicMock(spec=httpx.AsyncBaseTransport)
        mock_transport.aclose = AsyncMock()

        transport = EnforcingProxyTransport(
            wrapped=mock_transport,
            health_url="http://proxy:9090/health/ready",
        )

        await transport.aclose()
        mock_transport.aclose.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 3. SHARED PROBE
# ─────────────────────────────────────────────────────────────────────────────

class TestAssertProxyEnforcing:
    async def test_probe_rejects_unknown_mode(self):
        with HealthPatch(httpx.Response(200, json={"status": "ok", "mode": "shadow"})):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await assert_proxy_enforcing("http://proxy:9090/health/ready")
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_probe_accepts_enforcing(self):
        with HealthPatch(httpx.Response(200, json={"status": "ok", "mode": "enforcing"})):
            await assert_proxy_enforcing("http://proxy:9090/health/ready")

    async def test_probe_rejects_oversized_health_body(self):
        with HealthPatch(httpx.Response(200, content=b"x" * (64 * 1024 + 1))):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await assert_proxy_enforcing("http://proxy:9090/health/ready")
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE
        assert "too large" in exc_info.value.message.lower()

    async def test_probe_rejects_redirecting_health_endpoint(self):
        with HealthPatch(httpx.Response(302, headers={"location": "http://elsewhere/"})):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await assert_proxy_enforcing("http://proxy:9090/health/ready")
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE


# ─────────────────────────────────────────────────────────────────────────────
# 4. DOWNLOADER WIRING
# ─────────────────────────────────────────────────────────────────────────────

def make_streamer(**kwargs):
    from services.downloader import DownloadStreamer

    dns = FakeDnsResolver({"trusted.example.com": ["93.184.216.34"]})
    guard = SsrfGuard(resolver=dns, allow_private_networks=False)
    preflight = DownloadPreflight(
        url_validator=make_validator(), ssrf_guard=guard, dns_enabled=True,
    )
    storage = MagicMock()
    storage.allocate_temp_path.return_value = (MagicMock(), MagicMock(ref_string="temporary/uuid"))
    defaults = dict(
        preflight=preflight,
        storage_manager=storage,
        ssrf_guard=guard,
        egress_proxy_url="http://proxy:3128",
        egress_health_url="http://proxy:9090/health/ready",
        require_proxy=True,
    )
    defaults.update(kwargs)
    return DownloadStreamer(**defaults)


class TestDownloaderProxyEnforcement:

    async def test_downloader_rejects_non_enforcing_proxy(self):
        streamer = make_streamer()
        with HealthPatch(httpx.Response(200, json={"status": "ok", "mode": "permissive"})):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await streamer.assert_proxy_available()
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE
        assert "enforcing" in exc_info.value.message.lower()

    async def test_downloader_accepts_enforcing_proxy(self):
        streamer = make_streamer()
        with HealthPatch(httpx.Response(200, json={"status": "ok", "mode": "enforcing"})):
            await streamer.assert_proxy_available()

    async def test_downloader_rejects_missing_proxy_when_required(self):
        streamer = make_streamer(egress_proxy_url="", egress_health_url="")
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.assert_proxy_available()
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_downloader_rejects_proxy_without_health_url(self):
        """A proxy that cannot be attested is not usable — fail closed."""
        streamer = make_streamer(egress_health_url="")
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.assert_proxy_available()
        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_downloader_rejects_missing_ssrf_guard(self):
        """Without a guard there is no connection-time address validation."""
        streamer = make_streamer(ssrf_guard=None, egress_proxy_url="",
                                 egress_health_url="", require_proxy=False)
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download("https://trusted.example.com/file.pdf")
        assert exc_info.value.code == SSRF_BLOCKED

    def test_proxy_path_chain_checks_attestation_then_dns(self):
        """
        Every request on the proxied path goes through the attestation check
        before the DNS re-validation and the socket transport.
        """
        streamer = make_streamer()
        transport = streamer._build_transport()
        assert isinstance(transport, EnforcingProxyTransport)
        assert isinstance(transport._wrapped, DnsRevalidatingTransport)
        assert isinstance(transport._wrapped._wrapped, httpx.AsyncHTTPTransport)

    def test_direct_path_chain_still_validates_dns(self):
        streamer = make_streamer(egress_proxy_url="", egress_health_url="")
        transport = streamer._build_transport()
        assert isinstance(transport, DnsRevalidatingTransport)
        assert isinstance(transport._wrapped, httpx.AsyncHTTPTransport)
