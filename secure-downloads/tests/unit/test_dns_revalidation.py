"""
Tests for connection-level DNS re-validation (DnsRevalidatingTransport).

What these tests establish:
1. A hostname that resolves to a blocked IP at dispatch time is rejected before
   the wrapped transport is invoked.
2. Every A/AAAA record in the answer is validated; one blocked record rejects.
3. Requests reach the wrapped transport unchanged (URL, Host and headers
   preserved), so SNI and certificate verification stay correct.
4. Redirect destinations are re-validated on each dispatch.
5. Literal IP targets are policy-checked without a lookup.

What these tests deliberately do NOT claim: the transport does not pin the
connection to a validated address.  The residual rebinding window is exercised
against a real socket in tests/integration/test_downloader_http.py.

Mock transports and injectable DNS stubs are used here so the resolution
sequence can be controlled per lookup.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from security.dns_revalidation import DnsRevalidatingTransport
from security.errors import PRIVATE_IP_BLOCKED, DownloadSecurityError
from security.ssrf import SsrfGuard
from security.url_validator import DownloadUrlValidator, ValidatedDownloadUrl
from tests.conftest import FakeDnsResolver, SequenceDnsResolver


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


def make_validated_url(hostname: str = "trusted.example.com") -> ValidatedDownloadUrl:
    return ValidatedDownloadUrl(
        url=f"https://{hostname}/file.pdf",
        scheme="https",
        hostname=hostname,
        port=443,
        is_ip=False,
    )


def make_guard(addresses: list[str]) -> SsrfGuard:
    dns = FakeDnsResolver({"trusted.example.com": addresses})
    return SsrfGuard(resolver=dns, allow_private_networks=False)


def make_transport(guard: SsrfGuard, wrapped) -> DnsRevalidatingTransport:
    return DnsRevalidatingTransport(
        wrapped=wrapped,
        ssrf_guard=guard,
        allow_private=False,
    )


def recording_transport(response: httpx.Response | None = None):
    """A wrapped transport that records whether it was reached."""
    transport = MagicMock(spec=httpx.AsyncBaseTransport)
    transport.handle_async_request = AsyncMock(
        return_value=response or httpx.Response(200)
    )
    return transport


# ─────────────────────────────────────────────────────────────────────────────
# 1. BLOCKED RESOLUTION AT DISPATCH TIME
# ─────────────────────────────────────────────────────────────────────────────

class TestBlockedResolutionAtDispatch:
    """
    The lookup performed immediately before the request is dispatched is what
    rejects the request: the wrapped transport is never reached when the answer
    contains a blocked address.
    """

    async def test_private_ip_at_dispatch_blocked(self):
        transport = make_transport(make_guard(["10.0.0.5"]), recording_transport())
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(request)

        assert exc_info.value.code == PRIVATE_IP_BLOCKED
        transport._wrapped.handle_async_request.assert_not_called()

    async def test_loopback_at_dispatch_blocked(self):
        transport = make_transport(make_guard(["127.0.0.1"]), recording_transport())
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(request)

        assert exc_info.value.code == PRIVATE_IP_BLOCKED
        transport._wrapped.handle_async_request.assert_not_called()

    async def test_metadata_ip_at_dispatch_blocked(self):
        transport = make_transport(
            make_guard(["169.254.169.254"]), recording_transport()
        )
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(request)

        assert exc_info.value.code == PRIVATE_IP_BLOCKED
        transport._wrapped.handle_async_request.assert_not_called()

    async def test_consistent_public_ip_passes(self):
        """When DNS returns a public IP at dispatch time, the request proceeds."""
        inner = recording_transport(httpx.Response(200, content=b"file content"))
        transport = make_transport(make_guard(["93.184.216.34"]), inner)
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        response = await transport.handle_async_request(request)

        assert response.status_code == 200
        inner.handle_async_request.assert_called_once()

    async def test_mixed_addresses_with_one_private_blocked(self):
        """One blocked address in a mixed answer rejects the whole request."""
        transport = make_transport(
            make_guard(["93.184.216.34", "10.0.0.1"]), recording_transport()
        )
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(request)

        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_public_answer_then_blocked_answer_blocked(self):
        """
        The rebinding sequence the old tests could not express: the first lookup
        (preflight) returns a public address and the second lookup (dispatch)
        returns a blocked one.  The dispatch-time lookup rejects the request.
        """
        resolver = SequenceDnsResolver(
            {"trusted.example.com": [["93.184.216.34"], ["169.254.169.254"]]}
        )
        guard = SsrfGuard(resolver=resolver, allow_private_networks=False)

        # Preflight sees the safe answer and passes.
        await guard.resolve_and_validate(make_validated_url())

        inner = recording_transport()
        transport = make_transport(guard, inner)
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(request)

        assert exc_info.value.code == PRIVATE_IP_BLOCKED
        inner.handle_async_request.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# 2. ALL A/AAAA RECORDS VALIDATED
# ─────────────────────────────────────────────────────────────────────────────

class TestAllRecordsValidated:
    """
    Every A and AAAA record returned is validated; a single blocked address in
    the result set blocks the entire request.
    """

    async def test_multiple_ipv4_all_public_passes(self):
        transport = make_transport(
            make_guard(["93.184.216.34", "93.184.216.35"]),
            recording_transport(httpx.Response(200, content=b"ok")),
        )
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        response = await transport.handle_async_request(request)

        assert response.status_code == 200

    async def test_multiple_ipv4_one_private_blocked(self):
        transport = make_transport(
            make_guard(["93.184.216.34", "172.16.0.1", "93.184.216.35"]),
            recording_transport(),
        )
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(request)

        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_ipv6_loopback_blocked(self):
        transport = make_transport(make_guard(["::1"]), recording_transport())
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(request)

        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_ipv4_mapped_ipv6_blocked(self):
        """::ffff:127.0.0.1 must be unwrapped and treated as loopback."""
        transport = make_transport(
            make_guard(["::ffff:127.0.0.1"]), recording_transport()
        )
        request = httpx.Request("GET", "https://trusted.example.com/file.pdf")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(request)

        assert exc_info.value.code == PRIVATE_IP_BLOCKED


# ─────────────────────────────────────────────────────────────────────────────
# 3. REQUEST INTEGRITY (SNI / certificate verification preserved)
# ─────────────────────────────────────────────────────────────────────────────

class TestTlsHostnameVerification:
    """
    The transport does not modify the request URL or TLS settings: the
    underlying transport connects using the original hostname, preserving SNI
    and certificate verification — which is also why the connection cannot be
    pinned to the validated IP from here.
    """

    def _capturing_transport(self, guard: SsrfGuard):
        captured: dict[str, httpx.Request] = {}
        mock_transport = MagicMock(spec=httpx.AsyncBaseTransport)

        async def capture_request(req):
            captured["request"] = req
            return httpx.Response(200, content=b"ok")

        mock_transport.handle_async_request = capture_request
        return make_transport(guard, mock_transport), captured

    async def test_request_url_preserved(self):
        transport, captured = self._capturing_transport(make_guard(["93.184.216.34"]))
        original_url = "https://trusted.example.com/file.pdf"

        await transport.handle_async_request(httpx.Request("GET", original_url))

        # Not rewritten to an IP address — TLS SNI and certificate verification
        # depend on the hostname staying in the URL.
        assert str(captured["request"].url) == original_url

    async def test_request_headers_preserved(self):
        transport, captured = self._capturing_transport(make_guard(["93.184.216.34"]))
        request = httpx.Request(
            "GET",
            "https://trusted.example.com/file.pdf",
            headers={"X-Custom": "value", "User-Agent": "test"},
        )

        await transport.handle_async_request(request)

        assert captured["request"].headers["x-custom"] == "value"
        assert captured["request"].headers["host"] == "trusted.example.com"


# ─────────────────────────────────────────────────────────────────────────────
# 4. REDIRECTS CANNOT BYPASS DESTINATION VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

class TestRedirectValidation:
    """
    The transport validates DNS for every request, including redirect
    destinations, in addition to the downloader's per-hop preflight.
    """

    def sequential_transport(self, responses: list[httpx.Response]):
        mock_transport = MagicMock(spec=httpx.AsyncBaseTransport)
        calls = {"n": 0}

        async def handle(req):
            response = responses[min(calls["n"], len(responses) - 1)]
            calls["n"] += 1
            return response

        mock_transport.handle_async_request = handle
        return mock_transport

    async def test_redirect_destination_dns_revalidated(self):
        """
        A redirect from a safe host to a host resolving to a private IP is
        blocked on the second request.
        """
        dns = FakeDnsResolver({
            "trusted.example.com": ["93.184.216.34"],
            "evil.example.com": ["10.0.0.1"],
        })
        guard = SsrfGuard(resolver=dns, allow_private_networks=False)
        transport = make_transport(
            guard,
            self.sequential_transport(
                [
                    httpx.Response(
                        302, headers={"location": "https://evil.example.com/secret.pdf"}
                    ),
                    httpx.Response(200, content=b"should not reach here"),
                ]
            ),
        )

        first = await transport.handle_async_request(
            httpx.Request("GET", "https://trusted.example.com/file.pdf")
        )
        assert first.status_code == 302

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(
                httpx.Request("GET", "https://evil.example.com/secret.pdf")
            )
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_each_redirect_request_validated(self):
        """Each hop is validated; the first blocked resolution stops the chain."""
        dns = FakeDnsResolver({
            "trusted.example.com": ["93.184.216.34"],
            "second.example.com": ["93.184.216.35"],
            "third.example.com": ["192.168.1.1"],
        })
        guard = SsrfGuard(resolver=dns, allow_private_networks=False)
        transport = make_transport(
            guard,
            self.sequential_transport(
                [
                    httpx.Response(302, headers={"location": "https://second.example.com/2"}),
                    httpx.Response(302, headers={"location": "https://third.example.com/3"}),
                    httpx.Response(200, content=b"ok"),
                ]
            ),
        )

        r1 = await transport.handle_async_request(
            httpx.Request("GET", "https://trusted.example.com/1")
        )
        assert r1.status_code == 302
        r2 = await transport.handle_async_request(
            httpx.Request("GET", "https://second.example.com/2")
        )
        assert r2.status_code == 302

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(
                httpx.Request("GET", "https://third.example.com/3")
            )
        assert exc_info.value.code == PRIVATE_IP_BLOCKED


# ─────────────────────────────────────────────────────────────────────────────
# 5. LITERAL IP TARGETS
# ─────────────────────────────────────────────────────────────────────────────

class TestLiteralIpTargets:
    """Literal IP targets skip DNS but are still checked against IP policy."""

    async def test_literal_public_ip_passes(self):
        guard = SsrfGuard(resolver=FakeDnsResolver(), allow_private_networks=False)
        transport = make_transport(
            guard, recording_transport(httpx.Response(200, content=b"ok"))
        )

        response = await transport.handle_async_request(
            httpx.Request("GET", "https://93.184.216.34/file.pdf")
        )

        assert response.status_code == 200

    async def test_literal_private_ip_blocked(self):
        guard = SsrfGuard(resolver=FakeDnsResolver(), allow_private_networks=False)
        transport = make_transport(guard, recording_transport())

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(
                httpx.Request("GET", "https://10.0.0.1/secret")
            )
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_literal_loopback_blocked(self):
        guard = SsrfGuard(resolver=FakeDnsResolver(), allow_private_networks=False)
        transport = make_transport(guard, recording_transport())

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(
                httpx.Request("GET", "https://127.0.0.1/secret")
            )
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_literal_metadata_ip_blocked(self):
        guard = SsrfGuard(resolver=FakeDnsResolver(), allow_private_networks=False)
        transport = make_transport(guard, recording_transport())

        with pytest.raises(DownloadSecurityError) as exc_info:
            await transport.handle_async_request(
                httpx.Request("GET", "https://169.254.169.254/latest/meta-data")
            )
        assert exc_info.value.code == PRIVATE_IP_BLOCKED


# ─────────────────────────────────────────────────────────────────────────────
# 6. TRANSPORT LIFECYCLE
# ─────────────────────────────────────────────────────────────────────────────

class TestTransportLifecycle:
    async def test_aclose_delegates_to_wrapped(self):
        mock_transport = MagicMock(spec=httpx.AsyncBaseTransport)
        mock_transport.aclose = AsyncMock()
        guard = SsrfGuard(resolver=FakeDnsResolver(), allow_private_networks=False)

        await make_transport(guard, mock_transport).aclose()

        mock_transport.aclose.assert_called_once()
