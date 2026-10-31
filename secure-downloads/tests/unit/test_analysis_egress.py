"""Tests for analysis egress endpoint validation and destination pinning."""
from __future__ import annotations

import httpx
import pytest

from security.analysis_egress import (
    AnalysisEndpoint,
    DestinationCheckTransport,
    validate_analysis_endpoint,
)
from security.errors import ANALYSIS_ENDPOINT_BLOCKED, DownloadSecurityError


def validate(url: str, *, insecure=False, private=False) -> AnalysisEndpoint:
    return validate_analysis_endpoint(
        url, allow_insecure_local=insecure, allow_private_endpoints=private
    )


class TestEndpointValidation:
    def test_https_standard_port_accepted(self):
        endpoint = validate("https://analysis.example.com/v1/analyze")
        assert endpoint.scheme == "https"
        assert endpoint.port == 443
        assert endpoint.hostname == "analysis.example.com"

    def test_https_non_standard_port_rejected(self):
        with pytest.raises(DownloadSecurityError) as exc:
            validate("https://analysis.example.com:8443/v1/analyze")
        assert exc.value.code == ANALYSIS_ENDPOINT_BLOCKED

    def test_plain_http_requires_escape_hatch(self):
        with pytest.raises(DownloadSecurityError):
            validate("http://127.0.0.1:8080/analyze")

    def test_plain_http_non_loopback_rejected_even_with_escape_hatch(self):
        with pytest.raises(DownloadSecurityError):
            validate("http://analysis.example.com/analyze", insecure=True)

    def test_plain_http_loopback_accepted_with_escape_hatch(self):
        endpoint = validate(
            "http://127.0.0.1:8080/analyze", insecure=True, private=True
        )
        assert endpoint.port == 8080
        assert endpoint.scheme == "http"

    def test_credentials_in_endpoint_rejected(self):
        with pytest.raises(DownloadSecurityError):
            validate("https://user:pass@analysis.example.com/v1/analyze")

    def test_relative_url_rejected(self):
        with pytest.raises(DownloadSecurityError):
            validate("/v1/analyze")

    def test_literal_private_endpoint_blocked_by_default(self):
        with pytest.raises(DownloadSecurityError):
            validate("https://127.0.0.1/v1/analyze")

    def test_literal_private_endpoint_can_be_allowed_for_local_testing(self):
        endpoint = validate("https://127.0.0.1/v1/analyze", private=True)
        assert endpoint.hostname == "127.0.0.1"


class RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, json={"ok": True}, request=request)


class TestDestinationCheck:
    def make_transport(self, url: str) -> tuple[DestinationCheckTransport, RecordingTransport]:
        endpoint = validate(url, insecure=True, private=True)
        inner = RecordingTransport()
        return DestinationCheckTransport(wrapped=inner, endpoint=endpoint), inner

    async def test_same_endpoint_passes_through(self):
        transport, inner = self.make_transport("http://127.0.0.1:8080/analyze")
        request = httpx.Request("POST", "http://127.0.0.1:8080/analyze")

        response = await transport.handle_async_request(request)

        assert response.status_code == 200
        assert inner.requests == [request]
        await transport.aclose()

    async def test_different_host_is_rejected(self):
        transport, inner = self.make_transport("http://127.0.0.1:8080/analyze")
        request = httpx.Request("POST", "http://127.0.0.1:9999/analyze")

        with pytest.raises(DownloadSecurityError) as exc:
            await transport.handle_async_request(request)
        assert exc.value.code == ANALYSIS_ENDPOINT_BLOCKED
        assert inner.requests == []
        await transport.aclose()

    async def test_different_scheme_is_rejected(self):
        transport, inner = self.make_transport("http://localhost:8080/analyze")
        request = httpx.Request("POST", "https://localhost:8080/analyze")

        with pytest.raises(DownloadSecurityError):
            await transport.handle_async_request(request)
        assert inner.requests == []
        await transport.aclose()
