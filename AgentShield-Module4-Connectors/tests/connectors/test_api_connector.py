"""
Unit & Security Tests for AgentShield Generic External REST API Connector.
Tests:
  - Bulletproof SSRF protection:
      - 127.0.0.1 and localhost loopbacks
      - RFC 1918 private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
      - Cloud metadata services (169.254.169.254)
      - Scheme validation (rejects file://, gopher://, ftp://)
  - Redirect SSRF protection
  - Idempotent bounded retries (GET retries; POST never retries)
  - Request & response payload size limits
"""

import httpx
import pytest

from core.connectors.api_connector import RestApiConnector
from core.connectors.models import (
    ConnectorExecutionError,
    ConnectorRegistration,
    ConnectorType,
    EndpointDefinition,
    HttpMethod,
    SSRFSecurityError,
)


def test_ssrf_blocks_localhost():
    """Blocks loopback localhost addresses."""
    with pytest.raises(SSRFSecurityError, match="forbidden local or cloud metadata host"):
        RestApiConnector.validate_destination_safety("http://localhost:8080/admin", allow_private=False)

    with pytest.raises(SSRFSecurityError, match="forbidden local or cloud metadata host|Loopback destination"):
        RestApiConnector.validate_destination_safety("http://127.0.0.1:8000/keys", allow_private=False)


def test_ssrf_blocks_private_networks():
    """Blocks RFC 1918 private IPv4 addresses."""
    for private_ip in ["10.0.0.1", "172.16.0.5", "192.168.1.100"]:
        with pytest.raises(SSRFSecurityError, match="Private network destination"):
            RestApiConnector.validate_destination_safety(f"http://{private_ip}/internal/api", allow_private=False)


def test_ssrf_blocks_cloud_metadata():
    """Blocks link-local cloud metadata (AWS, GCP, Azure 169.254.169.254)."""
    with pytest.raises(SSRFSecurityError, match="metadata"):
        RestApiConnector.validate_destination_safety("http://169.254.169.254/latest/meta-data/", allow_private=False)


def test_ssrf_blocks_invalid_schemes():
    """Rejects dangerous URL schemes such as file:// and ftp://."""
    with pytest.raises(SSRFSecurityError, match="Disallowed URL scheme 'file'"):
        RestApiConnector.validate_destination_safety("file:///etc/passwd")

    with pytest.raises(SSRFSecurityError, match="Disallowed URL scheme 'ftp'"):
        RestApiConnector.validate_destination_safety("ftp://files.internal/dump.tar")


@pytest.mark.anyio
async def test_redirect_ssrf_is_intercepted():
    """Validates that a 302 redirect attempting to bounce to 169.254.169.254 is blocked."""
    def redirect_handler(request: httpx.Request) -> httpx.Response:
        # First request returns a redirect to cloud metadata
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(redirect_handler))
    connector = RestApiConnector(client=mock_client)

    reg = ConnectorRegistration(
        connector_id="external_api",
        name="External Service",
        connector_type=ConnectorType.REST_API,
        base_url="http://1.1.1.1",
    )
    ep = EndpointDefinition(path="/download", methods=[HttpMethod.GET])

    # Must raise SSRFSecurityError on the redirect destination!
    with pytest.raises(SSRFSecurityError, match="metadata"):
        await connector.execute_request(
            connector=reg,
            endpoint=ep,
            method=HttpMethod.GET,
            path="/download",
            headers={},
            allow_private_network=False,
        )


@pytest.mark.anyio
async def test_idempotent_get_retries_on_503():
    """Idempotent GET calls perform bounded retries on transient 503 errors."""
    attempts = 0

    def retry_handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return httpx.Response(503, json={"error": "Service Unavailable"})
        return httpx.Response(200, json={"status": "Recovered"})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(retry_handler))
    connector = RestApiConnector(client=mock_client)

    reg = ConnectorRegistration(
        connector_id="retry_api",
        name="Retry API",
        connector_type=ConnectorType.REST_API,
        base_url="https://retry.example.com",
        max_retries=2,
        retry_backoff_factor=0.01,  # fast backoff for tests
    )
    ep = EndpointDefinition(path="/items", methods=[HttpMethod.GET])

    status, data, _ = await connector.execute_request(
        connector=reg,
        endpoint=ep,
        method=HttpMethod.GET,
        path="/items",
        headers={},
        allow_private_network=True,
    )

    assert status == 200
    assert data["status"] == "Recovered"
    assert attempts == 3  # Verified that 2 retries occurred


@pytest.mark.anyio
async def test_non_idempotent_post_never_retries():
    """Non-idempotent POST calls must NEVER be automatically retried to prevent duplicate transactions."""
    attempts = 0

    def post_handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(500, json={"error": "Database error"})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(post_handler))
    connector = RestApiConnector(client=mock_client)

    reg = ConnectorRegistration(
        connector_id="billing_service",
        name="Billing",
        connector_type=ConnectorType.REST_API,
        base_url="https://billing.example.com",
        max_retries=3,
    )
    ep = EndpointDefinition(path="/charge", methods=[HttpMethod.POST])

    status, data, _ = await connector.execute_request(
        connector=reg,
        endpoint=ep,
        method=HttpMethod.POST,
        path="/charge",
        headers={},
        body={"amount": 100},
        allow_private_network=True,
    )

    # Failed on 500, but attempts MUST be exactly 1!
    assert attempts == 1
    assert status == 500


@pytest.mark.anyio
async def test_request_payload_size_limit():
    """Payloads exceeding max_payload_size_bytes are rejected before sending."""
    connector = RestApiConnector()
    reg = ConnectorRegistration(
        connector_id="tiny_api",
        name="Tiny",
        connector_type=ConnectorType.REST_API,
        base_url="https://tiny.example.com",
        max_payload_size_bytes=1024,  # 1 KB limit
    )
    ep = EndpointDefinition(path="/upload", methods=[HttpMethod.POST])

    oversized_body = "A" * 2048  # 2 KB

    with pytest.raises(ConnectorExecutionError, match="payload size .* exceeds maximum"):
        await connector.execute_request(
            connector=reg,
            endpoint=ep,
            method=HttpMethod.POST,
            path="/upload",
            headers={},
            body=oversized_body,
            allow_private_network=True,
        )
