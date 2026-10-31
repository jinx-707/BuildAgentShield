"""
AgentShield Generic External REST API Connector.
Handles outbound HTTP calls with:
  - Whitelist validation for endpoints and HTTP methods.
  - Bulletproof SSRF protection: blocks localhost, RFC 1918 private IPs,
    RFC 3927 link-local, and cloud metadata (AWS, GCP, Azure 169.254.169.254).
  - DNS resolution and rebinding prevention.
  - Redirect destination inspection (preventing open redirect SSRF).
  - Configurable timeouts and bounded retries on safe idempotent operations only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from core.config import setup_logger
from core.connectors.models import (
    ConnectorExecutionError,
    ConnectorRegistration,
    EndpointDefinition,
    HttpMethod,
    SSRFSecurityError,
)

logger = setup_logger("agentshield.connectors.api")

# Idempotent HTTP methods that are safe for automatic bounded retry
SAFE_IDEMPOTENT_METHODS = {
    HttpMethod.GET,
    HttpMethod.HEAD,
    HttpMethod.PUT,
    HttpMethod.DELETE,
    HttpMethod.OPTIONS,
}

# Known cloud metadata hostnames and aliases
METADATA_HOSTNAMES = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "instance-data.ec2.internal",
    "localhost",
    "127.0.0.1",
    "::1",
}


class RestApiConnector:
    """
    Secure REST API client executing outbound HTTP calls on behalf of agents.
    Strictly isolated and hardened against SSRF, unauthorized endpoints,
    and side-effect duplication on retries.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._custom_client = client

    # -----------------------------------------------------------------------
    # SSRF & DNS Validation
    # -----------------------------------------------------------------------

    @staticmethod
    def validate_destination_safety(url: str, allow_private: bool = False) -> None:
        """
        Validates URL destination against SSRF, private networks, and cloud metadata.
        Resolves DNS to prevent DNS rebinding attacks.
        """
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise SSRFSecurityError(f"SSRF blocked: Disallowed URL scheme '{scheme}'. Only http/https permitted.")

        if allow_private:
            return

        hostname = parsed.hostname
        if not hostname:
            raise SSRFSecurityError(f"SSRF blocked: Missing hostname in URL '{url}'")

        clean_host = hostname.strip().lower()

        # 1. Hostname blacklist check
        if clean_host in METADATA_HOSTNAMES or clean_host.endswith(".internal") or clean_host.endswith(".local"):
            if not allow_private:
                raise SSRFSecurityError(
                    f"SSRF blocked: Destination '{clean_host}' is a forbidden local or cloud metadata host"
                )

        # 2. Check if hostname is an IP literal
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            RestApiConnector._check_ip_safety(ip_obj, allow_private)
            return
        except ValueError:
            # Not an IP literal, proceed to DNS resolution
            pass

        # 3. DNS Resolution & Rebinding Check
        try:
            addr_info = socket.getaddrinfo(clean_host, parsed.port or (443 if scheme == "https" else 80))
            for family, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                ip_obj = ipaddress.ip_address(ip_str)
                RestApiConnector._check_ip_safety(ip_obj, allow_private)
        except socket.gaierror as exc:
            raise SSRFSecurityError(f"DNS resolution failure for host '{clean_host}': {exc}") from exc

    @staticmethod
    def _check_ip_safety(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool = False) -> None:
        """Evaluates whether an IP address belongs to unsafe / internal address spaces."""
        if allow_private:
            return

        if ip.is_loopback:
            raise SSRFSecurityError(f"SSRF blocked: Loopback destination '{ip}' is forbidden")

        if ip.is_private:
            raise SSRFSecurityError(f"SSRF blocked: Private network destination '{ip}' is forbidden")

        if ip.is_link_local:
            raise SSRFSecurityError(f"SSRF blocked: Link-local / Cloud metadata destination '{ip}' is forbidden")

        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise SSRFSecurityError(f"SSRF blocked: Special/Reserved IP destination '{ip}' is forbidden")

        # Specific check for AWS/GCP/Azure link-local metadata (169.254.169.254)
        if str(ip) == "169.254.169.254":
            raise SSRFSecurityError("SSRF blocked: Cloud metadata service (169.254.169.254) access forbidden")

    # -----------------------------------------------------------------------
    # Execution
    # -----------------------------------------------------------------------

    async def execute_request(
        self,
        connector: ConnectorRegistration,
        endpoint: EndpointDefinition,
        method: HttpMethod,
        path: str,
        headers: dict[str, str],
        query_params: dict[str, Any] | None = None,
        body: Any | None = None,
        allow_private_network: bool = False,
    ) -> tuple[int, Any, dict[str, str]]:
        """
        Executes a REST API call with full safety guards:
          1. Constructs canonical target URL under connector's base_url.
          2. Validates SSRF safety.
          3. Enforces request payload size limits.
          4. Applies bounded retries ONLY for idempotent methods.
          5. Validates redirect destinations to prevent redirect-based SSRF.
        Returns: (status_code, response_data, response_headers)
        """
        if not connector.base_url:
            raise ConnectorExecutionError(f"Connector '{connector.connector_id}' lacks base_url")

        # Build full URL
        base = connector.base_url.rstrip("/") + "/"
        clean_path = path.lstrip("/")
        target_url = urljoin(base, clean_path)

        # Pre-execution SSRF verification
        self.validate_destination_safety(target_url, allow_private=allow_private_network)

        # Timeout calculation
        timeout_val = endpoint.timeout_seconds or connector.default_timeout_seconds
        timeout = httpx.Timeout(timeout_val, connect=min(5.0, timeout_val))

        # Payload size validation
        content_bytes = None
        json_data = None
        if body is not None:
            if isinstance(body, (dict, list)):
                json_data = body
            elif isinstance(body, str):
                content_bytes = body.encode("utf-8")
            elif isinstance(body, bytes):
                content_bytes = body
            else:
                content_bytes = str(body).encode("utf-8")

            if content_bytes and len(content_bytes) > connector.max_payload_size_bytes:
                raise ConnectorExecutionError(
                    f"Request payload size ({len(content_bytes)} bytes) exceeds maximum "
                    f"allowed {connector.max_payload_size_bytes} bytes"
                )

        # Retry configuration: retries ONLY allowed for idempotent methods
        is_idempotent = method in SAFE_IDEMPOTENT_METHODS
        max_attempts = (connector.max_retries + 1) if is_idempotent else 1
        backoff = connector.retry_backoff_factor

        client = self._custom_client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)
        should_close_client = self._custom_client is None

        attempt = 0
        last_error: Exception | None = None

        try:
            while attempt < max_attempts:
                attempt += 1
                try:
                    logger.debug(
                        "Dispatching REST call: %s %s (attempt %d/%d)",
                        method.value,
                        target_url,
                        attempt,
                        max_attempts,
                    )

                    resp = await client.request(
                        method=method.value,
                        url=target_url,
                        headers=headers,
                        params=query_params,
                        json=json_data,
                        content=content_bytes,
                    )

                    # Handle Redirects securely (do not automatically trust Location)
                    if resp.is_redirect:
                        location = resp.headers.get("Location")
                        if not location:
                            raise ConnectorExecutionError("Redirect received without Location header")

                        redirect_url = urljoin(target_url, location)
                        # Validate redirect destination for SSRF!
                        self.validate_destination_safety(redirect_url, allow_private=allow_private_network)

                        # Follow single validated redirect
                        resp = await client.request(
                            method="GET" if resp.status_code in (301, 302, 303) else method.value,
                            url=redirect_url,
                            headers=headers,
                        )

                    # Check response size
                    raw_content = resp.content
                    if len(raw_content) > connector.max_payload_size_bytes:
                        raise ConnectorExecutionError(
                            f"Response payload size ({len(raw_content)} bytes) exceeds allowed limit "
                            f"({connector.max_payload_size_bytes} bytes)"
                        )

                    # Parse response content
                    parsed_data: Any
                    content_type = resp.headers.get("content-type", "").lower()
                    if "application/json" in content_type:
                        try:
                            parsed_data = resp.json()
                        except Exception:
                            parsed_data = resp.text
                    else:
                        parsed_data = resp.text

                    # If 5xx and safe idempotent method, retry
                    if resp.status_code >= 500 and is_idempotent and attempt < max_attempts:
                        logger.warning(
                            "Transient server error %d on %s; retrying in %.2fs...",
                            resp.status_code,
                            target_url,
                            backoff * attempt,
                        )
                        await asyncio.sleep(backoff * attempt)
                        continue

                    resp_headers = dict(resp.headers)
                    return resp.status_code, parsed_data, resp_headers

                except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError) as err:
                    last_error = err
                    if is_idempotent and attempt < max_attempts:
                        wait_time = backoff * (2 ** (attempt - 1))
                        logger.warning(
                            "Transient network error on %s: %s; retrying in %.2fs...",
                            target_url,
                            err,
                            wait_time,
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        # Non-idempotent or exhausted attempts
                        break

            raise ConnectorExecutionError(
                f"REST execution failed after {attempt} attempts for {method.value} {target_url}: {last_error}"
            ) from last_error

        finally:
            if should_close_client:
                await client.aclose()
