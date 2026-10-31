"""
Outbound security policy for the document-analysis provider.

The analysis adapter is a second egress path.  It does not inherit anything
from the downloader implicitly: this module builds its own transport chain and
enforces, explicitly:

* HTTPS for real providers.  Plain HTTP is accepted only for a loopback
  endpoint when ANALYSIS_ALLOW_INSECURE_LOCAL is set, which is refused in
  production-like environments and flagged by the security-configuration
  check.
* Port policy: HTTPS endpoints must use port 443; insecure local endpoints
  may use any port (test servers bind an ephemeral port).
* No credentials in the URL (rejected by Settings) — the bearer token is sent
  in a header and never appears in logs or errors.
* Destination IP policy at dispatch time, via the same
  ``DnsRevalidatingTransport`` used for downloads, with private/loopback/
  link-local/metadata addresses rejected unless
  ANALYSIS_ALLOW_PRIVATE_ENDPOINTS is set (local testing only).  This is a
  per-request gate check, not IP pinning — the same rebinding caveat as the
  download path applies (see README).
* The egress proxy, when configured, is used exactly as for downloads —
  authorized with PROXY_AUTH_TOKEN and attested as enforcing before every
  request.  No proxy is ever read from HTTP(S)_PROXY or other environment
  variables: the httpx clients are built with ``trust_env=False`` and an
  explicit transport.
* Redirects are never followed.  A 3xx response is an error, so the bearer
  token cannot be forwarded to an unexpected destination.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from config.settings import LOCAL_ENDPOINT_HOSTS, Settings
from security.dns_revalidation import DnsRevalidatingTransport
from security.errors import ANALYSIS_ENDPOINT_BLOCKED, DownloadSecurityError
from security.ip_policy import is_blocked_ip, parse_ip
from security.proxy_auth import build_authorized_proxy_url
from security.proxy_enforcement import (
    DEFAULT_HEALTH_CACHE_TTL_SECONDS,
    EnforcingProxyTransport,
)
from security.ssrf import SsrfGuard, SystemDnsResolver

logger = logging.getLogger(__name__)

ANALYSIS_HTTPS_PORT = 443


@dataclass(frozen=True)
class AnalysisEndpoint:
    url: str
    scheme: str
    hostname: str
    port: int


def validate_analysis_endpoint(
    endpoint_url: str,
    *,
    allow_insecure_local: bool,
    allow_private_endpoints: bool,
) -> AnalysisEndpoint:
    """
    Validate the configured provider endpoint.

    Raises DownloadSecurityError(ANALYSIS_ENDPOINT_BLOCKED) with a message
    that contains the scheme/host condition only — never a token.
    """
    parsed = urlparse(endpoint_url or "")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DownloadSecurityError(
            ANALYSIS_ENDPOINT_BLOCKED,
            "The analysis endpoint must be an absolute HTTP(S) URL.",
        )
    if parsed.username is not None or parsed.password is not None:
        raise DownloadSecurityError(
            ANALYSIS_ENDPOINT_BLOCKED,
            "The analysis endpoint must not embed credentials.",
        )

    hostname = parsed.hostname.lower()
    port = parsed.port or (ANALYSIS_HTTPS_PORT if parsed.scheme == "https" else 80)

    if parsed.scheme == "http":
        if not allow_insecure_local:
            raise DownloadSecurityError(
                ANALYSIS_ENDPOINT_BLOCKED,
                "The analysis endpoint must use https.",
            )
        if hostname not in LOCAL_ENDPOINT_HOSTS:
            raise DownloadSecurityError(
                ANALYSIS_ENDPOINT_BLOCKED,
                "Plain-HTTP analysis endpoints are restricted to loopback hosts.",
            )
    elif port != ANALYSIS_HTTPS_PORT:
        raise DownloadSecurityError(
            ANALYSIS_ENDPOINT_BLOCKED,
            "The analysis endpoint must use the standard HTTPS port (443).",
        )

    literal = parse_ip(hostname)
    if literal is not None and is_blocked_ip(
        hostname, allow_private=allow_private_endpoints
    ):
        raise DownloadSecurityError(
            ANALYSIS_ENDPOINT_BLOCKED,
            "The analysis endpoint address is in a restricted range.",
        )

    return AnalysisEndpoint(
        url=endpoint_url, scheme=parsed.scheme, hostname=hostname, port=port
    )


class DestinationCheckTransport(httpx.AsyncBaseTransport):
    """
    Last-line check that the request URL is still the configured endpoint.

    httpx is built with redirects disabled, so this is a structural guard
    against a future code path handing the client a different URL: any mismatch
    is rejected before the request leaves the process.
    """

    def __init__(
        self,
        *,
        wrapped: httpx.AsyncBaseTransport,
        endpoint: AnalysisEndpoint,
    ) -> None:
        self._wrapped = wrapped
        self._endpoint = endpoint

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        target = request.url
        expected = urlparse(self._endpoint.url)
        if (
            target.scheme != expected.scheme
            or (target.host or "").lower() != self._endpoint.hostname
            or (target.port or (443 if target.scheme == "https" else 80))
            != self._endpoint.port
        ):
            raise DownloadSecurityError(
                ANALYSIS_ENDPOINT_BLOCKED,
                "The analysis request target does not match the configured endpoint.",
            )
        return await self._wrapped.handle_async_request(request)

    async def aclose(self) -> None:
        await self._wrapped.aclose()


def build_analysis_transport(
    *,
    settings: Settings,
    endpoint: AnalysisEndpoint,
) -> httpx.AsyncBaseTransport:
    """
    Build the explicit transport chain for one provider request.

    The chain (innermost → outermost):

        AsyncHTTPTransport(proxy=... or direct)
          DnsRevalidatingTransport       per-request DNS/IP re-check
          EnforcingProxyTransport        per-request proxy attestation [proxy set]
          DestinationCheckTransport      target still equals the endpoint
    """
    proxy_url = (
        settings.egress_proxy_url if settings.analysis_use_egress_proxy else ""
    )
    authorized_proxy = build_authorized_proxy_url(
        proxy_url, settings.proxy_auth_token
    ) or None

    base = httpx.AsyncHTTPTransport(proxy=authorized_proxy, verify=True)
    guard = SsrfGuard(
        resolver=SystemDnsResolver(),
        allow_private_networks=settings.analysis_allow_private_endpoints,
    )
    chain: httpx.AsyncBaseTransport = DnsRevalidatingTransport(
        wrapped=base,
        ssrf_guard=guard,
        allow_private=settings.analysis_allow_private_endpoints,
    )
    if proxy_url:
        chain = EnforcingProxyTransport(
            wrapped=chain,
            health_url=settings.egress_proxy_health_url,
            health_cache_ttl=DEFAULT_HEALTH_CACHE_TTL_SECONDS,
        )
    return DestinationCheckTransport(wrapped=chain, endpoint=endpoint)
