"""
Streaming file downloader.

Security properties
-------------------
- Outbound connections use the egress proxy when one is configured, and the
  streamer refuses to run with a required proxy that cannot be attested.
- Proxy enforcement is re-checked before every request (cached for a few
  seconds), not only once before the download.
- DNS is re-resolved and re-validated immediately before every request
  (DnsRevalidatingTransport).  This narrows the DNS-rebinding window; it does
  not eliminate it — see security/dns_revalidation.py.
- Every redirect destination is revalidated through preflight (URL policy +
  SSRF guard) before it is followed.
- Connection isolation across redirect hops: every hop (including the final
  one) runs on a freshly built transport and client, and the transport is
  closed when the hop ends.  A response that leaves trailing bytes on the
  wire — e.g. a body longer than its declared Content-Length followed by a
  forged HTTP response — can never have those bytes consumed as the response
  to a later request: the socket carrying them is closed before the next hop
  is dispatched.  The requests also carry "Connection: close" as a
  courtesy signal, but the isolation is enforced by transport lifetime, not
  by the header.
- The response body is streamed; it is never buffered in memory.
- Response acceptance is strict: a 2xx body is accepted only when its framing
  is consistent — single valid Content-Length, not combined with a chunked
  Transfer-Encoding, and the streamed byte count must equal the declared
  length when one is declared.  Truncated transfers (early connection
  close, broken chunk framing) are rejected as RESPONSE_INCOMPLETE.
  Chunked transfers without Content-Length remain supported; the actual
  streamed bytes — never Content-Length — determine the stored file size.
- Content-Length is never trusted: the byte counter enforces the limit while
  the transfer is still in progress and aborts it.
- SHA-256 is computed during streaming so the checksum covers the exact bytes
  subsequently scanned.
- Incomplete temporary files are deleted on error, on timeout, and on task
  cancellation (the deadline path runs in a finally block).
- The download is aborted if the total deadline is exceeded, or if an
  individual network timeout fires; both classify as DOWNLOAD_TIMEOUT.
- Proxy authentication (Basic, username "agentshield", password
  PROXY_AUTH_TOKEN) is applied to the proxy connection via httpx proxy
  credentials; a 407 from a forwarding proxy or a rejected CONNECT classifies
  as PROXY_AUTH_FAILED.  The token never appears in messages or logs.

Enforcement boundary
--------------------
With a proxy configured the proxy is the party that resolves the name and
opens the TCP connection, so it is the authoritative IP-policy boundary.  The
in-process preflight and connection-time checks are defence-in-depth on top of
it; they cannot pin a proxied connection.

Without a proxy (development only) the in-process checks are the only
boundary, and the residual rebinding window applies to them.

Configuration
-------------
- REQUIRE_EGRESS_PROXY=true: startup and download fail closed unless an egress
  proxy is configured.
- assert_proxy_available() requires the proxy health endpoint to report
  status="ok" AND mode="enforcing".  A payload without a mode field is treated
  as non-enforcing and rejected; so is any download through a configured proxy
  that has no health endpoint to attest.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from security.dns_revalidation import DnsRevalidatingTransport
from security.errors import (
    DOWNLOAD_TIMEOUT,
    EGRESS_PROXY_UNAVAILABLE,
    FILE_TOO_LARGE,
    PROXY_AUTH_FAILED,
    RESPONSE_INCOMPLETE,
    SSRF_BLOCKED,
    DownloadSecurityError,
)
from security.preflight import DownloadPreflight
from security.proxy_auth import build_authorized_proxy_url
from security.proxy_enforcement import (
    DEFAULT_HEALTH_CACHE_TTL_SECONDS,
    EnforcingProxyTransport,
    assert_proxy_enforcing,
)
from security.ssrf import SsrfGuard
from security.url_validator import ValidatedDownloadUrl
from storage.manager import StorageManager, StorageRef

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 65_536       # 64 KiB streaming chunks
_HEADER_READ_BYTES = 8_192 # bytes read to populate MimeValidator header check


class DownloadResult:
    def __init__(
        self,
        *,
        storage_ref: StorageRef,
        sha256: str,
        file_size: int,
        detected_mime: str,
        original_filename: str | None,
        final_url: str,
        redirect_count: int,
    ) -> None:
        self.storage_ref = storage_ref
        self.sha256 = sha256
        self.file_size = file_size
        self.detected_mime = detected_mime
        self.original_filename = original_filename
        self.final_url = final_url
        self.redirect_count = redirect_count


class DownloadStreamer:
    """
    Downloads a file from the network, enforcing all security constraints.

    Parameters
    ----------
    preflight:          Pre-flight check (URL validation + SSRF guard).
    storage_manager:    Where to store the streamed file.
    ssrf_guard:         SsrfGuard for connection-level DNS re-validation.
    allow_private_networks: Whether private IPs are permitted.
    egress_proxy_url:   HTTP proxy URL for all outbound connections.
    egress_health_url:  Proxy health endpoint for enforcement attestation.
    proxy_auth_token:   Optional Basic-auth password for the egress proxy
                        (username is fixed; see security/proxy_auth.py).
                        Treated as a secret — never logged, never echoed.
    max_size_bytes:     Hard byte limit; download is aborted if exceeded.
    connect_timeout_s:  TCP connection timeout.
    read_timeout_s:     Per-chunk read timeout.
    total_timeout_s:    Absolute deadline for the entire download.
    max_redirects:      Maximum number of HTTP redirects to follow.
    require_proxy:      Fail closed if no proxy is configured.
    """

    def __init__(
        self,
        *,
        preflight: DownloadPreflight,
        storage_manager: StorageManager,
        ssrf_guard: SsrfGuard | None = None,
        allow_private_networks: bool = False,
        egress_proxy_url: str = "",
        egress_health_url: str = "",
        proxy_auth_token: str = "",
        max_size_bytes: int = 52_428_800,
        connect_timeout_s: float = 10.0,
        read_timeout_s: float = 30.0,
        total_timeout_s: float = 120.0,
        max_redirects: int = 5,
        require_proxy: bool = True,
        proxy_health_cache_ttl: float = DEFAULT_HEALTH_CACHE_TTL_SECONDS,
    ) -> None:
        self._preflight = preflight
        self._storage = storage_manager
        self._ssrf_guard = ssrf_guard
        self._allow_private = allow_private_networks
        self._proxy_url = egress_proxy_url
        self._health_url = egress_health_url
        self._proxy_auth_token = proxy_auth_token
        self._max_size = max_size_bytes
        self._connect_timeout = connect_timeout_s
        self._read_timeout = read_timeout_s
        self._total_timeout = total_timeout_s
        self._max_redirects = max_redirects
        self._require_proxy = require_proxy
        self._health_cache_ttl = proxy_health_cache_ttl

    async def assert_proxy_available(self) -> None:
        """
        Verify the egress proxy is configured, reachable and enforcing.

        Fail-closed rules, in order:
        - a required proxy that is not configured is rejected;
        - a configured proxy with no health endpoint is rejected, because its
          enforcement mode cannot then be attested;
        - a health payload that is not status="ok" with mode="enforcing" is
          rejected, including when the mode field is absent.
        """
        if self._require_proxy and not self._proxy_url:
            raise DownloadSecurityError(
                EGRESS_PROXY_UNAVAILABLE,
                "The egress proxy is required but not configured.",
            )

        if self._proxy_url and not self._health_url:
            raise DownloadSecurityError(
                EGRESS_PROXY_UNAVAILABLE,
                "An egress proxy is configured but EGRESS_PROXY_HEALTH_URL is "
                "not, so its enforcement mode cannot be verified.",
            )

        if not self._proxy_url:
            return  # Direct egress (development only); no proxy to attest.

        await assert_proxy_enforcing(self._health_url)

    async def download(self, raw_url: str) -> DownloadResult:
        """
        Validate and stream the file at raw_url to temporary storage.

        Returns a DownloadResult with the storage ref and file metadata.
        The file is in StorageZone.TEMPORARY; the caller is responsible for
        moving it to quarantine or approved storage after scanning.

        Raises DownloadSecurityError on any security or network violation.
        """
        await self.assert_proxy_available()

        if self._ssrf_guard is None:
            raise DownloadSecurityError(
                SSRF_BLOCKED,
                "No SSRF guard is configured, so connection-level address "
                "validation cannot be performed.",
            )

        # Pre-flight check: URL validation + DNS/SSRF.
        validated, _resolved = await self._preflight.validate(raw_url)

        temp_path, temp_ref = self._storage.allocate_temp_path()

        accepted = False
        try:
            try:
                stream_result = await asyncio.wait_for(
                    self._stream(validated, temp_path),
                    timeout=self._total_timeout,
                )
            except TimeoutError as exc:
                raise DownloadSecurityError(
                    DOWNLOAD_TIMEOUT,
                    f"Download exceeded the total deadline of "
                    f"{self._total_timeout}s.",
                    http_status=504,
                ) from exc
            except httpx.TimeoutException as exc:
                raise DownloadSecurityError(
                    DOWNLOAD_TIMEOUT,
                    "Download exceeded a network timeout "
                    f"({type(exc).__name__}) while communicating with the origin.",
                    http_status=504,
                ) from exc
            except httpx.RemoteProtocolError as exc:
                # Header-phase protocol violation (malformed status line or
                # headers — e.g. a redirect hop that is not valid HTTP).
                # Body-phase violations are classified inside _stream.
                raise DownloadSecurityError(
                    RESPONSE_INCOMPLETE,
                    "The origin sent a malformed HTTP response; nothing was "
                    "accepted from this transfer.",
                    http_status=502,
                ) from exc
            except httpx.ProxyError as exc:
                # A rejected CONNECT from the egress proxy (e.g. HTTP 407).
                # Do not interpolate the raw exception: proxy-layer errors can
                # echo request data and must not carry credentials onward.
                logger.warning(
                    "proxy_transport_error", extra={"error_type": type(exc).__name__}
                )
                raise DownloadSecurityError(
                    PROXY_AUTH_FAILED,
                    "The egress proxy rejected the connection. If proxy "
                    "authentication is configured, verify PROXY_AUTH_TOKEN.",
                    http_status=502,
                ) from None
            accepted = True
        finally:
            # Covers deadline/protocol failures, unexpected exceptions, and
            # task cancellation (CancelledError is a BaseException, so an
            # ``except Exception`` cleanup would miss it).
            if not accepted:
                self._discard_temp(temp_path)

        return DownloadResult(
            storage_ref=temp_ref,
            sha256=stream_result["sha256"],
            file_size=stream_result["file_size"],
            detected_mime=stream_result["detected_mime"],
            original_filename=stream_result["original_filename"],
            final_url=stream_result["final_url"],
            redirect_count=stream_result["redirect_count"],
        )

    # ── Internal streaming logic ──────────────────────────────────────────────

    def _build_transport(self) -> httpx.AsyncBaseTransport:
        """
        Build the transport chain used for one request hop.

        Outermost first: proxy attestation, then DNS re-validation, then the
        real socket transport (through the egress proxy when configured).

        A fresh chain is built for every hop so no connection pool (and hence
        no keep-alive socket) can survive across redirects — see the
        response-smuggling note in the module docstring.
        """
        # When a proxy is configured all outbound connections go to the proxy
        # (CONNECT for HTTPS); otherwise the connection is direct.  Proxy
        # credentials are supplied as URL userinfo so httpx attaches
        # Proxy-Authorization to the proxy request — never to the origin.
        transport: httpx.AsyncBaseTransport = httpx.AsyncHTTPTransport(
            proxy=build_authorized_proxy_url(self._proxy_url, self._proxy_auth_token)
            or None,
            verify=True,
        )

        transport = DnsRevalidatingTransport(
            wrapped=transport,
            ssrf_guard=self._ssrf_guard,
            allow_private=self._allow_private,
        )

        if self._proxy_url:
            transport = EnforcingProxyTransport(
                wrapped=transport,
                health_url=self._health_url,
                health_cache_ttl=self._health_cache_ttl,
            )

        return transport

    async def _stream(
        self, validated: ValidatedDownloadUrl, temp_path: Path
    ) -> dict:
        """
        Stream the file from the network to temp_path.

        Handles redirects manually, revalidating each destination.  Every hop
        uses a freshly built transport chain that is closed before the next
        hop starts, so a socket that still carries unread trailing bytes from
        one response (a smuggled/forged response behind a short
        Content-Length) can never feed the next request.

        The transport chain is, innermost to outermost:

            AsyncHTTPTransport(proxy=... or direct)
              wrapped by DnsRevalidatingTransport   — re-resolves and re-checks
                the destination address before each request is dispatched
              wrapped by EnforcingProxyTransport    — re-checks proxy
                enforcement before each request (only when a proxy is set)

        Every request the client makes — the first one and each redirect hop —
        passes through both checks.  Neither check pins the connection: the
        address the socket finally uses is resolved by the innermost transport.
        """
        from security.mime_validator import MimeValidator

        assert self._ssrf_guard is not None  # set by download()

        mime_validator = MimeValidator()
        timeout = httpx.Timeout(
            connect=self._connect_timeout,
            read=self._read_timeout,
            write=10.0,
            pool=5.0,
        )

        current_url = validated.url
        redirect_count = 0
        visited_urls: set[str] = {current_url}

        while True:
            # Fresh client *and* fresh transport per hop: the socket pool dies
            # with the hop, guaranteeing redirect responses come from their
            # actual destination, not from bytes left on a reused connection.
            transport = self._build_transport()
            async with httpx.AsyncClient(
                transport=transport,
                timeout=timeout,
                follow_redirects=False,  # Manual redirect handling
                verify=True,
                # Never let HTTP(S)_PROXY / ALL_PROXY environment variables
                # inject a proxy: egress is decided by configuration only.
                trust_env=False,
            ) as client:
                async with client.stream(
                    "GET",
                    current_url,
                    headers={
                        "User-Agent": "AgentShield/1.0 SecureDownload",
                        # Courtesy signal only — the anti-reuse guarantee comes
                        # from closing the transport between hops, not from this
                        # header, because a hostile server can ignore it.
                        "Connection": "close",
                    },
                ) as response:
                    # Handle redirects manually.
                    if response.status_code in {301, 302, 303, 307, 308}:
                        if redirect_count >= self._max_redirects:
                            raise DownloadSecurityError(
                                SSRF_BLOCKED,
                                f"Too many redirects (limit: {self._max_redirects}).",
                            )
                        location = response.headers.get("location", "")
                        if not location:
                            raise DownloadSecurityError(
                                SSRF_BLOCKED,
                                "Redirect response missing Location header.",
                            )

                        # Resolve relative redirects.
                        if not location.startswith(("http://", "https://")):
                            parsed = urlsplit(current_url)
                            base = f"{parsed.scheme}://{parsed.netloc}"
                            location = base + location

                        # Detect redirect loops.
                        if location in visited_urls:
                            raise DownloadSecurityError(
                                SSRF_BLOCKED,
                                f"Redirect loop detected at {location!r}.",
                            )

                        # Re-validate the redirect destination.
                        redirect_validated, _ = await self._preflight.validate(location)
                        visited_urls.add(location)
                        current_url = redirect_validated.url
                        redirect_count += 1
                        # Leaving the context managers closes the response and
                        # the transport: the redirect hop's connection (and any
                        # trailing bytes on it) is discarded here.
                        continue

                    if response.status_code == 407:
                        # Forwarding-proxy auth rejection.  The message is
                        # fixed text — it must never echo proxy request data.
                        raise DownloadSecurityError(
                            PROXY_AUTH_FAILED,
                            "The egress proxy demanded authentication and "
                            "rejected the supplied credentials (HTTP 407).",
                            http_status=502,
                        )

                    if response.status_code not in range(200, 300):
                        raise DownloadSecurityError(
                            SSRF_BLOCKED,
                            f"Server returned HTTP {response.status_code}.",
                            http_status=response.status_code,
                        )

                    # Reject inconsistent framing before accepting any bytes.
                    declared_length = self._declared_content_length(response)

                    # Derive original filename from Content-Disposition or URL path.
                    original_filename = self._extract_filename(
                        response.headers.get("content-disposition", ""),
                        current_url,
                    )
                    content_type_hint = response.headers.get("content-type", "")

                    # Stream to disk, enforcing the byte limit as bytes arrive.
                    sha256_hash = hashlib.sha256()
                    bytes_written = 0
                    header_buf = b""
                    detected_mime: str | None = None

                    with self._open_temp_file(temp_path) as fh:
                        try:
                            async for chunk in response.aiter_bytes(
                                chunk_size=_CHUNK_SIZE
                            ):
                                if not chunk:
                                    continue

                                # Accumulate header bytes for MIME detection.
                                if len(header_buf) < _HEADER_READ_BYTES:
                                    header_buf += chunk
                                    if (
                                        len(header_buf) >= _HEADER_READ_BYTES
                                        and detected_mime is None
                                    ):
                                        result = mime_validator.validate_header(
                                            header_buf[:_HEADER_READ_BYTES],
                                            content_type_hint=content_type_hint,
                                            filename_hint=original_filename,
                                        )
                                        detected_mime = result.detected_mime

                                bytes_written += len(chunk)

                                # Hard byte limit — do not trust Content-Length.
                                if bytes_written > self._max_size:
                                    raise DownloadSecurityError(
                                        FILE_TOO_LARGE,
                                        f"File exceeds the maximum permitted size of "
                                        f"{self._max_size} bytes.",
                                    )

                                sha256_hash.update(chunk)
                                fh.write(chunk)
                        except httpx.RemoteProtocolError as exc:
                            # Early connection close, broken chunk framing, or
                            # other protocol violation: the transfer never
                            # completed, so nothing may be accepted.
                            raise DownloadSecurityError(
                                RESPONSE_INCOMPLETE,
                                "The response terminated in violation of HTTP "
                                f"framing rules ({type(exc).__name__}); the "
                                "transfer is incomplete and was rejected.",
                                http_status=502,
                            ) from exc

                    # Final MIME check if file was smaller than _HEADER_READ_BYTES.
                    if detected_mime is None:
                        result = mime_validator.validate_header(
                            header_buf,
                            content_type_hint=content_type_hint,
                            filename_hint=original_filename,
                        )
                        detected_mime = result.detected_mime

                    # Response acceptance: the transfer must have delivered
                    # exactly the declared body, and the file on disk must
                    # match the bytes we actually streamed and hashed.
                    if declared_length is not None and bytes_written != declared_length:
                        raise DownloadSecurityError(
                            RESPONSE_INCOMPLETE,
                            f"Response declared Content-Length {declared_length} "
                            f"but only {bytes_written} bytes were transferred; "
                            "the response is truncated.",
                            http_status=502,
                        )

                    disk_size = temp_path.stat().st_size
                    if disk_size != bytes_written:
                        raise DownloadSecurityError(
                            RESPONSE_INCOMPLETE,
                            f"Stored file size {disk_size} does not match the "
                            f"{bytes_written} accepted response bytes.",
                            http_status=502,
                        )

                    return {
                        "sha256": sha256_hash.hexdigest(),
                        "file_size": bytes_written,
                        "detected_mime": detected_mime,
                        "original_filename": original_filename,
                        "final_url": current_url,
                        "redirect_count": redirect_count,
                    }

    @staticmethod
    def _open_temp_file(path: Path):
        """
        Create/open the temporary file owner-read/write only (0600).

        The explicit mode is independent of the process umask: streamed bytes
        are never group/world readable, even for an instant.
        """
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            # O_TRUNC preserves the mode of a pre-existing file; force 0600.
            os.fchmod(fd, 0o600)
        except OSError:
            os.close(fd)
            raise
        return os.fdopen(fd, "wb")

    @staticmethod
    def _discard_temp(path: Path) -> None:
        """
        Best-effort removal of an unaccepted temporary file.

        A cleanup failure must never mask the original download error; it is
        logged by type only (no path) and the startup sweep reclaims the file.
        """
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning(
                "temp_cleanup_failed", extra={"error_type": type(exc).__name__}
            )

    @staticmethod
    def _declared_content_length(response: httpx.Response) -> int | None:
        """
        Return the response's Content-Length, or None when not declared.

        Rejects (RESPONSE_INCOMPLETE) any framing ambiguity a response-splitting
        or smuggling attacker could exploit:

        - multiple or duplicate Content-Length headers;
        - a non-numeric or negative value;
        - Content-Length combined with Transfer-Encoding: chunked, where the
          two framing rules could disagree about where the body ends.

        A chunked response without Content-Length returns None: its completeness
        is guaranteed by the terminating zero-size chunk, which httpx enforces.
        """
        cl_values = [v.strip() for v in response.headers.get_list("content-length")]
        te_values = [
            v.strip().lower() for v in response.headers.get_list("transfer-encoding")
        ]
        chunked = any("chunked" in v for v in te_values)

        if len(cl_values) > 1:
            raise DownloadSecurityError(
                RESPONSE_INCOMPLETE,
                f"Response carries {len(cl_values)} Content-Length headers; "
                "ambiguous body framing is rejected.",
                http_status=502,
            )

        if cl_values and chunked:
            raise DownloadSecurityError(
                RESPONSE_INCOMPLETE,
                "Response declares both Content-Length and "
                "Transfer-Encoding: chunked; conflicting body framing is "
                "rejected.",
                http_status=502,
            )

        if not cl_values:
            return None

        raw = cl_values[0]
        try:
            declared = int(raw)
        except ValueError as exc:
            raise DownloadSecurityError(
                RESPONSE_INCOMPLETE,
                f"Response Content-Length {raw!r} is not a valid integer.",
                http_status=502,
            ) from exc
        if declared < 0:
            raise DownloadSecurityError(
                RESPONSE_INCOMPLETE,
                "Response Content-Length is negative.",
                http_status=502,
            )
        return declared

    @staticmethod
    def _extract_filename(content_disposition: str, url: str) -> str | None:
        """
        Extract the original filename from Content-Disposition or URL path.

        Returns None if no filename can be determined.
        The returned value is the raw filename from the response — it must never
        be used as a filesystem path component.
        """
        if content_disposition:
            for part in content_disposition.split(";"):
                part = part.strip()
                if part.lower().startswith("filename="):
                    name = part[len("filename="):].strip().strip('"')
                    if name:
                        # Strip any path components to just the basename.
                        return _sanitize_filename(os.path.basename(name))

        # Fallback: last path segment of the URL.
        path = urlsplit(url).path
        if path and path != "/":
            name = os.path.basename(path)
            if name:
                return _sanitize_filename(name)

        return None


def _sanitize_filename(name: str) -> str | None:
    """
    Bound and neutralise a caller-controlled filename for display metadata.

    The value is never used as a path (storage uses UUIDs), but it is returned
    through the API, so control characters (log/terminal injection) and
    leading dots are removed and the length is capped.
    """
    cleaned = "".join(ch for ch in name if ch.isprintable())
    cleaned = cleaned.strip().lstrip(".")
    if not cleaned:
        return None
    return cleaned[:255]
