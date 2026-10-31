"""
End-to-end download tests over real HTTP sockets.

These exercise DownloadStreamer with the genuine httpx transport stack
(httpx.AsyncHTTPTransport) against a local HTTP server running in a thread —
no mock transports, no patched clients.  That matters because the security
properties under test live in the interaction between the transport chain and
a real socket: streaming a body instead of buffering it, aborting a transfer,
following a redirect through a second dispatch, and re-running the policy
checks per request.

Test-only relaxations (clearly not production settings):
* the pipeline uses allow_private_networks=True so 127.0.0.1 is a legal target;
* https_only=False and default_domain_policy="allow" so plain HTTP and any
  host can be reached;
* socket.getaddrinfo is patched so the hostname used in some tests resolves to
  the local server, which is how a rebinding target would behave.

Two tests document the limits of the implementation rather than a control:
* test_validated_address_is_not_the_connection_target — re-validation is not
  pinning; the socket connects wherever the OS resolver says.
"""
from __future__ import annotations

import hashlib
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest

from security.errors import (
    EGRESS_PROXY_UNAVAILABLE,
    FILE_TOO_LARGE,
    MIME_NOT_ALLOWED,
    PRIVATE_IP_BLOCKED,
    SSRF_BLOCKED,
    DownloadSecurityError,
)
from security.preflight import DownloadPreflight
from security.ssrf import SsrfGuard
from security.url_validator import DownloadUrlValidator
from services.downloader import DownloadStreamer
from storage.manager import StorageManager, StorageZone
from tests.conftest import FakeDnsResolver, SequenceDnsResolver

pytestmark = pytest.mark.integration

PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 240 240]>>endobj\n"
    b"trailer<</Root 1 0 R/Size 4>>\n"
    b"%%EOF\n"
)

HUGE_TOTAL = 16 * 1024 * 1024      # 16 MiB
HUGE_CHUNK = 256 * 1024

# Addresses that stay blocked even with allow_private_networks=True.
ALWAYS_BLOCKED = "169.254.169.254"
PUBLIC_UNREACHABLE = "203.0.113.7"  # TEST-NET-3


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, *args):  # silence per-request logging
        pass

    # ── helpers ────────────────────────────────────────────────────────────
    def _count(self, path: str) -> None:
        self.server.state["requests"][path] = (
            self.server.state["requests"].get(path, 0) + 1
        )

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _respond(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ── routing ────────────────────────────────────────────────────────────
    def do_GET(self):  # noqa: N802 - stdlib name
        # self.path is absolute-form ("http://host:port/x") when this server is
        # used as a plain forwarding proxy, and origin-form otherwise.
        path = urlsplit(self.path).path or self.path
        self._count(path)

        if path == "/file.pdf":
            self._respond(PDF_BYTES, "application/pdf")
        elif path == "/huge.pdf":
            self._serve_huge()
        elif path == "/not-pdf.bin":
            self._respond(b"MZ\x90\x00" + b"\x00" * 256, "application/pdf")
        elif path == "/error":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/redirect-blocked":
            self._redirect(f"http://{ALWAYS_BLOCKED}/latest/meta-data/user-data")
        elif path == "/redirect-relative":
            self._redirect("/file.pdf")
        elif path == "/redirect-permissive":
            # Flip the mock proxy out of enforcing mode mid-download, then
            # hand the client a second hop that must be re-attested.
            self.server.state["proxy_mode"] = "permissive"
            self._redirect("/file.pdf")
        elif path == "/health":
            mode = self.server.state["proxy_mode"]
            payload = {"status": "ok"}
            if mode is not None:
                payload["mode"] = mode
            self._json(payload)
        elif path == "/health-degraded":
            self._json({"status": "degraded", "mode": "enforcing"})
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _serve_huge(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(HUGE_TOTAL))
        self.end_headers()
        chunk = b"%PDF-" + b"\x00" * (HUGE_CHUNK - 5)
        written = 0
        try:
            while written < HUGE_TOTAL:
                self.wfile.write(chunk)
                self.wfile.flush()
                written += len(chunk)
                self.server.state["huge_bytes_written"] = written
        except (BrokenPipeError, ConnectionResetError):
            self.server.state["huge_aborted"] = True


@pytest.fixture
def live_server():
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.state = {
        "requests": {},
        "proxy_mode": "enforcing",
        "huge_bytes_written": 0,
        "huge_aborted": False,
    }
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


@pytest.fixture
def hostname_resolves_to_server(live_server, monkeypatch):
    """
    Patch the OS resolver so "download.test" resolves to the live server.

    This is the attacker-controlled DNS in the rebinding scenarios: whatever the
    SsrfGuard stub says, the socket goes where this resolver points.
    """
    real = socket.getaddrinfo
    target = "127.0.0.1"

    def fake(host, port, *args, **kwargs):
        if host in ("download.test", b"download.test"):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                     (target, port))]
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return target


def make_streamer(
    live_server,
    tmp_path,
    *,
    resolver=None,
    max_size: int = 10 * 1024 * 1024,
    total_timeout: float = 15.0,
    proxy_url: str = "",
    health_url: str = "",
    require_proxy: bool = False,
    health_cache_ttl: float = 0.0,
    allow_private: bool = True,
) -> DownloadStreamer:
    port = live_server.server_address[1]
    validator = DownloadUrlValidator(
        allowed_ports=f"80,{port}",
        allowed_domains="download.test",
        blocked_domains="",
        default_domain_policy="allow",
        allow_private_networks=allow_private,
        https_only=False,
    )
    guard = SsrfGuard(
        resolver=resolver or FakeDnsResolver({"download.test": ["127.0.0.1"]}),
        allow_private_networks=allow_private,
    )
    preflight = DownloadPreflight(
        url_validator=validator, ssrf_guard=guard, dns_enabled=True
    )
    storage = StorageManager(str(tmp_path / "storage"))
    storage.initialize()

    return DownloadStreamer(
        preflight=preflight,
        storage_manager=storage,
        ssrf_guard=guard,
        allow_private_networks=allow_private,
        egress_proxy_url=proxy_url,
        egress_health_url=health_url,
        max_size_bytes=max_size,
        connect_timeout_s=3.0,
        read_timeout_s=5.0,
        total_timeout_s=total_timeout,
        require_proxy=require_proxy,
        proxy_health_cache_ttl=health_cache_ttl,
    )


def url_for(live_server, path: str, host: str = "127.0.0.1") -> str:
    port = live_server.server_address[1]
    return f"http://{host}:{port}{path}"


def temp_files(tmp_path) -> list[str]:
    zone = tmp_path / "storage" / StorageZone.TEMPORARY.value
    return sorted(p.name for p in zone.iterdir())


# ─────────────────────────────────────────────────────────────────────────────
# 1. SUCCESSFUL PDF DOWNLOAD OVER REAL HTTP
# ─────────────────────────────────────────────────────────────────────────────

class TestSuccessfulDownload:
    async def test_pdf_streamed_to_temporary_zone(self, live_server, tmp_path):
        streamer = make_streamer(live_server, tmp_path)
        target = url_for(live_server, "/file.pdf")

        result = await streamer.download(target)

        assert result.file_size == len(PDF_BYTES)
        assert result.final_url == target
        assert result.redirect_count == 0
        assert result.detected_mime == "application/pdf"
        assert result.original_filename == "file.pdf"
        assert result.storage_ref.zone == StorageZone.TEMPORARY
        path = (
            tmp_path / "storage" / StorageZone.TEMPORARY.value
            / result.storage_ref.filename
        )
        assert path.read_bytes() == PDF_BYTES

    async def test_checksum_covers_the_served_bytes(self, live_server, tmp_path):
        streamer = make_streamer(live_server, tmp_path)
        target = url_for(live_server, "/file.pdf")

        result = await streamer.download(target)

        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()
        # The stored file hashes to the same digest the lifecycle will verify.
        stored = (
            tmp_path / "storage" / StorageZone.TEMPORARY.value
            / result.storage_ref.filename
        )
        assert streamer._storage.compute_sha256(result.storage_ref) == result.sha256
        assert stored.exists()

    async def test_redirect_is_followed_and_revalidated(self, live_server, tmp_path):
        """
        Two dispatches over a real socket, each passing the transport chain; the
        relative Location is resolved against the current URL.
        """
        streamer = make_streamer(live_server, tmp_path)
        target = url_for(live_server, "/redirect-relative")

        result = await streamer.download(target)

        assert result.redirect_count == 1
        assert result.final_url == url_for(live_server, "/file.pdf")
        assert live_server.state["requests"]["/redirect-relative"] == 1
        assert live_server.state["requests"]["/file.pdf"] == 1
        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()

    async def test_hostname_target_over_real_socket(
        self, live_server, tmp_path, hostname_resolves_to_server
    ):
        streamer = make_streamer(live_server, tmp_path)
        target = url_for(live_server, "/file.pdf", host="download.test")

        result = await streamer.download(target)

        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# 2. OVERSIZED RESPONSE IS REJECTED *DURING* THE TRANSFER
# ─────────────────────────────────────────────────────────────────────────────

class TestOversizedResponse:
    async def test_transfer_aborts_before_the_whole_body_arrives(
        self, live_server, tmp_path
    ):
        """
        Regression for the buffered-body defect: with a 16 MiB response and a
        1 MiB limit, the server must observe the client stop reading.  If the
        client buffered the body (httpx AsyncClient.get), the server would have
        written all 16 MiB before the limit was ever evaluated.
        """
        streamer = make_streamer(live_server, tmp_path, max_size=1024 * 1024)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/huge.pdf"))

        assert exc_info.value.code == FILE_TOO_LARGE
        assert live_server.state["huge_bytes_written"] < HUGE_TOTAL
        assert live_server.state["huge_aborted"] is True

    async def test_partial_temp_file_is_removed(self, live_server, tmp_path):
        streamer = make_streamer(live_server, tmp_path, max_size=1024 * 1024)

        with pytest.raises(DownloadSecurityError):
            await streamer.download(url_for(live_server, "/huge.pdf"))

        assert temp_files(tmp_path) == []


# ─────────────────────────────────────────────────────────────────────────────
# 3. REDIRECT TO A BLOCKED DESTINATION
# ─────────────────────────────────────────────────────────────────────────────

class TestRedirectToBlockedDestination:
    async def test_blocked_redirect_rejected_before_connection(
        self, live_server, tmp_path
    ):
        streamer = make_streamer(live_server, tmp_path)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/redirect-blocked"))

        assert exc_info.value.code == PRIVATE_IP_BLOCKED
        # The redirect hop was served; nothing was fetched from the metadata IP.
        assert live_server.state["requests"]["/redirect-blocked"] == 1
        assert temp_files(tmp_path) == []

    async def test_non_200_response_rejected_and_temp_cleaned(self, live_server, tmp_path):
        streamer = make_streamer(live_server, tmp_path)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/error"))

        assert exc_info.value.code == SSRF_BLOCKED
        assert temp_files(tmp_path) == []


# ─────────────────────────────────────────────────────────────────────────────
# 4. DNS CHANGES BETWEEN VALIDATION AND CONNECTION
# ─────────────────────────────────────────────────────────────────────────────

class TestDnsChangeBetweenValidationAndConnection:
    async def test_second_lookup_returns_blocked_address_request_never_connects(
        self, live_server, tmp_path, hostname_resolves_to_server
    ):
        """
        Preflight resolves download.test to the safe loopback address; the
        lookup performed at dispatch returns a cloud-metadata address.  The
        request must be rejected and no HTTP request may reach the server.
        """
        resolver = SequenceDnsResolver(
            {"download.test": [["127.0.0.1"], [ALWAYS_BLOCKED]]}
        )
        streamer = make_streamer(live_server, tmp_path, resolver=resolver)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/file.pdf", host="download.test"))

        assert exc_info.value.code == PRIVATE_IP_BLOCKED
        assert live_server.state["requests"].get("/file.pdf", 0) == 0
        assert temp_files(tmp_path) == []

    async def test_validated_address_is_not_the_connection_target(
        self, live_server, tmp_path, hostname_resolves_to_server
    ):
        """
        Documents what this implementation does NOT do.

        The guard validates 203.0.113.7 (public, therefore permitted) and the
        connection then goes to whatever the OS resolver returns — here
        127.0.0.1, which the policy never approved.  The download succeeds,
        proving re-validation is not pinning: an attacker who controls DNS and
        can answer differently per caller can land a validated-hostname request
        on an internal address without tripping any in-process check.
        """
        resolver = FakeDnsResolver({"download.test": [PUBLIC_UNREACHABLE]})
        streamer = make_streamer(live_server, tmp_path, resolver=resolver)

        result = await streamer.download(
            url_for(live_server, "/file.pdf", host="download.test")
        )

        # The socket used the OS answer (127.0.0.1), not the validated answer.
        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()
        assert live_server.state["requests"]["/file.pdf"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# 5. TEMPORARY FILE CLEANUP ON FAILURE
# ─────────────────────────────────────────────────────────────────────────────

class TestTemporaryFileCleanup:
    async def test_mime_rejection_leaves_no_temp_file(self, live_server, tmp_path):
        streamer = make_streamer(live_server, tmp_path)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/not-pdf.bin"))

        assert exc_info.value.code == MIME_NOT_ALLOWED
        assert temp_files(tmp_path) == []

    async def test_connection_refused_leaves_no_temp_file(self, tmp_path):
        """A port nothing listens on: the download fails and the zone stays empty."""
        port = _closed_port()
        validator = DownloadUrlValidator(
            allowed_ports=str(port),
            default_domain_policy="allow",
            allow_private_networks=True,
            https_only=False,
        )
        guard = SsrfGuard(resolver=FakeDnsResolver(), allow_private_networks=True)
        preflight = DownloadPreflight(
            url_validator=validator, ssrf_guard=guard, dns_enabled=True
        )
        storage = StorageManager(str(tmp_path / "storage"))
        storage.initialize()
        streamer = DownloadStreamer(
            preflight=preflight,
            storage_manager=storage,
            ssrf_guard=guard,
            allow_private_networks=True,
            require_proxy=False,
            connect_timeout_s=1.0,
            total_timeout_s=5.0,
        )

        with pytest.raises(httpx.TransportError):
            await streamer.download(f"http://127.0.0.1:{port}/file.pdf")

        zone = tmp_path / "storage" / StorageZone.TEMPORARY.value
        assert list(zone.iterdir()) == []


# ─────────────────────────────────────────────────────────────────────────────
# 6. REQUIRED PROXY UNAVAILABLE OR NON-ENFORCING
# ─────────────────────────────────────────────────────────────────────────────

class TestProxyEnforcementOverRealHttp:
    async def test_required_but_unconfigured_proxy_blocks(self, live_server, tmp_path):
        streamer = make_streamer(
            live_server, tmp_path, proxy_url="", health_url="", require_proxy=True
        )

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/file.pdf"))

        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE
        assert live_server.state["requests"].get("/file.pdf", 0) == 0

    async def test_proxy_without_attestation_endpoint_blocks(self, live_server, tmp_path):
        streamer = make_streamer(
            live_server,
            tmp_path,
            proxy_url=url_for(live_server, ""),
            health_url="",
            require_proxy=True,
        )

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/file.pdf"))

        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_unreachable_proxy_health_endpoint_blocks(self, live_server, tmp_path):
        streamer = make_streamer(
            live_server,
            tmp_path,
            proxy_url=url_for(live_server, ""),
            health_url=f"http://127.0.0.1:{_closed_port()}/health",
            require_proxy=True,
        )

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/file.pdf"))

        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_permissive_proxy_blocks_download(self, live_server, tmp_path):
        live_server.state["proxy_mode"] = "permissive"
        streamer = make_streamer(
            live_server,
            tmp_path,
            proxy_url=url_for(live_server, ""),
            health_url=url_for(live_server, "/health"),
            require_proxy=True,
        )

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/file.pdf"))

        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_proxy_that_omits_its_mode_blocks_download(self, live_server, tmp_path):
        """Fail closed: an unreported mode is not evidence of enforcement."""
        live_server.state["proxy_mode"] = None
        streamer = make_streamer(
            live_server,
            tmp_path,
            proxy_url=url_for(live_server, ""),
            health_url=url_for(live_server, "/health"),
            require_proxy=True,
        )

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/file.pdf"))

        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_degraded_proxy_blocks_download(self, live_server, tmp_path):
        streamer = make_streamer(
            live_server,
            tmp_path,
            proxy_url=url_for(live_server, ""),
            health_url=url_for(live_server, "/health-degraded"),
            require_proxy=True,
        )

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/file.pdf"))

        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE

    async def test_enforcing_proxy_path_downloads(self, live_server, tmp_path):
        """Positive control: an attested proxy does not break the download."""
        live_server.state["proxy_mode"] = "enforcing"
        streamer = make_streamer(
            live_server,
            tmp_path,
            proxy_url=url_for(live_server, ""),
            health_url=url_for(live_server, "/health"),
            require_proxy=True,
        )

        result = await streamer.download(url_for(live_server, "/file.pdf"))

        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()

    async def test_proxy_flipping_out_of_enforcing_stops_next_hop(
        self, live_server, tmp_path
    ):
        """
        Per-connection enforcement: the first hop is attested as enforcing, the
        proxy flips to permissive, and the redirect hop is refused.  Before the
        attestation check was wired into the transport chain this download would
        have completed.
        """
        live_server.state["proxy_mode"] = "enforcing"
        streamer = make_streamer(
            live_server,
            tmp_path,
            proxy_url=url_for(live_server, ""),
            health_url=url_for(live_server, "/health"),
            require_proxy=True,
            health_cache_ttl=0.0,
        )

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(live_server, "/redirect-permissive"))

        assert exc_info.value.code == EGRESS_PROXY_UNAVAILABLE
        assert live_server.state["requests"]["/redirect-permissive"] == 1
        assert live_server.state["requests"].get("/file.pdf", 0) == 0
        assert temp_files(tmp_path) == []


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────

def _closed_port() -> int:
    """Return a port that is not listening."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()
    return port
