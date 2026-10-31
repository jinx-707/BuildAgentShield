"""
Shared raw-framing HTTP server for transport-level regression tests.

The security properties under test (response smuggling, content-length
completeness, timeouts, proxy authentication) all live in the byte-level
interaction between the client transport and a real socket, so these tests
must control the exact bytes written to the wire — something
BaseHTTPRequestHandler's convenience helpers actively prevent.  This module
provides a threading HTTP server whose routes are plain callables receiving
the handler, so a route can write a byte-exact response, append forged
trailing data, keep the connection alive for reuse attempts, stall, or drip.

state fields:
  requests           dict[path, count]  — parsed requests per connection
  connections        int                 — TCP connections accepted
  seen_headers       list[dict]         — per-request headers (lowercased keys)
"""
from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from security.preflight import DownloadPreflight
from security.ssrf import SsrfGuard
from security.url_validator import DownloadUrlValidator
from services.downloader import DownloadStreamer
from storage.manager import StorageManager
from tests.conftest import FakeDnsResolver

PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 240 240]>>endobj\n"
    b"trailer<</Root 1 0 R/Size 4>>\n"
    b"%%EOF\n"
)

# A valid-looking but distinguishable PDF used as forged response bodies.
FORGED_PDF_BYTES = b"%PDF-9.9 FORGED-RESPONSE-CONTENT" + b"\x00" * 64


class RawHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive by default: reuse must be possible
    server: "RawServer"

    def log_message(self, *args):  # silence per-request logging
        pass

    def do_GET(self):  # noqa: N802 - stdlib name
        path = urlsplit(self.path).path or self.path
        st = self.server.state
        st["requests"][path] = st["requests"].get(path, 0) + 1
        st["seen_headers"].append(
            {k.lower(): v for k, v in self.headers.items()}
        )
        route = self.server.routes.get(path)
        if route is None:
            self.write_raw(
                "404 Not Found",
                [("Content-Length", "0")],
                b"",
            )
            return
        route(self)

    # ── byte-exact response helpers (used by routes) ────────────────────────

    def write_raw(
        self,
        status_line: str,
        headers: list[tuple[str, str]],
        body: bytes,
        *,
        trailing: bytes = b"",
        close: bool = False,
    ) -> None:
        """
        Write a byte-exact HTTP/1.1 response.

        `trailing` data is appended after the declared body on the same
        socket — the smuggled/forged second response.  `close=True` shuts the
        connection down immediately afterwards; otherwise the connection stays
        open so a client that (wrongly) reuses it would read the trailing data.
        """
        head = f"HTTP/1.1 {status_line}\r\n".encode()
        for name, value in headers:
            head += f"{name}: {value}\r\n".encode()
        head += b"\r\n"
        try:
            self.wfile.write(head + body + trailing)
            self.wfile.flush()
            if close:
                self.close_connection = True
        except (BrokenPipeError, ConnectionResetError):
            self.server.state["write_errors"] = (
                self.server.state.get("write_errors", 0) + 1
            )

    def write_unparseable(self, payload: bytes) -> None:
        """Write bytes that are not a valid HTTP response at all, then close."""
        try:
            self.wfile.write(payload)
            self.wfile.flush()
            self.close_connection = True
        except (BrokenPipeError, ConnectionResetError):
            pass


class RawServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, routes: dict[str, object]) -> None:
        self.routes = routes
        self.state = {
            "requests": {},
            "connections": 0,
            "seen_headers": [],
        }
        super().__init__(("127.0.0.1", 0), RawHandler)

    def finish_request(self, request, client_address):
        self.state["connections"] += 1
        super().finish_request(request, client_address)


def serve_raw(routes: dict[str, object]):
    """Start a RawServer in a daemon thread; return (server, shutdown_fn)."""
    srv = RawServer(routes)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    def shutdown():
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=10)

    return srv, shutdown


def url_for(srv: RawServer, path: str, host: str = "127.0.0.1") -> str:
    port = srv.server_address[1]
    return f"http://{host}:{port}{path}"


def build_streamer(
    srv: RawServer,
    tmp_path,
    *,
    max_size: int = 10 * 1024 * 1024,
    connect_timeout: float = 3.0,
    read_timeout: float = 5.0,
    total_timeout: float = 15.0,
    proxy_url: str = "",
    health_url: str = "",
    proxy_auth_token: str = "",
    require_proxy: bool = False,
    health_cache_ttl: float = 0.0,
) -> DownloadStreamer:
    """
    A real-pipeline DownloadStreamer aimed at the local raw server.

    Test-only relaxations (never production settings): plain HTTP, any domain,
    and private networks allowed so 127.0.0.1 is a legal target.
    """
    port = srv.server_address[1]
    validator = DownloadUrlValidator(
        allowed_ports=f"80,{port}",
        allowed_domains="download.test",
        blocked_domains="",
        default_domain_policy="allow",
        allow_private_networks=True,
        https_only=False,
    )
    guard = SsrfGuard(
        resolver=FakeDnsResolver({"download.test": ["127.0.0.1"]}),
        allow_private_networks=True,
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
        allow_private_networks=True,
        egress_proxy_url=proxy_url,
        egress_health_url=health_url,
        proxy_auth_token=proxy_auth_token,
        max_size_bytes=max_size,
        connect_timeout_s=connect_timeout,
        read_timeout_s=read_timeout,
        total_timeout_s=total_timeout,
        require_proxy=require_proxy,
        proxy_health_cache_ttl=health_cache_ttl,
    )


def zone_listing(tmp_path, zone: str) -> list[str]:
    d = tmp_path / "storage" / zone
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def closed_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
