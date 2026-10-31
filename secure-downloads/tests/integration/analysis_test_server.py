"""
Local HTTP server implementing provider contract v1 for integration tests.

This is a *test double for the wire protocol*, not a production provider: it
lets the real httpx transport stack exercise success and every failure mode
(auth, redirect, rate limit, timeout, oversized bodies, invalid payloads).
Requests are recorded so tests can assert on headers and bodies.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlsplit

ANALYSIS_PATH = "/v1/analyze"


class AnalysisProviderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "AnalysisProviderServer"

    def log_message(self, *args):  # silence stdlib logging
        pass

    def do_POST(self):  # noqa: N802 - stdlib name
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        request = {
            "path": urlsplit(self.path).path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body,
        }
        self.server.state["requests"].append(request)
        try:
            self.server.responder(self)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def write_response(
        self,
        status_line: str,
        headers: list[tuple[str, str]],
        body: bytes,
        *,
        delay: float = 0.0,
        close: bool = True,
    ) -> None:
        if delay:
            time.sleep(delay)
        head = f"HTTP/1.1 {status_line}\r\n".encode()
        for name, value in headers:
            head += f"{name}: {value}\r\n".encode()
        head += b"\r\n"
        self.wfile.write(head + body)
        self.wfile.flush()
        if close:
            self.close_connection = True


class AnalysisProviderServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, responder: Callable[[AnalysisProviderHandler], None]) -> None:
        self.responder = responder
        self.state: dict = {"requests": [], "connections": 0}
        super().__init__(("127.0.0.1", 0), AnalysisProviderHandler)

    def finish_request(self, request, client_address):
        self.state["connections"] += 1
        super().finish_request(request, client_address)


def serve_analysis(responder: Callable[[AnalysisProviderHandler], None]):
    server = AnalysisProviderServer(responder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def shutdown() -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)

    return server, shutdown


def endpoint_for(server: AnalysisProviderServer) -> str:
    port = server.server_address[1]
    return f"http://127.0.0.1:{port}{ANALYSIS_PATH}"


def json_responder(
    payload: dict | bytes | None = None,
    *,
    status: str = "200 OK",
    headers: list[tuple[str, str]] | None = None,
    delay: float = 0.0,
    content_type: str = "application/json",
    omit_content_length: bool = False,
):
    """Build a responder that writes a fixed JSON body."""

    def respond(handler: AnalysisProviderHandler) -> None:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        response_headers = [("Content-Type", content_type)]
        if not omit_content_length:
            response_headers.append(("Content-Length", str(len(body))))
        if headers:
            response_headers.extend(headers)
        handler.write_response(status, response_headers, body, delay=delay)

    return respond


def raw_responder(
    status: str,
    headers: list[tuple[str, str]],
    body: bytes,
    *,
    delay: float = 0.0,
):
    def respond(handler: AnalysisProviderHandler) -> None:
        handler.write_response(status, headers, body, delay=delay)

    return respond
