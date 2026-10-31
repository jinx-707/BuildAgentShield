"""
F1 regression: HTTP response smuggling across redirect hops.

Attack shape (demonstrated in the Phase 1 audit): a malicious origin answers
the redirecting hop with a deliberately short Content-Length and appends a
*complete forged HTTP response* to the same keep-alive connection.  A client
that reuses that connection for the next hop reads the forged response as if
it came from the redirect target — smuggling arbitrary attacker-chosen
"content" (and headers) into the download under the trust of the real origin.

Fix under test: every hop runs on a freshly built transport/client whose
socket pool is closed before the next hop is dispatched.  Trailing bytes left
by a hop die with that hop's connection; the next hop performs a genuine TCP
connection and receives a genuine response from its intended destination.
The requests also carry `Connection: close`, but the guarantee comes from
transport lifetime, not from that header — the hostile server below ignores
it.
"""
from __future__ import annotations

import hashlib

import pytest

from security.errors import DownloadSecurityError
from tests.integration.raw_http import (
    FORGED_PDF_BYTES,
    PDF_BYTES,
    build_streamer,
    serve_raw,
    url_for,
    zone_listing,
)

pytestmark = pytest.mark.integration


def forged_response_bytes() -> bytes:
    """A complete, plausible HTTP response to smuggle after a short body."""
    body = FORGED_PDF_BYTES
    head = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/pdf\r\n"
        "Content-Length: %d\r\n"
        "\r\n" % len(body)
    ).encode()
    return head + body


def _smuggling_redirect(location: str):
    def route(handler):
        # Declared body of 8 bytes ("12345678") — a truncated stub — followed
        # by the forged response on the same socket, left OPEN for reuse.
        handler.write_raw(
            "302 Found",
            [("Location", location), ("Content-Length", "8")],
            b"12345678",
            trailing=forged_response_bytes(),
        )
    return route


@pytest.fixture
def smuggle_server():
    routes = {
        "/smuggle-relative": _smuggling_redirect("/target.pdf"),
        "/smuggle-absolute": None,  # set below once the port is known
        "/smuggle-double": _smuggling_redirect("/mid.pdf"),
        "/mid.pdf": _smuggling_redirect("/target.pdf"),
        "/target.pdf": lambda h: h.write_raw(
            "200 OK",
            [("Content-Type", "application/pdf"), ("Content-Length", str(len(PDF_BYTES)))],
            PDF_BYTES,
        ),
        "/plain-redirect": lambda h: h.write_raw(
            "302 Found",
            [("Location", "/target.pdf"), ("Content-Length", "0")],
            b"",
        ),
    }

    srv, shutdown = serve_raw(routes)
    routes["/smuggle-absolute"] = _smuggling_redirect(url_for(srv, "/target.pdf"))
    try:
        yield srv
    finally:
        shutdown()


class TestForgedResponseCannotBeConsumed:
    async def test_relative_redirect_smuggle_defeated(self, smuggle_server, tmp_path):
        streamer = build_streamer(smuggle_server, tmp_path)

        result = await streamer.download(url_for(smuggle_server, "/smuggle-relative"))

        # The bytes come from the REAL target, not from the forged response.
        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()
        assert result.sha256 != hashlib.sha256(FORGED_PDF_BYTES).hexdigest()
        assert result.file_size == len(PDF_BYTES)
        assert result.redirect_count == 1
        # The next hop genuinely reached the origin: the /target.pdf handler
        # ran exactly once.  A reused connection would have been answered by
        # the smuggled bytes and the server would show zero /target.pdf hits.
        assert smuggle_server.state["requests"].get("/target.pdf", 0) == 1
        assert smuggle_server.state["requests"]["/smuggle-relative"] == 1
        # The redirect hop and the target hop used distinct TCP connections.
        assert smuggle_server.state["connections"] == 2

    async def test_absolute_redirect_same_origin_smuggle_defeated(
        self, smuggle_server, tmp_path
    ):
        streamer = build_streamer(smuggle_server, tmp_path)

        result = await streamer.download(url_for(smuggle_server, "/smuggle-absolute"))

        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()
        assert smuggle_server.state["requests"].get("/target.pdf", 0) == 1
        assert smuggle_server.state["connections"] == 2

    async def test_two_smuggling_hops_both_defeated(self, smuggle_server, tmp_path):
        """Chain: smuggle hop -> smuggle hop -> real target (3 connections)."""
        streamer = build_streamer(smuggle_server, tmp_path)

        result = await streamer.download(url_for(smuggle_server, "/smuggle-double"))

        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()
        assert result.redirect_count == 2
        assert smuggle_server.state["requests"].get("/target.pdf", 0) == 1
        assert smuggle_server.state["connections"] == 3

    async def test_client_sends_connection_close_courtesy_header(
        self, smuggle_server, tmp_path
    ):
        """Defense-in-depth header is present, though not the mechanism."""
        streamer = build_streamer(smuggle_server, tmp_path)
        await streamer.download(url_for(smuggle_server, "/plain-redirect"))

        connection_headers = [
            h.get("connection", "") for h in smuggle_server.state["seen_headers"]
        ]
        assert connection_headers and all(
            "close" in v.lower() for v in connection_headers
        )


class TestOrdinaryRedirectsStillWork:
    async def test_plain_relative_redirect_succeeds(self, smuggle_server, tmp_path):
        streamer = build_streamer(smuggle_server, tmp_path)

        result = await streamer.download(url_for(smuggle_server, "/plain-redirect"))

        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()
        assert result.final_url == url_for(smuggle_server, "/target.pdf")
        assert result.redirect_count == 1
        assert smuggle_server.state["requests"]["/target.pdf"] == 1

    async def test_direct_download_uses_single_connection(self, smuggle_server, tmp_path):
        streamer = build_streamer(smuggle_server, tmp_path)

        result = await streamer.download(url_for(smuggle_server, "/target.pdf"))

        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()
        assert smuggle_server.state["connections"] == 1

    async def test_smuggled_trailing_bytes_never_enter_storage(
        self, smuggle_server, tmp_path
    ):
        """The temp file contains the target body only — no forged residue."""
        streamer = build_streamer(smuggle_server, tmp_path)
        result = await streamer.download(url_for(smuggle_server, "/smuggle-relative"))

        stored = (tmp_path / "storage" / "temporary" / result.storage_ref.filename).read_bytes()
        assert stored == PDF_BYTES
        assert b"FORGED" not in stored
        assert zone_listing(tmp_path, "temporary") == [result.storage_ref.filename]
