"""
F2 regression: response acceptance must validate completeness and framing.

A response is accepted only when its framing is consistent and the transfer
completed:

* declared Content-Length that matches the streamed byte count;
* close-delimited bodies (no Content-Length) end at EOF;
* chunked bodies end at the terminating zero-size chunk;
* truncated transfers, broken chunk framing, malformed status lines and
  ambiguous framing (duplicate Content-Length, Content-Length combined with
  Transfer-Encoding: chunked) are rejected as RESPONSE_INCOMPLETE;
* the byte limit is enforced on streamed bytes, independent of any header;
* the stored file size equals the accepted bytes; nothing incomplete reaches
  the temp zone, let alone approved storage (the orchestrator only moves
  records that completed a download).
"""
from __future__ import annotations

import hashlib

import pytest

from security.errors import (
    FILE_TOO_LARGE,
    MIME_NOT_ALLOWED,
    RESPONSE_INCOMPLETE,
    DownloadSecurityError,
)
from tests.integration.raw_http import (
    PDF_BYTES,
    build_streamer,
    serve_raw,
    url_for,
    zone_listing,
)

pytestmark = pytest.mark.integration

PDF_LEN = str(len(PDF_BYTES))


@pytest.fixture
def framing_server():
    routes = {
        # 1. Exact declared length.
        "/exact": lambda h: h.write_raw(
            "200 OK",
            [("Content-Type", "application/pdf"), ("Content-Length", PDF_LEN)],
            PDF_BYTES,
        ),
        # 2. No Content-Length, no chunked: close-delimited body.
        "/no-cl": lambda h: h.write_raw(
            "200 OK", [("Content-Type", "application/pdf")], PDF_BYTES, close=True
        ),
        # 3. Proper chunked transfer.
        "/chunked": _chunked_route,
        # 4. Declared longer than the body actually sent (truncated).
        "/truncated": lambda h: h.write_raw(
            "200 OK",
            [("Content-Type", "application/pdf"), ("Content-Length", "100000")],
            PDF_BYTES,
            close=True,
        ),
        # 5. Declared shorter than what the server writes: the surplus bytes
        #    sit on the wire but must never enter the accepted file.
        "/over-long": lambda h: h.write_raw(
            "200 OK",
            [("Content-Type", "application/pdf"), ("Content-Length", "8")],
            PDF_BYTES[:8],
            trailing=PDF_BYTES[8:],
            close=True,
        ),
        # 6. Connection dies in the middle of a chunked body.
        "/chunk-broken": lambda h: h.write_raw(
            "200 OK",
            [("Content-Type", "application/pdf"), ("Transfer-Encoding", "chunked")],
            b"40\r\n%PDF-1.4\n1 0 obj <</Type/Catalog/Pa\r\n",  # promised 0x40, gave 0x2A
            close=True,
        ),
        # 7. Chunked body far above the byte limit.
        "/chunked-huge": _chunked_huge_route,
        # 8. Empty body.
        "/empty": lambda h: h.write_raw(
            "200 OK",
            [("Content-Type", "application/pdf"), ("Content-Length", "0")],
            b"",
        ),
        # 9. Redirect hop whose response is not valid HTTP at all.
        "/malformed-redirect": lambda h: h.write_unparseable(b"GARBAGE NOT HTTP\r\n\r\n"),
        # 10. Conflicting Content-Length headers (identical duplicates are
        #     normalized by httpcore; differing values are a framing conflict).
        "/dup-cl": lambda h: h.write_raw(
            "200 OK",
            [
                ("Content-Type", "application/pdf"),
                ("Content-Length", PDF_LEN),
                ("Content-Length", "8"),
            ],
            PDF_BYTES,
            close=True,
        ),
        # 11. Content-Length and chunked together: ambiguous framing.
        "/cl-and-chunked": lambda h: h.write_raw(
            "200 OK",
            [
                ("Content-Type", "application/pdf"),
                ("Content-Length", "8"),
                ("Transfer-Encoding", "chunked"),
            ],
            b"whatever",
            close=True,
        ),
    }
    srv, shutdown = serve_raw(routes)
    try:
        yield srv
    finally:
        shutdown()


def _chunked_route(handler):
    body = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nTransfer-Encoding: chunked\r\n\r\n"
    step = 100
    pos = 0
    chunks = []
    while pos < len(PDF_BYTES):
        piece = PDF_BYTES[pos:pos + step]
        chunks.append(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
        pos += step
    chunks.append(b"0\r\n\r\n")
    handler.wfile.write(body + b"".join(chunks))
    handler.wfile.flush()


def _chunked_huge_route(handler):
    handler.wfile.write(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    piece = b"%PDF-" + b"\x00" * (4096 - 5)
    written = 0
    try:
        while written < 4 * 1024 * 1024:
            handler.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            handler.wfile.flush()
            written += len(piece)
            handler.server.state["huge_bytes_written"] = written
        handler.wfile.write(b"0\r\n\r\n")
    except (BrokenPipeError, ConnectionResetError):
        handler.server.state["huge_aborted"] = True


class TestAcceptedResponses:
    async def test_exact_content_length_accepted(self, framing_server, tmp_path):
        streamer = build_streamer(framing_server, tmp_path)
        result = await streamer.download(url_for(framing_server, "/exact"))
        assert result.file_size == len(PDF_BYTES)
        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()

    async def test_close_delimited_body_accepted(self, framing_server, tmp_path):
        """Missing Content-Length is legal (HTTP/1.0-style): EOF ends the body."""
        streamer = build_streamer(framing_server, tmp_path)
        result = await streamer.download(url_for(framing_server, "/no-cl"))
        assert result.file_size == len(PDF_BYTES)
        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()

    async def test_chunked_transfer_accepted(self, framing_server, tmp_path):
        streamer = build_streamer(framing_server, tmp_path)
        result = await streamer.download(url_for(framing_server, "/chunked"))
        assert result.file_size == len(PDF_BYTES)
        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()

    async def test_declared_shorter_than_actual_only_cl_bytes_accepted(
        self, framing_server, tmp_path
    ):
        """
        Declared 8, server wrote the full PDF.  Only the 8 framed bytes are
        response content; the surplus never enters the file, and because the
        framing is what the client can observe, the acceptance boundary is
        exactly the declared body.  The file size equals the accepted bytes.
        """
        streamer = build_streamer(framing_server, tmp_path)
        result = await streamer.download(url_for(framing_server, "/over-long"))

        assert result.file_size == 8
        assert result.sha256 == hashlib.sha256(PDF_BYTES[:8]).hexdigest()
        stored = (
            tmp_path / "storage" / "temporary" / result.storage_ref.filename
        ).read_bytes()
        assert stored == PDF_BYTES[:8]


class TestRejectedResponses:
    async def test_declared_longer_than_actual_rejected(
        self, framing_server, tmp_path
    ):
        """Regression for the audit defect: CL=100000 with an 8-byte body."""
        streamer = build_streamer(framing_server, tmp_path)
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(framing_server, "/truncated"))

        assert exc_info.value.code == RESPONSE_INCOMPLETE
        assert zone_listing(tmp_path, "temporary") == []

    async def test_connection_death_mid_chunked_body_rejected(
        self, framing_server, tmp_path
    ):
        streamer = build_streamer(framing_server, tmp_path)
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(framing_server, "/chunk-broken"))

        assert exc_info.value.code == RESPONSE_INCOMPLETE
        assert zone_listing(tmp_path, "temporary") == []

    async def test_malformed_redirect_response_rejected(
        self, framing_server, tmp_path
    ):
        streamer = build_streamer(framing_server, tmp_path)
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(framing_server, "/malformed-redirect"))

        assert exc_info.value.code == RESPONSE_INCOMPLETE
        assert zone_listing(tmp_path, "temporary") == []

    async def test_conflicting_content_length_headers_rejected(
        self, framing_server, tmp_path
    ):
        """
        Two Content-Length values that disagree is a smuggling signal.
        httpcore rejects the conflict at the header phase (RemoteProtocolError);
        the streamer maps it to RESPONSE_INCOMPLETE, and its own duplicate
        check would reject a surviving multi-value header the same way.
        """
        streamer = build_streamer(framing_server, tmp_path)
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(framing_server, "/dup-cl"))

        assert exc_info.value.code == RESPONSE_INCOMPLETE
        assert zone_listing(tmp_path, "temporary") == []

    async def test_cl_combined_with_chunked_rejected(self, framing_server, tmp_path):
        streamer = build_streamer(framing_server, tmp_path)
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(framing_server, "/cl-and-chunked"))

        assert exc_info.value.code == RESPONSE_INCOMPLETE
        assert zone_listing(tmp_path, "temporary") == []


class TestLimitAndEmptyBehavior:
    async def test_oversized_chunked_body_aborted_by_streamed_limit(
        self, framing_server, tmp_path
    ):
        """Byte limit is enforced on streamed bytes with no Content-Length."""
        framing_server.state["huge_bytes_written"] = 0
        streamer = build_streamer(framing_server, tmp_path, max_size=64 * 1024)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(framing_server, "/chunked-huge"))

        assert exc_info.value.code == FILE_TOO_LARGE
        assert framing_server.state["huge_bytes_written"] < 4 * 1024 * 1024
        assert zone_listing(tmp_path, "temporary") == []

    async def test_empty_body_rejected_deterministically(self, framing_server, tmp_path):
        """CL=0 passes framing but the MIME layer rejects empty content."""
        streamer = build_streamer(framing_server, tmp_path)
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(framing_server, "/empty"))

        assert exc_info.value.code == MIME_NOT_ALLOWED
        assert "Empty" in exc_info.value.message
        assert zone_listing(tmp_path, "temporary") == []
