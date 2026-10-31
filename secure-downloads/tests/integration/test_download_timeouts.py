"""
F5 regression: total download deadline and per-phase network timeouts.

Real-socket coverage of the deadline paths:

* fast success and slow-but-valid transfers complete within the budget;
* a slow-drip server that stays under the read timeout but blows the total
  deadline is aborted with DOWNLOAD_TIMEOUT;
* a stall before the response headers arrives is DOWNLOAD_TIMEOUT (read
  timeout phase), not an unclassified transport error;
* a stall partway through the body is DOWNLOAD_TIMEOUT too;
* cancelling the download task mid-transfer propagates CancelledError and
  still removes the partial temp file (the cleanup runs in a finally, because
  CancelledError is a BaseException);
* every failure classifies as DOWNLOAD_TIMEOUT with HTTP 504 semantics.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from security.errors import DOWNLOAD_TIMEOUT, DownloadSecurityError
from tests.integration.raw_http import (
    PDF_BYTES,
    build_streamer,
    serve_raw,
    url_for,
    zone_listing,
)

pytestmark = pytest.mark.integration

PDF_LEN = str(len(PDF_BYTES))


def _slow_valid(handler):
    """Headers+body arrive ~0.4s late but well inside the timeouts."""
    time.sleep(0.4)
    handler.write_raw(
        "200 OK",
        [("Content-Type", "application/pdf"), ("Content-Length", PDF_LEN)],
        PDF_BYTES,
    )


def _stall_headers(handler):
    time.sleep(5)
    handler.write_raw(
        "200 OK",
        [("Content-Type", "application/pdf"), ("Content-Length", "0")],
        b"",
    )


def _stall_body(handler):
    handler.write_raw(
        "200 OK",
        [("Content-Type", "application/pdf"), ("Content-Length", "100000")],
        PDF_BYTES[:16],
    )
    time.sleep(5)


def _drip_forever(handler):
    """Chunked body that never ends, each gap safely under the read timeout."""
    handler.wfile.write(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    handler.wfile.flush()
    piece = b"%PDF-" + b"\x00" * 59
    try:
        while True:
            handler.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            handler.wfile.flush()
            time.sleep(0.02)
    except (BrokenPipeError, ConnectionResetError):
        handler.server.state["drip_aborted"] = True


@pytest.fixture
def timeout_server():
    routes = {
        "/fast": lambda h: h.write_raw(
            "200 OK",
            [("Content-Type", "application/pdf"), ("Content-Length", PDF_LEN)],
            PDF_BYTES,
        ),
        "/slow-valid": _slow_valid,
        "/stall-headers": _stall_headers,
        "/stall-body": _stall_body,
        "/drip-forever": _drip_forever,
    }
    srv, shutdown = serve_raw(routes)
    try:
        yield srv
    finally:
        shutdown()


class TestSuccessfulWithinDeadline:
    async def test_fast_download_succeeds(self, timeout_server, tmp_path):
        streamer = build_streamer(timeout_server, tmp_path, total_timeout=5)
        result = await streamer.download(url_for(timeout_server, "/fast"))
        assert result.file_size == len(PDF_BYTES)

    async def test_slow_but_valid_download_succeeds(self, timeout_server, tmp_path):
        """Latency inside the budget must not be misclassified as a timeout."""
        streamer = build_streamer(
            timeout_server, tmp_path, total_timeout=5.0, read_timeout=3.0
        )
        result = await streamer.download(url_for(timeout_server, "/slow-valid"))
        assert result.file_size == len(PDF_BYTES)


class TestDeadlineFailures:
    async def test_total_deadline_beats_a_within_read_timeout_drip(
        self, timeout_server, tmp_path
    ):
        """
        The server keeps bytes coming every 20ms (read timeout 10s would never
        fire), but the whole transfer is killed at the 0.6s total deadline.
        """
        streamer = build_streamer(
            timeout_server,
            tmp_path,
            total_timeout=0.6,
            read_timeout=10.0,
            max_size=10 * 1024 * 1024,
        )
        start = time.monotonic()
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(timeout_server, "/drip-forever"))

        assert exc_info.value.code == DOWNLOAD_TIMEOUT
        assert exc_info.value.http_status == 504
        assert "total deadline" in exc_info.value.message
        assert time.monotonic() - start < 5.0
        assert zone_listing(tmp_path, "temporary") == []

    async def test_timeout_during_response_headers(self, timeout_server, tmp_path):
        streamer = build_streamer(
            timeout_server, tmp_path, read_timeout=0.4, total_timeout=10.0
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(timeout_server, "/stall-headers"))

        assert exc_info.value.code == DOWNLOAD_TIMEOUT
        assert exc_info.value.http_status == 504
        assert zone_listing(tmp_path, "temporary") == []

    async def test_timeout_during_body_transfer(self, timeout_server, tmp_path):
        streamer = build_streamer(
            timeout_server, tmp_path, read_timeout=0.4, total_timeout=10.0
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(timeout_server, "/stall-body"))

        assert exc_info.value.code == DOWNLOAD_TIMEOUT
        assert exc_info.value.http_status == 504
        # The 16 bytes that did arrive are a partial file and must not survive.
        assert zone_listing(tmp_path, "temporary") == []

    async def test_failure_classification_is_timeout_not_generic(
        self, timeout_server, tmp_path
    ):
        """Timeouts are DOWNLOAD_TIMEOUT (504), never bare transport errors."""
        streamer = build_streamer(
            timeout_server, tmp_path, read_timeout=0.3, total_timeout=10.0
        )
        for path in ("/stall-headers", "/stall-body"):
            with pytest.raises(DownloadSecurityError) as exc_info:
                await streamer.download(url_for(timeout_server, path))
            assert exc_info.value.code == DOWNLOAD_TIMEOUT


class TestCancellation:
    async def test_cancel_mid_transfer_removes_partial_temp_file(
        self, timeout_server, tmp_path
    ):
        streamer = build_streamer(
            timeout_server,
            tmp_path,
            total_timeout=30.0,
            read_timeout=10.0,
            max_size=10 * 1024 * 1024,
        )
        task = asyncio.create_task(
            streamer.download(url_for(timeout_server, "/drip-forever"))
        )
        # Let the transfer start and write some bytes.
        await asyncio.sleep(0.4)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert zone_listing(tmp_path, "temporary") == []
