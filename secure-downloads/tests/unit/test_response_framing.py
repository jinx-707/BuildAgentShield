"""
F2 unit coverage: response framing acceptance rules (pure header logic).

Complements the real-socket tests in tests/integration/test_response_acceptance.py
by exercising DownloadStreamer._declared_content_length directly.
"""
from __future__ import annotations

import pytest
import httpx

from security.errors import RESPONSE_INCOMPLETE, DownloadSecurityError
from services.downloader import DownloadStreamer

declared = DownloadStreamer._declared_content_length


def response_with(*headers: tuple[str, str]) -> httpx.Response:
    return httpx.Response(200, headers=httpx.Headers(list(headers)))


class TestValidFraming:
    def test_single_content_length_returns_int(self):
        r = response_with(("Content-Length", "42"))
        assert declared(r) == 42

    def test_zero_length_is_valid(self):
        r = response_with(("Content-Length", "0"))
        assert declared(r) == 0

    def test_absent_headers_mean_no_declared_length(self):
        r = response_with(("Content-Type", "application/pdf"))
        assert declared(r) is None

    def test_pure_chunked_returns_none(self):
        """Chunked framing has no declared length; completeness is enforced by
        the terminating chunk, which httpx validates during streaming."""
        r = response_with(("Transfer-Encoding", "chunked"))
        assert declared(r) is None

    def test_surrounding_whitespace_is_tolerated(self):
        r = response_with(("Content-Length", " 17 "))
        assert declared(r) == 17


class TestRejectedFraming:
    def test_multiple_content_length_values_rejected(self):
        r = response_with(("Content-Length", "10"), ("Content-Length", "20"))
        with pytest.raises(DownloadSecurityError) as exc_info:
            declared(r)
        assert exc_info.value.code == RESPONSE_INCOMPLETE

    def test_content_length_with_chunked_rejected(self):
        r = response_with(
            ("Content-Length", "10"), ("Transfer-Encoding", "chunked")
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            declared(r)
        assert exc_info.value.code == RESPONSE_INCOMPLETE

    @pytest.mark.parametrize("value", ["banana", "12x", "", "+-3", "1.5"])
    def test_non_integer_content_length_rejected(self, value):
        r = response_with(("Content-Length", value))
        with pytest.raises(DownloadSecurityError) as exc_info:
            declared(r)
        assert exc_info.value.code == RESPONSE_INCOMPLETE

    def test_negative_content_length_rejected(self):
        r = response_with(("Content-Length", "-5"))
        with pytest.raises(DownloadSecurityError) as exc_info:
            declared(r)
        assert exc_info.value.code == RESPONSE_INCOMPLETE
