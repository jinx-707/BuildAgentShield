"""Tests for ClamAV scanner integration."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from services.scanner import ClamAvScanner, ScanResult, ScanVerdict


@pytest.fixture
def tmp_file(tmp_path):
    f = tmp_path / "test.pdf"
    f.write_bytes(b"%PDF-1.7\ntest content")
    return f


class TestCleanVerdict:
    async def test_clean_verdict(self, tmp_file):
        with patch("services.scanner.clamd") as mock_clamd:
            cd = MagicMock()
            cd.scan.return_value = {str(tmp_file): ("OK", None)}
            mock_clamd.ClamdNetworkSocket.return_value = cd
            scanner = ClamAvScanner(host="127.0.0.1", port=3310, fail_closed=True)
            result = await scanner.scan(tmp_file)
        assert result.verdict == ScanVerdict.CLEAN
        assert result.detail is None


class TestInfectedVerdict:
    async def test_infected_verdict(self, tmp_file):
        with patch("services.scanner.clamd") as mock_clamd:
            cd = MagicMock()
            cd.scan.return_value = {str(tmp_file): ("FOUND", "Eicar.Test.File-7")}
            mock_clamd.ClamdNetworkSocket.return_value = cd
            scanner = ClamAvScanner(host="127.0.0.1", port=3310, fail_closed=True)
            result = await scanner.scan(tmp_file)
        assert result.verdict == ScanVerdict.INFECTED
        assert "Eicar" in result.detail


class TestScannerUnavailable:
    async def test_unavailable_raises_when_fail_closed(self, tmp_file):
        with patch("services.scanner.clamd") as mock_clamd:
            from services.scanner import ScannerUnavailableError

            mock_clamd.ConnectionError = ConnectionError
            cd = MagicMock()
            cd.scan.side_effect = ConnectionError("refused")
            mock_clamd.ClamdNetworkSocket.return_value = cd
            scanner = ClamAvScanner(fail_closed=True)
            with pytest.raises(ScannerUnavailableError):
                await scanner.scan(tmp_file)

    async def test_unavailable_returns_unavailable_when_not_fail_closed(self, tmp_file):
        with patch("services.scanner.clamd") as mock_clamd:
            from services.scanner import ScannerUnavailableError

            mock_clamd.ConnectionError = ScannerUnavailableError
            cd = MagicMock()
            cd.scan.side_effect = ScannerUnavailableError("refused")
            mock_clamd.ClamdNetworkSocket.return_value = cd
            scanner = ClamAvScanner(fail_closed=False)
            result = await scanner.scan(tmp_file)
        assert result.verdict == ScanVerdict.UNAVAILABLE


class TestScanTimeout:
    async def test_timeout_returns_timeout_verdict(self, tmp_file):
        import time

        def slow_scan(*args, **kwargs):
            # Runs in the scanner's worker thread, so this blocks only that
            # thread, never the event loop.
            time.sleep(0.3)

        scanner = ClamAvScanner(timeout_seconds=0.01, fail_closed=True)
        with patch.object(scanner, "_do_scan", side_effect=slow_scan):
            result = await scanner.scan(tmp_file)
        assert result.verdict == ScanVerdict.TIMEOUT

    async def test_scan_does_not_block_the_event_loop(self, tmp_file):
        import asyncio
        import time

        ticks = 0

        def slow_scan(*args, **kwargs):
            time.sleep(0.2)
            return ScanResult(verdict=ScanVerdict.CLEAN)

        scanner = ClamAvScanner(fail_closed=True)
        with patch.object(scanner, "_do_scan", side_effect=slow_scan):
            task = asyncio.create_task(scanner.scan(tmp_file))
            for _ in range(5):
                await asyncio.sleep(0.01)
                ticks += 1
            result = await task
        assert result.verdict == ScanVerdict.CLEAN
        assert ticks == 5  # the loop kept running during the blocking scan


class TestUnknownVerdict:
    async def test_unknown_status_is_not_clean(self, tmp_file):
        with patch("services.scanner.clamd") as mock_clamd:
            cd = MagicMock()
            cd.scan.return_value = {str(tmp_file): ("SUSPICIOUS", "unknown")}
            mock_clamd.ClamdNetworkSocket.return_value = cd
            scanner = ClamAvScanner(fail_closed=True)
            result = await scanner.scan(tmp_file)
        assert result.verdict != ScanVerdict.CLEAN
        assert result.verdict == ScanVerdict.ERROR


class TestStubScan:
    async def test_stub_returns_unavailable_not_clean(self, tmp_file):
        """When clamd library is missing, stub must not return CLEAN."""
        result = ClamAvScanner._stub_scan(str(tmp_file))
        assert result.verdict == ScanVerdict.UNAVAILABLE
        assert result.verdict != ScanVerdict.CLEAN

    async def test_availability_is_false_without_clamd_library(self):
        """A stub scanner can perform no scan, so readiness must not pass."""
        with patch("services.scanner.clamd", None):
            scanner = ClamAvScanner()
            assert await scanner.is_available() is False

    async def test_scan_with_missing_library_is_unavailable(self, tmp_file):
        with patch("services.scanner.clamd", None):
            scanner = ClamAvScanner(fail_closed=True)
            result = await scanner.scan(tmp_file)
        assert result.verdict == ScanVerdict.UNAVAILABLE


class TestScannerErrorHandling:
    async def test_generic_scan_exception_is_error_not_clean(self, tmp_file):
        with patch("services.scanner.clamd") as mock_clamd:
            mock_clamd.ConnectionError = ConnectionError
            cd = MagicMock()
            cd.scan.side_effect = RuntimeError(f"boom while reading {tmp_file}")
            mock_clamd.ClamdNetworkSocket.return_value = cd
            result = await ClamAvScanner().scan(tmp_file)
        assert result.verdict == ScanVerdict.ERROR
        # The local path must not become part of the public scan detail.
        assert str(tmp_file) not in (result.detail or "")

    async def test_empty_daemon_response_is_error(self, tmp_file):
        with patch("services.scanner.clamd") as mock_clamd:
            cd = MagicMock()
            cd.scan.return_value = {}
            mock_clamd.ClamdNetworkSocket.return_value = cd
            result = await ClamAvScanner().scan(tmp_file)
        assert result.verdict == ScanVerdict.ERROR

    async def test_response_for_a_different_path_is_error(self, tmp_file):
        with patch("services.scanner.clamd") as mock_clamd:
            cd = MagicMock()
            cd.scan.return_value = {"/somewhere/else": ("OK", None)}
            mock_clamd.ClamdNetworkSocket.return_value = cd
            result = await ClamAvScanner().scan(tmp_file)
        assert result.verdict == ScanVerdict.ERROR

    async def test_availability_false_when_ping_fails(self):
        with patch("services.scanner.clamd") as mock_clamd:
            mock_clamd.ClamdNetworkSocket.side_effect = ConnectionError("refused")
            assert await ClamAvScanner().is_available() is False

    async def test_fail_closed_false_never_returns_clean_on_unavailable(self, tmp_file):
        from services.scanner import ScannerUnavailableError

        with patch("services.scanner.clamd") as mock_clamd:
            mock_clamd.ConnectionError = ScannerUnavailableError
            cd = MagicMock()
            cd.scan.side_effect = ScannerUnavailableError("refused")
            mock_clamd.ClamdNetworkSocket.return_value = cd
            result = await ClamAvScanner(fail_closed=False).scan(tmp_file)
        assert result.verdict == ScanVerdict.UNAVAILABLE
        assert result.verdict != ScanVerdict.CLEAN
