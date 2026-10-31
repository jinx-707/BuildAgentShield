"""
Adversarial download tests.
"""
import os
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.capabilities.online.downloads.url_validator import validate_download_url
from app.capabilities.online.downloads.file_validator import validate_file
from app.capabilities.online.downloads.malware_scanner import MockMalwareScanner, ScanStatus, ClamAVScanner
from app.capabilities.online.downloads.quarantine_manager import QuarantineManager
from app.core.exceptions import (
    SSRFAttemptError, URLValidationError, FileValidationError,
    MalwareDetectedError, ScannerUnavailableError,
)


class TestMaliciousDownloadURLs:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/malware.exe",
        "http://10.0.0.1/internal-api",
        "file:///etc/shadow",
        "http://169.254.169.254/credentials",
        "javascript:fetch('http://attacker.com')",
    ])
    def test_malicious_url_blocked(self, url):
        with pytest.raises((SSRFAttemptError, URLValidationError)):
            validate_download_url(url)

    def test_redirect_to_private_ip_blocked(self):
        """Ensure private IP is blocked even from domain lookups."""
        with pytest.raises((SSRFAttemptError, URLValidationError)):
            validate_download_url("http://127.0.0.1/file.pdf")

    def test_blocklisted_domain_blocked(self):
        with pytest.raises(URLValidationError):
            validate_download_url(
                "https://malware-site.example.com/evil.exe",
                domain_blocklist=["malware-site.example.com"],
            )


class TestOversizedDownloads:
    def test_file_exceeding_size_limit_rejected(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"X" * 2000)
            path = f.name
        try:
            with pytest.raises(FileValidationError, match="size"):
                validate_file(file_path=path, max_size_bytes=1000)
        finally:
            os.unlink(path)


class TestSpoofedFileFormats:
    def test_executable_with_pdf_extension_blocked(self):
        """ELF binary named .pdf must be blocked."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with pytest.raises(FileValidationError, match="executable"):
                validate_file(file_path=path)
        finally:
            os.unlink(path)

    def test_pe_binary_with_jpg_extension_blocked(self):
        """Windows PE binary named .jpg must be blocked."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as f:
            f.write(b"MZ" + b"\x00" * 100)
            path = f.name
        try:
            with pytest.raises(FileValidationError, match="executable"):
                validate_file(file_path=path)
        finally:
            os.unlink(path)


class TestMalwareDetection:
    def test_eicar_file_detected(self):
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        scanner = MockMalwareScanner()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(eicar)
            path = f.name
        try:
            result = scanner.scan_file(path)
            assert result.status == ScanStatus.INFECTED
        finally:
            os.unlink(path)

    def test_scanner_unavailable_fail_closed(self):
        """If scanner is unavailable and fail_closed=True, raise exception."""
        scanner = ClamAVScanner(
            host="localhost", port=19999,  # non-existent port
            fail_closed=True,
        )
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            path = f.name
        try:
            with pytest.raises(ScannerUnavailableError, match="fail-closed"):
                scanner.scan_file(path)
        finally:
            os.unlink(path)


class TestQuarantineManager:
    def test_file_moved_to_quarantine(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            q_dir = os.path.join(tmpdir, "quarantine")
            mgr = QuarantineManager(quarantine_dir=q_dir)

            # Create a test file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
                f.write(b"malicious content")
                src = f.name

            record = mgr.quarantine(
                file_path=src,
                original_url="https://evil.com/malware.bin",
                mime_type="application/octet-stream",
                scan_result="Mock.Malware.Test",
                security_decision="QUARANTINE",
                quarantine_reason="Malware detected",
            )
            # Original file removed
            assert not os.path.exists(src)
            assert record.quarantine_id.startswith("quar_")
            assert record.sha256 != "UNKNOWN"

    def test_quarantine_record_contains_no_path_in_external_view(self):
        """to_dict() must not expose quarantine path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            q_dir = os.path.join(tmpdir, "quarantine")
            mgr = QuarantineManager(quarantine_dir=q_dir)

            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"test")
                src = f.name

            record = mgr.quarantine(
                file_path=src,
                original_url="http://example.com/f",
                mime_type="text/plain",
                scan_result="INFECTED",
                security_decision="QUARANTINE",
                quarantine_reason="Test",
            )
            d = record.to_dict()
            assert "quarantine_path" not in d

    def test_quarantine_records_are_retrievable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            q_dir = os.path.join(tmpdir, "quarantine")
            mgr = QuarantineManager(quarantine_dir=q_dir)

            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"test content")
                src = f.name

            record = mgr.quarantine(
                file_path=src,
                original_url="https://example.com/f",
                mime_type="text/plain",
                scan_result="INFECTED",
                security_decision="QUARANTINE",
                quarantine_reason="Test",
            )
            retrieved = mgr.get_record(record.quarantine_id)
            assert retrieved is not None
            assert retrieved.original_url == "https://example.com/f"
