"""
File validation and malware scanner tests.
"""
import os
import tempfile
import pytest

from app.capabilities.online.downloads.file_validator import validate_file, detect_mime_from_magic
from app.capabilities.online.downloads.file_hasher import hash_file, hash_bytes
from app.capabilities.online.downloads.malware_scanner import MockMalwareScanner, ScanStatus
from app.core.exceptions import FileValidationError


class TestFileHasher:
    def test_hash_bytes_deterministic(self):
        h1 = hash_bytes(b"hello world")
        h2 = hash_bytes(b"hello world")
        assert h1 == h2
        assert len(h1) == 64  # sha256 hex

    def test_different_content_different_hash(self):
        h1 = hash_bytes(b"content_a")
        h2 = hash_bytes(b"content_b")
        assert h1 != h2

    def test_hash_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content for hashing")
            path = f.name
        try:
            h = hash_file(path)
            assert len(h) == 64
        finally:
            os.unlink(path)


class TestFileValidator:
    def _write_temp(self, content: bytes, suffix: str = ".bin") -> str:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        f.write(content)
        f.close()
        return f.name

    def test_valid_pdf_passes(self):
        path = self._write_temp(b"%PDF-1.4 fake pdf content", ".pdf")
        try:
            result = validate_file(
                file_path=path,
                allowed_mimes=["application/pdf"],
                allowed_extensions=[".pdf"],
            )
            assert result.valid is True
        finally:
            os.unlink(path)

    def test_elf_executable_blocked(self):
        path = self._write_temp(b"\x7fELF fake elf binary content", ".bin")
        try:
            with pytest.raises(FileValidationError, match="executable"):
                validate_file(file_path=path)
        finally:
            os.unlink(path)

    def test_windows_pe_blocked(self):
        path = self._write_temp(b"MZ fake windows executable", ".exe")
        try:
            with pytest.raises(FileValidationError, match="executable"):
                validate_file(file_path=path)
        finally:
            os.unlink(path)

    def test_file_size_limit_enforced(self):
        path = self._write_temp(b"A" * 1000, ".txt")
        try:
            with pytest.raises(FileValidationError, match="size"):
                validate_file(file_path=path, max_size_bytes=100)
        finally:
            os.unlink(path)

    def test_disallowed_mime_blocked(self):
        # PNG magic bytes
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        path = self._write_temp(png_header, ".png")
        try:
            with pytest.raises(FileValidationError, match="MIME"):
                validate_file(
                    file_path=path,
                    allowed_mimes=["application/pdf"],  # PDF only
                )
        finally:
            os.unlink(path)

    def test_disallowed_extension_blocked(self):
        path = self._write_temp(b"plain text", ".sh")
        try:
            with pytest.raises(FileValidationError, match="extension"):
                validate_file(
                    file_path=path,
                    declared_filename="script.sh",
                    allowed_extensions=[".txt", ".pdf"],
                )
        finally:
            os.unlink(path)


class TestMockMalwareScanner:
    @pytest.fixture
    def scanner(self):
        return MockMalwareScanner()

    def test_clean_file_passes(self, scanner):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"normal text content")
            path = f.name
        try:
            result = scanner.scan_file(path)
            assert result.status == ScanStatus.CLEAN
        finally:
            os.unlink(path)

    def test_eicar_test_string_detected(self, scanner):
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(eicar)
            path = f.name
        try:
            result = scanner.scan_file(path)
            assert result.status == ScanStatus.INFECTED
            assert result.threat_name is not None
        finally:
            os.unlink(path)

    def test_malware_filename_heuristic(self, scanner):
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="malware_", suffix=".txt"
        ) as f:
            f.write(b"suspicious file")
            path = f.name
        try:
            result = scanner.scan_file(path)
            assert result.status == ScanStatus.INFECTED
        finally:
            os.unlink(path)
