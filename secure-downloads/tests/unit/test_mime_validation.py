"""Tests for MIME type and magic-byte validation."""
from __future__ import annotations

import pytest

from security.errors import ARCHIVE_REJECTED, MIME_NOT_ALLOWED, DownloadSecurityError
from security.mime_validator import MimeValidator, _PDF_MAGIC


@pytest.fixture
def validator():
    return MimeValidator()


def make_pdf_header(size: int = 1024) -> bytes:
    """Create a fake PDF header that passes magic-byte checks."""
    header = _PDF_MAGIC + b"-1.7\n%\xe2\xe3\xcf\xd3\n"
    return header + b"\x00" * (size - len(header))


class TestArchiveRejection:
    def test_zip_magic_rejected(self, validator):
        data = b"PK\x03\x04" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data)
        assert exc_info.value.code == ARCHIVE_REJECTED

    def test_zip_empty_magic_rejected(self, validator):
        data = b"PK\x05\x06" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data)
        assert exc_info.value.code == ARCHIVE_REJECTED

    def test_rar_magic_rejected(self, validator):
        data = b"Rar!\x1a\x07" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data)
        assert exc_info.value.code == ARCHIVE_REJECTED

    def test_7zip_magic_rejected(self, validator):
        data = b"7z\xbc\xaf'\x1c" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data)
        assert exc_info.value.code == ARCHIVE_REJECTED

    def test_gzip_magic_rejected(self, validator):
        data = b"\x1f\x8b" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data)
        assert exc_info.value.code == ARCHIVE_REJECTED

    def test_xz_magic_rejected(self, validator):
        data = b"\xfd7zXZ\x00" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data)
        assert exc_info.value.code == ARCHIVE_REJECTED

    def test_zstd_magic_rejected(self, validator):
        data = b"\x28\xb5\x2f\xfd" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data)
        assert exc_info.value.code == ARCHIVE_REJECTED

    def test_bzip2_magic_rejected(self, validator):
        data = b"BZh" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data)
        assert exc_info.value.code == ARCHIVE_REJECTED


class TestPdfValidation:
    def test_valid_pdf_header_accepted(self, validator):
        data = make_pdf_header()
        # When libmagic is unavailable the fallback path is taken.
        result = validator.validate_header(data)
        assert result.is_valid is True
        assert result.detected_mime == "application/pdf"

    def test_pdf_with_matching_extension_accepted(self, validator):
        data = make_pdf_header()
        result = validator.validate_header(data, filename_hint="report.pdf")
        assert result.is_valid is True

    def test_pdf_with_wrong_extension_rejected(self, validator):
        data = make_pdf_header()
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data, filename_hint="malware.exe")
        assert exc_info.value.code == MIME_NOT_ALLOWED

    def test_fake_pdf_content_type_but_zip_bytes_rejected(self, validator):
        """Content-Type: application/pdf but ZIP magic bytes → rejected."""
        data = b"PK\x03\x04" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(data, content_type_hint="application/pdf")
        assert exc_info.value.code == ARCHIVE_REJECTED

    def test_empty_content_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate_header(b"")
        assert exc_info.value.code == MIME_NOT_ALLOWED


class TestUnsupportedMimeTypes:
    def test_executable_rejected(self):
        """MZ header (Windows PE) should be rejected."""
        v = MimeValidator()
        data = b"MZ" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate_header(data)
        assert exc_info.value.code == MIME_NOT_ALLOWED

    def test_html_rejected(self):
        v = MimeValidator()
        data = b"<html><body>test</body></html>" + b"\x00" * 512
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate_header(data)
        assert exc_info.value.code == MIME_NOT_ALLOWED
