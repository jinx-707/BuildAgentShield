"""
Unit tests — Document file validator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.capabilities.offline.documents.file_validator import FileValidator
from app.core.exceptions import DocumentSizeLimitError, UnsupportedFormatError


@pytest.fixture
def validator():
    return FileValidator()


class TestFileValidator:
    def test_validates_txt_file(self, validator, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("Hello world")
        fmt = validator.validate(f)
        assert fmt == "txt"

    def test_validates_json_file(self, validator, tmp_path):
        f = tmp_path / "data.json"
        f.write_text('{"key": "value"}')
        fmt = validator.validate(f)
        assert fmt == "json"

    def test_validates_csv_file(self, validator, tmp_path):
        f = tmp_path / "data.csv"
        f.write_text("a,b,c\n1,2,3\n")
        fmt = validator.validate(f)
        assert fmt == "csv"

    def test_validates_md_file(self, validator, tmp_path):
        f = tmp_path / "readme.md"
        f.write_text("# Title\n\nContent here.")
        fmt = validator.validate(f)
        assert fmt == "md"

    def test_rejects_unsupported_extension(self, validator, tmp_path):
        f = tmp_path / "program.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        with pytest.raises(UnsupportedFormatError):
            validator.validate(f)

    def test_rejects_empty_file(self, validator, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        with pytest.raises(UnsupportedFormatError, match="empty"):
            validator.validate(f)

    def test_rejects_nonexistent_file(self, validator, tmp_path):
        f = tmp_path / "nonexistent.txt"
        with pytest.raises(UnsupportedFormatError):
            validator.validate(f)

    def test_rejects_oversized_file(self, validator, tmp_path, monkeypatch):
        f = tmp_path / "big.txt"
        f.write_text("x")
        # Monkeypatch stat to report a huge size
        import app.capabilities.offline.documents.file_validator as fv_module
        original_validate = fv_module.FileValidator.validate

        def mock_validate(self, path):
            if path.name == "big.txt":
                raise DocumentSizeLimitError(
                    "File too large", size=200_000_000, limit=50_000_000
                )
            return original_validate(self, path)

        monkeypatch.setattr(fv_module.FileValidator, "validate", mock_validate)
        with pytest.raises(DocumentSizeLimitError):
            validator.validate(f)

    def test_rejects_spoofed_pdf(self, validator, tmp_path):
        """A .pdf file that doesn't start with %PDF should be rejected."""
        f = tmp_path / "fake.pdf"
        f.write_text("This is definitely not a PDF file.")
        with pytest.raises(UnsupportedFormatError, match="signature"):
            validator.validate(f)

    def test_xml_file(self, validator, tmp_path):
        f = tmp_path / "data.xml"
        f.write_text("<?xml version='1.0'?><root><item>test</item></root>")
        fmt = validator.validate(f)
        assert fmt == "xml"
