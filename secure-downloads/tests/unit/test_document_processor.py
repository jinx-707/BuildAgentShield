"""Tests for local, bounded PDF processing."""
from __future__ import annotations

import sys
import time

import pytest

from security.errors import (
    DOCUMENT_EMPTY,
    DOCUMENT_ENCRYPTED,
    DOCUMENT_MALFORMED,
    DOCUMENT_PROCESSING_TIMEOUT,
    DOCUMENT_PROCESSING_UNAVAILABLE,
    DOCUMENT_SIGNATURE_INVALID,
    DOCUMENT_TOO_MANY_PAGES,
)
from services.document_processor import DocumentProcessingError, PdfDocumentProcessor
from tests.pdf_fixtures import make_encrypted_pdf, make_pdf


def processor(**overrides) -> PdfDocumentProcessor:
    options = {
        "max_pages": 200,
        "max_text_chars": 200_000,
        "processing_timeout_seconds": 20.0,
    }
    options.update(overrides)
    return PdfDocumentProcessor(**options)


class TestValidDocuments:
    async def test_extracts_text_and_page_count(self):
        result = await processor().process(make_pdf(("Hello AgentShield",)))

        assert result.document_type == "pdf"
        assert result.page_count == 1
        assert "Hello AgentShield" in result.text
        assert result.text_truncated is False
        assert "NO_EXTRACTABLE_TEXT" not in result.warnings

    async def test_multi_page_document(self):
        result = await processor().process(make_pdf(("Page one", "Page two")))

        assert result.page_count == 2
        assert "Page one" in result.text
        assert "Page two" in result.text


class TestSignatureAndStructure:
    async def test_non_pdf_is_rejected_by_signature(self):
        with pytest.raises(DocumentProcessingError) as exc:
            await processor().process(b"PK\x03\x04 this is a zip")
        assert exc.value.code == DOCUMENT_SIGNATURE_INVALID

    async def test_missing_eof_trailer_is_malformed(self):
        with pytest.raises(DocumentProcessingError) as exc:
            await processor().process(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n")
        assert exc.value.code == DOCUMENT_MALFORMED

    async def test_corrupt_structure_is_malformed(self):
        body = b"%PDF-1.4\nthis is not a pdf at all\n%%EOF\n"
        with pytest.raises(DocumentProcessingError) as exc:
            await processor().process(body)
        assert exc.value.code in {DOCUMENT_MALFORMED, DOCUMENT_EMPTY}

    async def test_zero_page_pdf_is_empty(self):
        with pytest.raises(DocumentProcessingError) as exc:
            await processor().process(make_pdf(()))
        assert exc.value.code == DOCUMENT_EMPTY

    async def test_page_limit_is_enforced(self):
        with pytest.raises(DocumentProcessingError) as exc:
            await processor(max_pages=2).process(make_pdf(("a", "b", "c")))
        assert exc.value.code == DOCUMENT_TOO_MANY_PAGES

    async def test_encrypted_pdf_is_rejected(self):
        with pytest.raises(DocumentProcessingError) as exc:
            await processor().process(make_encrypted_pdf())
        assert exc.value.code == DOCUMENT_ENCRYPTED


class TestBoundsAndWarnings:
    async def test_text_limit_truncates(self):
        long_text = "x" * 5_000
        result = await processor(max_text_chars=100).process(make_pdf((long_text,)))

        assert result.text_truncated is True
        assert "EXTRACTED_TEXT_TRUNCATED" in result.warnings
        assert len(result.text) == 100

    async def test_no_extractable_text_is_flagged(self):
        result = await processor().process(make_pdf(("",)))
        assert "NO_EXTRACTABLE_TEXT" in result.warnings
        assert result.text == ""

    async def test_active_content_is_reported_not_executed(self):
        pdf = make_pdf(("danger",), extra_content=b"\n% /JavaScript\n")
        result = await processor().process(pdf)
        assert "DOCUMENT_CONTAINS_ACTIVE_CONTENT" in result.warnings

    async def test_timeout_is_reported(self, monkeypatch):
        def slow(self, data):  # noqa: ANN001
            time.sleep(0.3)
            return None

        monkeypatch.setattr(PdfDocumentProcessor, "_process_sync", slow)
        with pytest.raises(DocumentProcessingError) as exc:
            await processor(processing_timeout_seconds=0.01).process(make_pdf())
        assert exc.value.code == DOCUMENT_PROCESSING_TIMEOUT

    async def test_missing_library_is_reported(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "pypdf", None)
        with pytest.raises(DocumentProcessingError) as exc:
            await processor().process(make_pdf())
        assert exc.value.code == DOCUMENT_PROCESSING_UNAVAILABLE
