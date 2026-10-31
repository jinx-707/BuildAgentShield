"""
Local, bounded PDF processing for the analysis pipeline.

What this module does
---------------------
Parses an APPROVED PDF that has already passed MIME/signature checks and the
ClamAV scan, and produces the locally derived facts used for analysis:

* page count (bounded),
* extracted text (bounded, sanitized, control characters removed),
* structural warnings (truncation, no extractable text, active-content
  tokens, per-page extraction failures).

What it deliberately does not do
--------------------------------
* It never executes JavaScript, launch actions, embedded files or macros.
  PDF active-content markers are detected and reported as warnings only.
* It does not decrypt password-protected documents.  Encrypted PDFs are
  rejected as unsupported (DOCUMENT_ENCRYPTED).
* It never treats extracted text as instructions.  The text is data: it is
  length-bounded, control characters are stripped, and it is sent to the
  provider in a dedicated `extracted_text` field that the provider contract
  defines as untrusted input.

Limits
------
`analysis_max_pages`, `analysis_max_extracted_chars` and
`analysis_processing_timeout_seconds` are enforced here.  The whole parse
runs in a worker thread under `asyncio.wait_for`; if the deadline fires the
thread may keep running until it finishes (Python cannot pre-empt a thread),
so the input size and page cap — not the timeout — are the hard memory
bounds.
"""
from __future__ import annotations

import asyncio
import io
import logging
import re
from dataclasses import dataclass, field

from security.errors import (
    DOCUMENT_EMPTY,
    DOCUMENT_ENCRYPTED,
    DOCUMENT_MALFORMED,
    DOCUMENT_PROCESSING_TIMEOUT,
    DOCUMENT_PROCESSING_UNAVAILABLE,
    DOCUMENT_SIGNATURE_INVALID,
    DOCUMENT_TOO_MANY_PAGES,
)

logger = logging.getLogger(__name__)

PDF_MAGIC = b"%PDF-"
_EOF_WINDOW = 4_096

# PDF tokens that indicate active content.  Presence is reported as a
# warning; nothing in this module (or pypdf) executes them.
_ACTIVE_CONTENT_TOKENS: tuple[bytes, ...] = (
    b"/JavaScript",
    b"/JS",
    b"/Launch",
    b"/OpenAction",
    b"/EmbeddedFile",
    b"/RichMedia",
    b"/AA",
)

_TEXT_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HORIZONTAL_SPACE = re.compile(r"[ \t\f\v]+")
_BLANK_LINES = re.compile(r"\n{3,}")


class DocumentProcessingError(Exception):
    """A document failed local processing (non-retryable for the same bytes)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ProcessedDocument:
    document_type: str
    page_count: int
    text: str
    text_truncated: bool
    warnings: list[str] = field(default_factory=list)


def _sanitize_pdf_text(value: str) -> str:
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = _TEXT_CONTROL.sub("", value)
    value = _HORIZONTAL_SPACE.sub(" ", value)
    value = _BLANK_LINES.sub("\n\n", value)
    return value.strip()


class PdfDocumentProcessor:
    """Bounded, synchronous-parser-backed PDF inspection."""

    def __init__(
        self,
        *,
        max_pages: int = 200,
        max_text_chars: int = 200_000,
        processing_timeout_seconds: float = 20.0,
    ) -> None:
        self._max_pages = max_pages
        self._max_text_chars = max_text_chars
        self._timeout = processing_timeout_seconds

    async def process(self, data: bytes) -> ProcessedDocument:
        if not data.startswith(PDF_MAGIC):
            raise DocumentProcessingError(
                DOCUMENT_SIGNATURE_INVALID,
                "The file does not start with the %PDF- signature.",
            )
        if b"%%EOF" not in data[-_EOF_WINDOW:]:
            # A PDF without a trailer marker is truncated or malformed; the
            # downloader already rejected inconsistent framing, so this is
            # document-level damage.
            raise DocumentProcessingError(
                DOCUMENT_MALFORMED,
                "The PDF is missing its %%EOF trailer and may be truncated.",
            )

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._process_sync, data),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            raise DocumentProcessingError(
                DOCUMENT_PROCESSING_TIMEOUT,
                f"Document processing exceeded {self._timeout:g}s.",
            ) from exc

    # ── Synchronous implementation (runs in a worker thread) ────────────────

    def _process_sync(self, data: bytes) -> ProcessedDocument:
        try:
            import pypdf  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise DocumentProcessingError(
                DOCUMENT_PROCESSING_UNAVAILABLE,
                "The PDF processing library is not installed.",
            ) from exc

        try:
            reader = pypdf.PdfReader(io.BytesIO(data), strict=False)
        except Exception as exc:
            logger.warning(
                "pdf_parse_failed",
                extra={"error_type": type(exc).__name__},
            )
            raise DocumentProcessingError(
                DOCUMENT_MALFORMED, "The PDF structure could not be parsed."
            ) from exc

        if reader.is_encrypted:
            raise DocumentProcessingError(
                DOCUMENT_ENCRYPTED,
                "Password-protected or encrypted PDFs are not supported.",
            )

        try:
            page_count = len(reader.pages)
        except Exception as exc:
            raise DocumentProcessingError(
                DOCUMENT_MALFORMED, "The PDF page tree could not be read."
            ) from exc

        if page_count == 0:
            raise DocumentProcessingError(
                DOCUMENT_EMPTY, "The PDF contains no pages."
            )
        if page_count > self._max_pages:
            raise DocumentProcessingError(
                DOCUMENT_TOO_MANY_PAGES,
                f"The PDF has {page_count} pages; the limit is {self._max_pages}.",
            )

        warnings: list[str] = []
        parts: list[str] = []
        total = 0
        truncated = False
        extraction_failures = 0

        for page in reader.pages:
            if truncated:
                break
            try:
                page_text = page.extract_text() or ""
            except Exception:
                extraction_failures += 1
                continue
            cleaned = _sanitize_pdf_text(page_text)
            if not cleaned:
                continue
            remaining = self._max_text_chars - total
            if remaining <= 0:
                truncated = True
                break
            if len(cleaned) > remaining:
                parts.append(cleaned[:remaining])
                total = self._max_text_chars
                truncated = True
            else:
                parts.append(cleaned)
                total += len(cleaned)

        if extraction_failures:
            warnings.append("PAGE_TEXT_EXTRACTION_FAILED")
        if truncated:
            warnings.append("EXTRACTED_TEXT_TRUNCATED")
        if _contains_active_content(data):
            warnings.append("DOCUMENT_CONTAINS_ACTIVE_CONTENT")

        text = "\n".join(parts)
        if not text.strip():
            warnings.append("NO_EXTRACTABLE_TEXT")

        return ProcessedDocument(
            document_type="pdf",
            page_count=page_count,
            text=text,
            text_truncated=truncated,
            warnings=warnings,
        )


def _contains_active_content(data: bytes) -> bool:
    return any(token in data for token in _ACTIVE_CONTENT_TOKENS)
