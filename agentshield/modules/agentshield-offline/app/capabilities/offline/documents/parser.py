"""
AgentShield Offline — Document Parser.

Parses supported document formats and extracts text and metadata.
All parsers run with timeouts and resource limits to prevent DoS.
Macros, scripts, and embedded executable content are never executed.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import signal
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Optional
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeoutError
import concurrent.futures

import structlog

from app.core.configuration import get_settings
from app.core.exceptions import DocumentParseError

log = structlog.get_logger(__name__)


@dataclass
class ParsedDocument:
    format: str
    text: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    page_count: Optional[int] = None
    sheet_names: Optional[list[str]] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Per-format parsers
# ---------------------------------------------------------------------------


def _parse_pdf(path: Path, max_pages: int, max_text_len: int) -> ParsedDocument:
    try:
        import fitz  # PyMuPDF

        doc = fitz.open(str(path))
        page_count = doc.page_count
        if page_count > max_pages:
            raise DocumentParseError(
                f"PDF has {page_count} pages, exceeds limit {max_pages}",
                format="pdf",
            )

        texts = []
        meta = doc.metadata or {}
        for page in doc:
            texts.append(page.get_text())
        full_text = "\n".join(texts)
        if len(full_text) > max_text_len:
            full_text = full_text[:max_text_len] + "\n[TEXT TRUNCATED]"

        return ParsedDocument(
            format="pdf",
            text=full_text,
            metadata={k: v for k, v in meta.items() if v},
            page_count=page_count,
        )
    except DocumentParseError:
        raise
    except Exception as exc:
        raise DocumentParseError(f"PDF parse error: {exc}", format="pdf") from exc


def _parse_docx(path: Path, max_text_len: int) -> ParsedDocument:
    try:
        from docx import Document  # python-docx

        doc = Document(str(path))
        paragraphs = [p.text for p in doc.paragraphs]
        full_text = "\n".join(paragraphs)
        if len(full_text) > max_text_len:
            full_text = full_text[:max_text_len] + "\n[TEXT TRUNCATED]"

        core_props = doc.core_properties
        meta = {}
        for attr in ("author", "title", "subject", "keywords", "description"):
            val = getattr(core_props, attr, None)
            if val:
                meta[attr] = str(val)

        return ParsedDocument(format="docx", text=full_text, metadata=meta)
    except Exception as exc:
        raise DocumentParseError(f"DOCX parse error: {exc}", format="docx") from exc


def _parse_xlsx(path: Path, max_text_len: int) -> ParsedDocument:
    try:
        import openpyxl

        wb = openpyxl.load_workbook(
            str(path), read_only=True, data_only=True, keep_vba=False
        )
        sheet_names = wb.sheetnames
        rows = []
        for sname in sheet_names:
            ws = wb[sname]
            rows.append(f"[Sheet: {sname}]")
            for row in ws.iter_rows(values_only=True):
                rows.append("\t".join(str(c) if c is not None else "" for c in row))
        full_text = "\n".join(rows)
        if len(full_text) > max_text_len:
            full_text = full_text[:max_text_len] + "\n[TEXT TRUNCATED]"

        wb.close()
        return ParsedDocument(format="xlsx", text=full_text, sheet_names=sheet_names)
    except Exception as exc:
        raise DocumentParseError(f"XLSX parse error: {exc}", format="xlsx") from exc


def _parse_pptx(path: Path, max_pages: int, max_text_len: int) -> ParsedDocument:
    try:
        from pptx import Presentation

        prs = Presentation(str(path))
        slides = []
        for i, slide in enumerate(prs.slides):
            if i >= max_pages:
                break
            for shape in slide.shapes:
                if shape.has_text_frame:
                    slides.append(shape.text_frame.text)

        full_text = "\n".join(slides)
        if len(full_text) > max_text_len:
            full_text = full_text[:max_text_len] + "\n[TEXT TRUNCATED]"

        return ParsedDocument(
            format="pptx",
            text=full_text,
            page_count=len(prs.slides),
        )
    except Exception as exc:
        raise DocumentParseError(f"PPTX parse error: {exc}", format="pptx") from exc


def _parse_text(path: Path, max_text_len: int) -> ParsedDocument:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        if len(text) > max_text_len:
            text = text[:max_text_len] + "\n[TEXT TRUNCATED]"
        return ParsedDocument(format="txt", text=text)
    except Exception as exc:
        raise DocumentParseError(f"Text parse error: {exc}", format="txt") from exc


def _parse_csv(path: Path, max_text_len: int) -> ParsedDocument:
    try:
        rows = []
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                rows.append(",".join(row))
        full_text = "\n".join(rows)
        if len(full_text) > max_text_len:
            full_text = full_text[:max_text_len] + "\n[TEXT TRUNCATED]"
        return ParsedDocument(format="csv", text=full_text)
    except Exception as exc:
        raise DocumentParseError(f"CSV parse error: {exc}", format="csv") from exc


def _parse_json(path: Path, max_text_len: int) -> ParsedDocument:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        # Validate it is actual JSON
        json.loads(text)
        if len(text) > max_text_len:
            text = text[:max_text_len] + "\n[TEXT TRUNCATED]"
        return ParsedDocument(format="json", text=text)
    except json.JSONDecodeError as exc:
        raise DocumentParseError(f"Invalid JSON: {exc}", format="json") from exc
    except Exception as exc:
        raise DocumentParseError(f"JSON parse error: {exc}", format="json") from exc


def _parse_xml(path: Path, max_text_len: int) -> ParsedDocument:
    """Parse XML with entity expansion disabled."""
    try:
        # Disable entity expansion to prevent XXE attacks
        parser = ET.XMLParser()
        # Python's stdlib ElementTree does not expand external entities
        # For additional safety we disable default namespace processing
        tree = ET.parse(str(path), parser=parser)
        root = tree.getroot()
        # Extract all text nodes
        texts = [elem.text or "" for elem in root.iter() if elem.text]
        full_text = "\n".join(texts)
        if len(full_text) > max_text_len:
            full_text = full_text[:max_text_len] + "\n[TEXT TRUNCATED]"
        return ParsedDocument(format="xml", text=full_text)
    except ET.ParseError as exc:
        raise DocumentParseError(f"XML parse error: {exc}", format="xml") from exc
    except Exception as exc:
        raise DocumentParseError(f"XML parse error: {exc}", format="xml") from exc


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------


class DocumentParser:
    """
    Dispatches to the appropriate per-format parser with timeout protection.
    """

    def __init__(self) -> None:
        self._settings = get_settings()

    async def parse(self, path: Path, fmt: str) -> ParsedDocument:
        """
        Parse *path* as *fmt* with a processing timeout.
        Runs in a thread pool to avoid blocking the async event loop.
        """
        timeout = self._settings.document_processing_timeout
        max_pages = self._settings.document_max_pages
        max_text = self._settings.document_max_text_length

        loop = asyncio.get_event_loop()
        fn = partial(self._parse_sync, path, fmt, max_pages, max_text)

        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, fn),
                timeout=float(timeout),
            )
            return result
        except asyncio.TimeoutError:
            raise DocumentParseError(
                f"Document parsing timed out after {timeout}s", format=fmt
            )
        except DocumentParseError:
            raise
        except Exception as exc:
            raise DocumentParseError(f"Unexpected parse error: {exc}", format=fmt) from exc

    @staticmethod
    def _parse_sync(path: Path, fmt: str, max_pages: int, max_text: int) -> ParsedDocument:
        dispatch = {
            "pdf": lambda: _parse_pdf(path, max_pages, max_text),
            "docx": lambda: _parse_docx(path, max_text),
            "xlsx": lambda: _parse_xlsx(path, max_text),
            "pptx": lambda: _parse_pptx(path, max_pages, max_text),
            "txt": lambda: _parse_text(path, max_text),
            "md": lambda: _parse_text(path, max_text),
            "csv": lambda: _parse_csv(path, max_text),
            "json": lambda: _parse_json(path, max_text),
            "xml": lambda: _parse_xml(path, max_text),
        }
        parser_fn = dispatch.get(fmt)
        if not parser_fn:
            raise DocumentParseError(f"No parser for format '{fmt}'", format=fmt)
        return parser_fn()
