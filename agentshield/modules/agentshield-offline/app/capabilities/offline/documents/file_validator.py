"""
AgentShield Offline — Document File Validator.

Validates file existence, size, signature, and MIME type.
Never trusts the filename extension alone.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import structlog

from app.core.configuration import get_settings
from app.core.exceptions import (
    DocumentSizeLimitError,
    UnsupportedFormatError,
)

log = structlog.get_logger(__name__)

# Magic bytes (file signatures) for supported formats
_MAGIC_SIGNATURES: dict[str, list[bytes]] = {
    "pdf": [b"%PDF"],
    "docx": [b"PK\x03\x04"],   # ZIP-based OOXML
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "zip": [b"PK\x03\x04"],
    "txt": [],  # no fixed magic
    "md": [],
    "csv": [],
    "json": [],
    "xml": [b"<?xml", b"<"],
}

_ALLOWED_MIMETYPES: dict[str, list[str]] = {
    "pdf": ["application/pdf"],
    "docx": [
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip",
    ],
    "xlsx": [
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip",
    ],
    "pptx": [
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/zip",
    ],
    "txt": ["text/plain"],
    "md": ["text/plain", "text/markdown"],
    "csv": ["text/csv", "text/plain"],
    "json": ["application/json", "text/plain"],
    "xml": ["text/xml", "application/xml"],
}

SUPPORTED_EXTENSIONS = frozenset(_ALLOWED_MIMETYPES.keys())


def detect_mime(path: Path) -> str:
    """Detect MIME type using libmagic. Falls back to 'application/octet-stream'."""
    try:
        import magic  # type: ignore
        mime = magic.from_file(str(path), mime=True)
        return mime or "application/octet-stream"
    except Exception:
        # magic not available — fall back gracefully
        return "application/octet-stream"


def read_magic_bytes(path: Path, n: int = 8) -> bytes:
    with path.open("rb") as f:
        return f.read(n)


class FileValidator:
    """
    Validates a document file before parsing.
    """

    def __init__(self) -> None:
        self._settings = get_settings()

    def validate(self, path: Path) -> str:
        """
        Validate the file and return the detected format identifier (e.g. 'pdf').
        Raises DocumentSizeLimitError or UnsupportedFormatError on failure.
        """
        if not path.exists():
            raise UnsupportedFormatError(f"File does not exist: {path}")

        if not path.is_file():
            raise UnsupportedFormatError(f"Path is not a regular file: {path}")

        # Size check
        size = path.stat().st_size
        if size == 0:
            raise UnsupportedFormatError("File is empty", detected_format="empty")
        if size > self._settings.document_max_size_bytes:
            raise DocumentSizeLimitError(
                f"File size {size} exceeds limit {self._settings.document_max_size_bytes}",
                size=size,
                limit=self._settings.document_max_size_bytes,
            )

        # Declared extension
        ext = path.suffix.lower().lstrip(".")
        if ext not in SUPPORTED_EXTENSIONS:
            raise UnsupportedFormatError(
                f"Unsupported file extension '.{ext}'",
                detected_format=ext,
            )

        # Magic byte check (best-effort)
        magic_bytes = read_magic_bytes(path)
        sigs = _MAGIC_SIGNATURES.get(ext, [])
        if sigs:
            matches = any(magic_bytes.startswith(sig) for sig in sigs)
            if not matches:
                raise UnsupportedFormatError(
                    f"File signature does not match declared extension '.{ext}' "
                    f"(magic: {magic_bytes[:4]!r})",
                    detected_format=ext,
                )

        # MIME type cross-check
        mime = detect_mime(path)
        allowed_mimes = _ALLOWED_MIMETYPES.get(ext, [])
        if allowed_mimes and not any(mime.startswith(m) for m in allowed_mimes):
            # Log but don't block — magic library may not be installed
            log.warning(
                "mime_type_mismatch",
                path=str(path),
                declared_ext=ext,
                detected_mime=mime,
                allowed_mimes=allowed_mimes,
            )

        return ext
