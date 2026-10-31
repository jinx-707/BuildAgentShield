"""
File validator — validates file signatures, MIME types, extensions.
Never trusts response headers or filenames alone.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import NamedTuple

from app.core.exceptions import FileValidationError

logger = logging.getLogger(__name__)

# Magic byte signatures for common file types
_MAGIC_SIGNATURES: dict[str, list[bytes]] = {
    "application/pdf": [b"%PDF"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "image/jpeg": [b"\xff\xd8\xff"],
    "image/gif": [b"GIF87a", b"GIF89a"],
    "application/zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "text/plain": [],  # no magic — validate by trying UTF-8 decode
    "text/csv": [],
    "application/json": [],
    # Executables — used to block, not allow
    "application/x-executable": [b"\x7fELF"],
    "application/x-dosexec": [b"MZ"],
    "application/x-mach-binary": [b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"],
}

_BLOCKED_MAGIC = {
    b"\x7fELF",     # ELF executable
    b"MZ",          # DOS/PE executable
    b"#!/",         # shell script shebang
    b"#!",          # generic shebang
}


class FileValidationResult(NamedTuple):
    valid: bool
    detected_mime: str
    detected_extension: str
    reason: str | None


def detect_mime_from_magic(data: bytes) -> str:
    """
    Detect MIME type from file magic bytes.
    Returns best guess or 'application/octet-stream'.
    """
    try:
        import magic  # python-magic
        mime = magic.from_buffer(data, mime=True)
        return mime
    except ImportError:
        # Fallback: manual magic check
        return _manual_magic_detect(data)
    except Exception as e:
        logger.warning("MIME detection error: %s", e)
        return "application/octet-stream"


def _manual_magic_detect(data: bytes) -> str:
    head = data[:16]
    for mime, sigs in _MAGIC_SIGNATURES.items():
        for sig in sigs:
            if head.startswith(sig):
                return mime
    return "application/octet-stream"


def validate_file(
    file_path: str | Path,
    declared_mime: str | None = None,
    declared_filename: str | None = None,
    allowed_mimes: list[str] | None = None,
    allowed_extensions: list[str] | None = None,
    max_size_bytes: int = 52428800,
) -> FileValidationResult:
    """
    Validate a downloaded file.
    Checks: size, magic bytes, MIME type, extension.
    Never trusts declared_mime or declared_filename alone.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileValidationError(f"File not found: {file_path}")

    # Size check
    size = path.stat().st_size
    if size > max_size_bytes:
        raise FileValidationError(
            f"File size {size} bytes exceeds limit {max_size_bytes} bytes"
        )

    # Read first 8KB for magic detection
    with open(path, "rb") as f:
        header = f.read(8192)

    # Block known executable magic bytes
    for blocked_magic in _BLOCKED_MAGIC:
        if header.startswith(blocked_magic):
            raise FileValidationError(
                f"File has executable magic bytes ({blocked_magic!r}) — "
                "potentially dangerous file type blocked"
            )

    # Detect MIME from magic
    detected_mime = detect_mime_from_magic(header)

    # Extension from filename
    ext = ""
    if declared_filename:
        ext = Path(declared_filename).suffix.lower()
    elif path.name:
        ext = path.suffix.lower()

    # Check against allowed lists
    if allowed_mimes and detected_mime not in allowed_mimes:
        raise FileValidationError(
            f"Detected MIME type '{detected_mime}' is not in allowed list: {allowed_mimes}"
        )

    if allowed_extensions and ext and ext not in allowed_extensions:
        raise FileValidationError(
            f"File extension '{ext}' is not in allowed list: {allowed_extensions}"
        )

    return FileValidationResult(
        valid=True,
        detected_mime=detected_mime,
        detected_extension=ext,
        reason=None,
    )
