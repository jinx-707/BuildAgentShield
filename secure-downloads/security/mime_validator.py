"""
MIME type and magic-byte validator for downloaded files.

Security model
--------------
- The HTTP Content-Type header is treated as an untrusted hint only.
- The filename extension is treated as an untrusted hint only.
- The actual file bytes are inspected using python-magic (libmagic).
- Only explicitly allowlisted MIME types are accepted.
- Archive formats are always rejected to prevent decompression bombs and
  malicious nested content.
- A mismatch between the detected MIME type and the allowed set causes REJECTED.

Initial release: PDF-only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from security.errors import ARCHIVE_REJECTED, MIME_NOT_ALLOWED, DownloadSecurityError

# ── Archive magic bytes / MIME types that are always rejected ─────────────────
_ARCHIVE_MIME_TYPES: frozenset[str] = frozenset(
    [
        "application/zip",
        "application/x-zip-compressed",
        "application/x-zip",
        "application/x-rar-compressed",
        "application/vnd.rar",
        "application/x-7z-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-gzip",
        "application/x-bzip2",
        "application/x-xz",
        "application/zstd",
        "application/x-lzip",
        "application/x-lzma",
        "application/x-lzop",
        "application/x-compress",
        "application/x-archive",
        "application/x-cpio",
        "application/x-iso9660-image",
        "application/vnd.ms-cab-compressed",
        "application/x-deb",
        "application/x-rpm",
        "application/java-archive",
    ]
)

# Magic-byte prefixes for common archives (checked independently of libmagic
# to guard against edge cases in the MIME database).
_ARCHIVE_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"PK\x03\x04",        # ZIP
    b"PK\x05\x06",        # ZIP (empty)
    b"PK\x07\x08",        # ZIP (spanned)
    b"Rar!\x1a\x07",      # RAR
    b"7z\xbc\xaf'\x1c",   # 7-Zip
    b"\x1f\x8b",           # gzip
    b"BZh",                # bzip2
    b"\xfd7zXZ\x00",       # XZ
    b"\x28\xb5\x2f\xfd",  # zstd
    b"\x04\x22\x4d\x18",  # LZ4
    b"ustar",              # TAR (POSIX)
    b"MSCF",               # CAB
    b"\xc5\xd0\xd3\xc6",  # Debian .deb (ar archive)
    b"!<arch>\n",          # ar archive
)

# PDF magic bytes — the only currently allowed format.
_PDF_MAGIC = b"%PDF-"

# ── Allowed MIME types for the initial release ────────────────────────────────
_ALLOWED_MIME_TYPES: frozenset[str] = frozenset(["application/pdf"])

# PDF extension — must match when an extension is present.
_PDF_EXTENSIONS: frozenset[str] = frozenset([".pdf"])


@dataclass
class MimeValidationResult:
    detected_mime: str
    is_valid: bool
    rejection_reason: str | None = None


class MimeValidator:
    """
    Validates downloaded file content using actual magic bytes.

    The validator:
    1. Detects archive magic bytes from the raw file header (independent of MIME DB).
    2. Detects the MIME type from the file header bytes using libmagic.
    3. Rejects any MIME type not in the allowlist.
    4. For PDF: verifies the %PDF- magic prefix.
    5. Optionally validates that the filename extension is consistent.

    Parameters
    ----------
    allowed_mime_types: Override the default allowlist.
    """

    def __init__(
        self,
        *,
        allowed_mime_types: frozenset[str] | None = None,
    ) -> None:
        self._allowed = allowed_mime_types or _ALLOWED_MIME_TYPES

    def validate_header(
        self,
        header_bytes: bytes,
        *,
        content_type_hint: str | None = None,
        filename_hint: str | None = None,
    ) -> MimeValidationResult:
        """
        Validate the file header bytes (first 512+ bytes are sufficient).

        Parameters
        ----------
        header_bytes:      The first N bytes of the file (at least 512 recommended).
        content_type_hint: The HTTP Content-Type header value (treated as untrusted).
        filename_hint:     The suggested filename (treated as untrusted).

        Returns a MimeValidationResult.  Raises DownloadSecurityError on rejection.
        """
        if not header_bytes:
            self._reject(MIME_NOT_ALLOWED, "Empty file or no content received.")

        # 1. Archive magic-byte check — fail immediately on archive content.
        for prefix in _ARCHIVE_MAGIC_PREFIXES:
            if header_bytes.startswith(prefix):
                self._reject(
                    ARCHIVE_REJECTED,
                    "Archive files are not permitted. "
                    f"Detected archive magic bytes: {prefix!r}.",
                )

        # 2. Detect MIME type from raw bytes.
        detected = self._detect_mime(header_bytes)

        # 3. Archive MIME type check.
        if detected in _ARCHIVE_MIME_TYPES:
            self._reject(
                ARCHIVE_REJECTED,
                f"Archive files are not permitted. Detected MIME type: {detected!r}.",
            )

        # 4. Allowlist check.
        if detected not in self._allowed:
            self._reject(
                MIME_NOT_ALLOWED,
                f"File type {detected!r} is not permitted. "
                f"Allowed types: {sorted(self._allowed)}.",
            )

        # 5. PDF-specific magic prefix check.
        if detected == "application/pdf":
            self._validate_pdf_magic(header_bytes)

        # 6. Extension consistency check (untrusted hint — rejection only on mismatch).
        if filename_hint:
            self._validate_extension(detected, filename_hint)

        return MimeValidationResult(detected_mime=detected, is_valid=True)

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _detect_mime(data: bytes) -> str:
        try:
            import magic  # type: ignore[import-untyped]
            return magic.from_buffer(data, mime=True)
        except ImportError:
            # Fallback: check the PDF magic bytes directly.
            if data.startswith(_PDF_MAGIC):
                return "application/pdf"
            return "application/octet-stream"

    @staticmethod
    def _validate_pdf_magic(data: bytes) -> None:
        if not data.startswith(_PDF_MAGIC):
            raise DownloadSecurityError(
                MIME_NOT_ALLOWED,
                "File is detected as PDF but does not start with the %PDF- signature.",
            )

    def _validate_extension(self, detected_mime: str, filename: str) -> None:
        _, ext = os.path.splitext(filename.lower())
        if not ext:
            return

        # If the extension suggests a different format, reject.
        if detected_mime == "application/pdf" and ext not in _PDF_EXTENSIONS:
            raise DownloadSecurityError(
                MIME_NOT_ALLOWED,
                f"File extension {ext!r} does not match the detected "
                f"MIME type {detected_mime!r}.",
            )

    @staticmethod
    def _reject(code: str, message: str) -> None:
        raise DownloadSecurityError(code, message)
