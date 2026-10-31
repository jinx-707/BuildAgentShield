"""Attachment security scanner: File signature (magic bytes), archive bomb defense, and quarantine."""

import hashlib
import io
import logging
import os
import re
import secrets
import tempfile
import zipfile
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field
from app.config import get_settings

logger = logging.getLogger("agentshield.security.attachment_scanner")

# Magic signatures
MAGIC_EXECUTABLES = [
    (b"MZ", "Windows/DOS executable (PE/COFF)"),
    (b"\x7fELF", "Linux ELF executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java bytecode"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit executable"),
    (b"#!/bin/sh", "Shell script"),
    (b"#!/bin/bash", "Bash script"),
    (b"#!/usr/bin/env", "Script interpreter invocation"),
]

MAGIC_SAFE_DOCUMENTS = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"PK\x03\x04", "application/zip"),  # Also covers .docx, .xlsx, .pptx
]


class AttachmentScanResult(BaseModel):
    """Result from deep attachment inspection."""

    model_config = ConfigDict(extra="ignore")

    filename: str
    sanitized_filename: str
    declared_content_type: str
    detected_mime: Optional[str] = None
    size_bytes: int
    sha256_hash: str
    is_safe: bool
    quarantined: bool = False
    # quarantine_path is intentionally NOT included — never expose filesystem paths in responses
    quarantine_ref: Optional[str] = None  # opaque reference token, not a path
    reasons: List[str] = Field(default_factory=list)


def sanitize_filename(raw_name: str) -> str:
    """Sanitize filename to prevent directory traversal and special character exploits."""
    if not raw_name:
        return "unnamed_attachment.dat"

    # Remove path traversal characters
    clean = os.path.basename(raw_name.replace("\\", "/"))
    # Remove null bytes and control chars
    clean = re.sub(r"[\x00-\x1f\x7f]", "", clean)
    # Remove dangerous Windows reserved chars
    clean = re.sub(r'[<>:"/\\|?*]', "_", clean)
    clean = clean.strip(". ")
    return clean if clean else "sanitized_attachment.dat"


class BaseAttachmentScanner(ABC):
    """Abstract interface contract for attachment security scanner."""

    @abstractmethod
    async def scan(
        self, filename: str, declared_content_type: str, data: bytes
    ) -> AttachmentScanResult:
        """Scan raw attachment bytes and return security outcome."""
        pass


# Quarantine retention: files are preserved for this duration before they may be purged.
QUARANTINE_RETENTION_DAYS: int = 90


class LocalAttachmentScanner(BaseAttachmentScanner):
    """Security scanner inspecting file signatures, archive bombs, and path traversal.

    Quarantine retention policy:
      - Files are written to a dedicated, permission-restricted quarantine directory.
      - Each file is named with a cryptographically random token (not the sha256 or filename)
        to prevent enumeration and symlink pre-staging attacks.
      - Quarantine files are NEVER automatically deleted before QUARANTINE_RETENTION_DAYS.
      - The filesystem path is never returned in scan results or API responses.
      - An opaque reference token is returned instead for internal audit correlation.
    """

    def __init__(self, quarantine_dir: Optional[str] = None):
        settings = get_settings()
        # Prefer an explicit argument, then fall back to a subdirectory of the system temp dir
        # so we never hard-code /tmp in production.
        self.quarantine_dir = quarantine_dir or os.path.join(
            tempfile.gettempdir(), "agentshield_quarantine"
        )
        self.settings = settings
        self._init_quarantine_dir()

    def _init_quarantine_dir(self) -> None:
        """Create quarantine directory with strict permissions, refusing symlinks."""
        parent = os.path.dirname(self.quarantine_dir)
        # Resolve the parent to catch traversal before mkdir
        real_parent = os.path.realpath(parent)
        target = os.path.join(real_parent, os.path.basename(self.quarantine_dir))
        os.makedirs(target, mode=0o700, exist_ok=True)
        # Reject if the path is a symlink (could have been pre-staged by attacker)
        if os.path.islink(target):
            raise RuntimeError(f"Quarantine directory is a symlink — refusing to use: {target}")
        self.quarantine_dir = target

    def _write_quarantine(self, data: bytes) -> str:
        """Write data to quarantine using an unpredictable filename.

        Returns an opaque reference token (not a path).
        Raises on failure — caller must treat scan as unsafe.
        """
        ref_token = secrets.token_hex(32)
        # Use a fixed suffix that is not the original extension
        dest = os.path.join(self.quarantine_dir, f"{ref_token}.quar")
        # Resolve to catch any traversal in quarantine_dir itself
        real_dest = os.path.realpath(dest)
        if not real_dest.startswith(os.path.realpath(self.quarantine_dir) + os.sep):
            raise RuntimeError("Quarantine path traversal detected")
        if os.path.exists(real_dest) or os.path.islink(real_dest):
            raise RuntimeError("Quarantine destination already exists — possible collision or symlink attack")
        # Write to a temp file in the same directory, then rename atomically
        fd, tmp_path = tempfile.mkstemp(dir=self.quarantine_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.chmod(tmp_path, 0o600)
            os.rename(tmp_path, real_dest)
        except Exception:
            # Clean up the temp file on failure; do NOT leave partial data
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return ref_token

    async def scan(
        self, filename: str, declared_content_type: str, data: bytes
    ) -> AttachmentScanResult:
        sanitized = sanitize_filename(filename)
        size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
        reasons: List[str] = []
        is_safe = True
        quarantined = False
        quarantine_ref: Optional[str] = None
        detected_mime = None
        scan_error = False

        try:
            # 1. Size check
            if size > self.settings.MAX_ATTACHMENT_SIZE_BYTES:
                is_safe = False
                reasons.append(
                    f"File size ({size} bytes) exceeds maximum limit ({self.settings.MAX_ATTACHMENT_SIZE_BYTES} bytes)"
                )

            # 2. Check for Executable Magic Bytes (disguised executables)
            for sig, desc in MAGIC_EXECUTABLES:
                if data.startswith(sig):
                    is_safe = False
                    quarantined = True
                    reasons.append(f"Executable file signature detected disguised as document: {desc}")
                    break

            # 3. Detect file type signature
            for sig, mime in MAGIC_SAFE_DOCUMENTS:
                if data.startswith(sig):
                    detected_mime = mime
                    break

            # Disguised extension check: e.g. named .pdf but magic is not %PDF-
            lower_name = sanitized.lower()
            if lower_name.endswith(".pdf") and not data.startswith(b"%PDF-"):
                is_safe = False
                reasons.append("File claims to be PDF but lacks '%PDF-' magic header")

            # 4. Archive bomb check (for zip/office files)
            if data.startswith(b"PK\x03\x04"):
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        total_uncompressed = 0
                        file_count = 0
                        for info in zf.infolist():
                            file_count += 1
                            total_uncompressed += info.file_size
                            if file_count > 1000:
                                is_safe = False
                                reasons.append("Archive contains excessive number of files (>1000)")
                                break

                        if size > 0 and (total_uncompressed / size) > 100 and total_uncompressed > 50 * 1024 * 1024:
                            is_safe = False
                            quarantined = True
                            reasons.append(
                                f"Archive bomb detected: uncompressed ratio {total_uncompressed / size:.1f}:1"
                            )
                except zipfile.BadZipFile:
                    if lower_name.endswith((".zip", ".docx", ".xlsx", ".pptx")):
                        is_safe = False
                        reasons.append("Corrupted or malformed archive format")

        except Exception as exc:
            # Any unexpected scan failure must result in an unsafe verdict — fail closed.
            logger.error(f"Attachment scan raised unexpected exception for '{sanitized}': {exc}")
            is_safe = False
            scan_error = True
            reasons.append("Attachment scan failed with an internal error — treating as unsafe (fail-closed)")

        # 5. Quarantine handling — only after scan logic completes
        if quarantined and not scan_error:
            try:
                quarantine_ref = self._write_quarantine(data)
                logger.info(f"Quarantined attachment sha256={sha256} ref={quarantine_ref}")
            except Exception as qe:
                logger.error(f"Failed to write quarantine file for sha256={sha256}: {qe}")
                # Quarantine write failure is itself a security failure — keep is_safe=False
                reasons.append("Quarantine write failed — attachment blocked")

        return AttachmentScanResult(
            filename=filename,
            sanitized_filename=sanitized,
            declared_content_type=declared_content_type,
            detected_mime=detected_mime,
            size_bytes=size,
            sha256_hash=sha256,
            is_safe=is_safe,
            quarantined=quarantined,
            quarantine_ref=quarantine_ref,
            reasons=reasons,
        )

