"""Attachment validation engine: Extension analysis, double-extension detection, and size limits."""

import base64
import logging
import os
from typing import List, Set
from app.config import get_settings
from app.schemas.email import EmailAttachmentInput
from app.schemas.security import AttachmentValidationResult

logger = logging.getLogger("agentshield.security.attachment")

# File extensions classified as dangerous or executable
DANGEROUS_EXTENSIONS: Set[str] = {
    ".exe", ".bat", ".cmd", ".sh", ".bash", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".scr", ".jar", ".msi", ".dll",
    ".com", ".pif", ".cpl", ".hta", ".reg", ".bin", ".iso", ".img",
}

# Dangerous MIME types
DANGEROUS_MIME_TYPES: Set[str] = {
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-sh",
    "application/x-csh",
    "application/javascript",
    "application/x-bat",
}


class AttachmentValidator:
    """Validates email attachments before outbound delivery or after inbound receipt."""

    def __init__(self, max_size_bytes: int = None):
        settings = get_settings()
        self.max_size_bytes = max_size_bytes or settings.MAX_ATTACHMENT_SIZE_BYTES

    def validate_attachment(self, attachment: EmailAttachmentInput) -> tuple[bool, str]:
        """Validate single attachment for naming, double extensions, MIME type, and size."""
        filename = attachment.filename.strip()
        lower_name = filename.lower()

        # Check for empty filename or directory traversal sequences
        if not filename or "/" in filename or "\\" in filename or ".." in filename:
            return False, f"Filename '{filename}' contains invalid or directory traversal characters"

        # Check double-extension tricks first (e.g. invoice.pdf.exe or report.docx.vbs)
        parts = lower_name.split(".")
        if len(parts) > 2:
            inner_ext = f".{parts[-2]}"
            if inner_ext in {".pdf", ".docx", ".xlsx", ".txt", ".jpg", ".png"} and f".{parts[-1]}" in DANGEROUS_EXTENSIONS:
                return False, f"Double-extension deception detected: '{filename}'"

        # Check dangerous primary extension
        _, ext = os.path.splitext(lower_name)
        if ext in DANGEROUS_EXTENSIONS:
            return False, f"Prohibited executable or script extension: '{ext}'"

        # Check MIME type
        if attachment.content_type.lower() in DANGEROUS_MIME_TYPES:
            return False, f"Disallowed dangerous MIME type: '{attachment.content_type}'"

        # Validate base64 payload size
        try:
            raw_bytes = base64.b64decode(attachment.content_base64)
            size = len(raw_bytes)
        except Exception:
            return False, f"Attachment '{filename}' contains corrupted base64 data"

        if size > self.max_size_bytes:
            return False, f"Attachment '{filename}' size ({size} bytes) exceeds limit ({self.max_size_bytes} bytes)"

        return True, ""

    def validate_attachments(
        self, attachments: List[EmailAttachmentInput]
    ) -> AttachmentValidationResult:
        """Validate an array of attachments."""
        if not attachments:
            return AttachmentValidationResult(is_valid=True, rejected_attachments=[], reasons=[])

        rejected: List[str] = []
        reasons: List[str] = []

        total_size = 0
        for att in attachments:
            valid, reason = self.validate_attachment(att)
            if not valid:
                rejected.append(att.filename)
                reasons.append(reason)
            else:
                try:
                    total_size += len(base64.b64decode(att.content_base64))
                except Exception:
                    pass

        settings = get_settings()
        if total_size > settings.MAX_TOTAL_MESSAGE_SIZE_BYTES:
            rejected.append("TOTAL_PAYLOAD")
            reasons.append(
                f"Combined attachments size ({total_size} bytes) exceeds maximum allowable message size"
            )

        return AttachmentValidationResult(
            is_valid=len(rejected) == 0,
            rejected_attachments=rejected,
            reasons=reasons,
        )
