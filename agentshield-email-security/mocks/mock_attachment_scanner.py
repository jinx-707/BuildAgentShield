"""Development mock implementation of AttachmentScanner.

WARNING:
This mock is for local development and test suites ONLY.
It DOES NOT provide production malware detection and must NEVER be used in production.
"""

import hashlib
import logging
from app.security.attachment_scanner import (
    AttachmentScanResult,
    BaseAttachmentScanner,
    sanitize_filename,
)

logger = logging.getLogger("agentshield.mocks.attachment_scanner")


class MockAttachmentScanner(BaseAttachmentScanner):
    """Development mock attachment scanner."""

    IS_DEVELOPMENT_MOCK: bool = True

    def __init__(self, default_safe: bool = True):
        logger.warning(
            "*** SECURITY WARNING: MockAttachmentScanner ACTIVE. THIS IS A TEST MOCK ONLY. ***"
        )
        self.default_safe = default_safe

    async def scan(
        self, filename: str, declared_content_type: str, data: bytes
    ) -> AttachmentScanResult:
        sanitized = sanitize_filename(filename)
        size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()

        reasons = []
        is_safe = self.default_safe
        quarantined = False

        if b"MALICIOUS_VIRUS_SIGNATURE" in data or filename.endswith(".malware"):
            is_safe = False
            quarantined = True
            reasons.append("Mock malware signature detected")
        elif b"MZ" == data[:2] and not filename.endswith(".exe"):
            is_safe = False
            quarantined = True
            reasons.append("Disguised executable detected in mock scan")

        return AttachmentScanResult(
            filename=filename,
            sanitized_filename=sanitized,
            declared_content_type=declared_content_type,
            size_bytes=size,
            sha256_hash=sha256,
            is_safe=is_safe,
            quarantined=quarantined,
            reasons=reasons,
        )

