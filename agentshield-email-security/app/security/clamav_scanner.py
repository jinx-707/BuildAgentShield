"""ClamAV malware scanner integration with fail-closed behavior and structured verdicts.

Scan verdicts:
  CLEAN             — scanner ran, no threat found
  INFECTED          — scanner found a known threat
  SUSPICIOUS        — heuristic match, not a confirmed signature
  NOT_SCANNED       — file was not submitted (e.g. size exceeded limit before scan)
  SCANNER_UNAVAILABLE — ClamAV daemon unreachable or not configured
  SCAN_ERROR        — scanner returned an unexpected error

The EICAR test string is the standard controlled test payload for antivirus integration.
It is not malware and is safe to include in test fixtures.

ClamAV dependency:
  pip install clamd>=1.0.2
  System: apt-get install clamav-daemon  (or brew install clamav on macOS)
  Socket: /var/run/clamav/clamd.ctl  (Unix socket, preferred)
         or TCP localhost:3310

If ClamAV is unavailable the scanner returns SCANNER_UNAVAILABLE and the caller
must treat the attachment as unsafe (fail-closed). The scanner never silently
downgrades a verdict.
"""

import hashlib
import logging
import os
import tempfile
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict

from app.security.attachment_scanner import (
    AttachmentScanResult,
    BaseAttachmentScanner,
    LocalAttachmentScanner,
    sanitize_filename,
)

logger = logging.getLogger("agentshield.security.clamav")

# EICAR test string — safe, standardized AV test payload (not real malware)
EICAR_TEST_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


class ScanVerdict(str, Enum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    SUSPICIOUS = "SUSPICIOUS"
    NOT_SCANNED = "NOT_SCANNED"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"
    SCAN_ERROR = "SCAN_ERROR"


class ClamAVScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    verdict: ScanVerdict
    threat_name: Optional[str] = None
    scanner_version: Optional[str] = None
    error_detail: Optional[str] = None


def _try_import_clamd():
    """Import clamd lazily so the module loads even when clamd is not installed."""
    try:
        import clamd
        return clamd
    except ImportError:
        return None


def _connect_clamav(socket_path: Optional[str] = None, host: str = "127.0.0.1", port: int = 3310):
    """Attempt to connect to ClamAV daemon. Returns clamd connection or None."""
    clamd = _try_import_clamd()
    if clamd is None:
        logger.warning("clamd Python package not installed; ClamAV scanning unavailable")
        return None

    # Prefer Unix socket if it exists
    effective_socket = socket_path or "/var/run/clamav/clamd.ctl"
    if os.path.exists(effective_socket):
        try:
            cd = clamd.ClamdUnixSocket(path=effective_socket)
            cd.ping()
            return cd
        except Exception as e:
            logger.warning(f"ClamAV Unix socket connect failed ({effective_socket}): {e}")

    # Fall back to TCP
    try:
        cd = clamd.ClamdNetworkSocket(host=host, port=port, timeout=10)
        cd.ping()
        return cd
    except Exception as e:
        logger.warning(f"ClamAV TCP connect failed ({host}:{port}): {e}")

    return None


def scan_bytes_with_clamav(
    data: bytes,
    socket_path: Optional[str] = None,
    max_size_bytes: int = 25 * 1024 * 1024,
) -> ClamAVScanResult:
    """Scan raw bytes with ClamAV. Never executes the payload.

    Uses an in-memory stream scan (instream) to avoid writing to disk.
    Falls back to a temp file only if instream is unavailable.
    """
    if len(data) > max_size_bytes:
        return ClamAVScanResult(
            verdict=ScanVerdict.NOT_SCANNED,
            error_detail=f"File size {len(data)} exceeds ClamAV scan limit {max_size_bytes}",
        )

    cd = _connect_clamav(socket_path=socket_path)
    if cd is None:
        return ClamAVScanResult(
            verdict=ScanVerdict.SCANNER_UNAVAILABLE,
            error_detail="ClamAV daemon not reachable",
        )

    try:
        # Prefer instream (no temp file needed)
        import io
        result = cd.instream(io.BytesIO(data))
        # result format: {'stream': ('OK', None)} or {'stream': ('FOUND', 'Eicar-Test-Signature')}
        status, threat = result.get("stream", ("ERROR", "no result"))
    except Exception as e:
        logger.error(f"ClamAV instream scan error: {e}")
        return ClamAVScanResult(
            verdict=ScanVerdict.SCAN_ERROR,
            error_detail=str(e),
        )

    try:
        version_info = cd.version()
        scanner_version = version_info if isinstance(version_info, str) else str(version_info)
    except Exception:
        scanner_version = None

    if status == "OK":
        return ClamAVScanResult(verdict=ScanVerdict.CLEAN, scanner_version=scanner_version)
    elif status == "FOUND":
        return ClamAVScanResult(
            verdict=ScanVerdict.INFECTED,
            threat_name=threat,
            scanner_version=scanner_version,
        )
    else:
        return ClamAVScanResult(
            verdict=ScanVerdict.SCAN_ERROR,
            error_detail=f"Unexpected ClamAV status: {status}",
            scanner_version=scanner_version,
        )


class ClamAVAttachmentScanner(BaseAttachmentScanner):
    """Attachment scanner that combines magic-byte heuristics with ClamAV signature scanning.

    Verdict precedence (most severe wins):
      1. INFECTED / SCAN_ERROR / SCANNER_UNAVAILABLE  → is_safe=False
      2. SUSPICIOUS                                    → is_safe=False
      3. NOT_SCANNED (size exceeded)                  → is_safe=False (fail-closed)
      4. CLEAN + heuristics pass                      → is_safe=True

    A SCANNER_UNAVAILABLE result never silently passes — it always fails closed.
    """

    def __init__(
        self,
        quarantine_dir: Optional[str] = None,
        clamav_socket: Optional[str] = None,
    ):
        self._local = LocalAttachmentScanner(quarantine_dir=quarantine_dir)
        self._clamav_socket = clamav_socket

    async def scan(
        self, filename: str, declared_content_type: str, data: bytes
    ) -> AttachmentScanResult:
        # Run local heuristic scan first
        result = await self._local.scan(filename, declared_content_type, data)

        # Run ClamAV scan regardless of heuristic result
        clamav_result = scan_bytes_with_clamav(data, socket_path=self._clamav_socket)

        reasons = list(result.reasons)

        if clamav_result.verdict == ScanVerdict.CLEAN:
            pass  # No additional reason needed
        elif clamav_result.verdict == ScanVerdict.INFECTED:
            result.is_safe = False
            reasons.append(
                f"ClamAV: INFECTED — threat={clamav_result.threat_name}"
            )
        elif clamav_result.verdict == ScanVerdict.SUSPICIOUS:
            result.is_safe = False
            reasons.append(
                f"ClamAV: SUSPICIOUS — threat={clamav_result.threat_name}"
            )
        elif clamav_result.verdict == ScanVerdict.NOT_SCANNED:
            result.is_safe = False
            reasons.append(
                f"ClamAV: NOT_SCANNED — {clamav_result.error_detail} (fail-closed)"
            )
        elif clamav_result.verdict == ScanVerdict.SCANNER_UNAVAILABLE:
            result.is_safe = False
            reasons.append(
                "ClamAV: SCANNER_UNAVAILABLE — antivirus daemon unreachable (fail-closed)"
            )
        elif clamav_result.verdict == ScanVerdict.SCAN_ERROR:
            result.is_safe = False
            reasons.append(
                f"ClamAV: SCAN_ERROR — {clamav_result.error_detail} (fail-closed)"
            )

        result.reasons = reasons
        return result
