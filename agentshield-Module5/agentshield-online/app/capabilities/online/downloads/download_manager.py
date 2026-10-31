"""
Download manager — streaming HTTPS downloader with full security controls.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from app.capabilities.online.downloads.file_hasher import hash_file
from app.capabilities.online.downloads.file_validator import validate_file, FileValidationResult
from app.capabilities.online.downloads.malware_scanner import ClamAVScanner, ScanStatus, MockMalwareScanner
from app.capabilities.online.downloads.quarantine_manager import QuarantineManager
from app.capabilities.online.downloads.storage_manager import StorageManager
from app.capabilities.online.downloads.url_validator import validate_download_url
from app.core.exceptions import (
    DownloadError,
    DownloadSizeLimitError,
    FileValidationError,
    MalwareDetectedError,
    QuarantinedError,
    ScannerUnavailableError,
    SSRFAttemptError,
    URLValidationError,
)
from app.core.result_models import DownloadRecord

logger = logging.getLogger(__name__)


class DownloadPolicy:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        c = config or {}
        self.max_file_size = c.get("max_file_size_bytes", 52428800)
        self.max_redirects = c.get("max_redirects", 3)
        self.allowed_mimes = c.get("allowed_mime_types", [])
        self.allowed_extensions = c.get("allowed_extensions", [])
        self.blocked_mimes = c.get("blocked_mime_types", [])
        self.connection_timeout = c.get("connection_timeout_seconds", 10)
        self.read_timeout = c.get("read_timeout_seconds", 60)
        self.approved_domains = c.get("approved_source_domains", [])
        self.blocked_domains = c.get("blocked_source_domains", [])


class DownloadManager:
    """
    Handles the complete secure download pipeline:
    URL validation → streaming download → file validation → malware scan → quarantine/store
    """

    def __init__(
        self,
        scanner: ClamAVScanner | MockMalwareScanner,
        storage: StorageManager,
        quarantine: QuarantineManager,
        policy: DownloadPolicy | None = None,
    ) -> None:
        self._scanner = scanner
        self._storage = storage
        self._quarantine = quarantine
        self._policy = policy or DownloadPolicy()
        # In-memory download registry — in production, use DB
        self._downloads: dict[str, DownloadRecord] = {}

    async def download(
        self,
        url: str,
        requested_filename: str | None = None,
    ) -> DownloadRecord:
        """
        Full secure download pipeline.
        Returns DownloadRecord on success.
        Raises on any security failure.
        """
        download_id = f"dl_{uuid.uuid4().hex[:12]}"

        # Step 1: Validate URL (no SSRF, no private IPs)
        try:
            validate_download_url(
                url=url,
                domain_allowlist=self._policy.approved_domains or None,
                domain_blocklist=self._policy.blocked_domains,
            )
        except (SSRFAttemptError, URLValidationError) as e:
            raise

        # Step 2: Allocate temp file
        suffix = ""
        if requested_filename:
            suffix = Path(requested_filename).suffix
        temp_path = self._storage.allocate(suffix=suffix or ".tmp")

        try:
            # Step 3: Stream download
            filename, content_type = await self._stream_download(url, temp_path)

            # Step 4: File validation (magic bytes, MIME, extension)
            file_result: FileValidationResult = validate_file(
                file_path=temp_path,
                declared_mime=content_type,
                declared_filename=filename,
                allowed_mimes=self._policy.allowed_mimes or None,
                allowed_extensions=self._policy.allowed_extensions or None,
                max_size_bytes=self._policy.max_file_size,
            )

            # Step 5: Malware scan
            scan_result = self._scanner.scan_file(temp_path)

            # Step 6: Hash
            sha256 = hash_file(temp_path)
            file_size = self._storage.get_size(temp_path)

            # Step 7: Quarantine if infected
            if scan_result.status == ScanStatus.INFECTED:
                qrec = self._quarantine.quarantine(
                    file_path=temp_path,
                    original_url=url,
                    mime_type=file_result.detected_mime,
                    scan_result=scan_result.threat_name or "unknown",
                    security_decision="QUARANTINE",
                    quarantine_reason=f"Malware detected: {scan_result.threat_name}",
                )
                raise MalwareDetectedError(
                    f"Malware detected: {scan_result.threat_name}. "
                    f"File quarantined: {qrec.quarantine_id}"
                )

            # Clean download — create record
            record = DownloadRecord(
                download_id=download_id,
                url=url,
                filename=filename,
                file_size=file_size,
                sha256=sha256,
                mime_type=file_result.detected_mime,
                status="CLEAN",
                scan_result="CLEAN",
                created_at=datetime.utcnow(),
            )
            self._downloads[download_id] = record
            logger.info(
                "Download complete: id=%s url=%s sha256=%s mime=%s size=%s",
                download_id,
                url[:60],
                sha256[:16],
                file_result.detected_mime,
                file_size,
            )
            return record

        except (MalwareDetectedError, ScannerUnavailableError, FileValidationError,
                DownloadSizeLimitError) as e:
            # Clean up temp file if not quarantined
            self._storage.delete(temp_path)
            raise
        except Exception as e:
            self._storage.delete(temp_path)
            raise DownloadError(f"Download failed: {e}") from e

    async def _stream_download(
        self,
        url: str,
        dest: Path,
        max_size: int | None = None,
    ) -> tuple[str, str]:
        """
        Stream download to dest path.
        Returns (filename, content_type).
        Enforces size limits during streaming.
        """
        max_bytes = max_size or self._policy.max_file_size
        timeout = httpx.Timeout(
            connect=float(self._policy.connection_timeout),
            read=float(self._policy.read_timeout),
            write=30.0,
            pool=5.0,
        )

        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=self._policy.max_redirects,
            timeout=timeout,
            verify=True,
        ) as client:
            async with client.stream("GET", url) as resp:
                resp.raise_for_status()

                content_type = resp.headers.get("content-type", "application/octet-stream")
                content_type = content_type.split(";")[0].strip()

                # Content-length check
                content_length = resp.headers.get("content-length")
                if content_length:
                    declared_size = int(content_length)
                    if declared_size > max_bytes:
                        raise DownloadSizeLimitError(
                            f"Content-Length {declared_size} exceeds limit {max_bytes}"
                        )

                # Derive filename
                filename = _extract_filename(url, resp.headers)

                bytes_written = 0
                with open(dest, "wb") as f:
                    async for chunk in resp.aiter_bytes(chunk_size=65536):
                        bytes_written += len(chunk)
                        if bytes_written > max_bytes:
                            raise DownloadSizeLimitError(
                                f"Download exceeded size limit {max_bytes} bytes"
                            )
                        f.write(chunk)

        return filename, content_type

    def get_download(self, download_id: str) -> DownloadRecord | None:
        return self._downloads.get(download_id)


def _extract_filename(url: str, headers: httpx.Headers) -> str:
    """Extract safe filename from Content-Disposition or URL."""
    cd = headers.get("content-disposition", "")
    if "filename=" in cd:
        try:
            fname = cd.split("filename=")[1].strip().strip('"').strip("'")
            return Path(fname).name  # strip any path components
        except Exception:
            pass
    # Fallback: last path segment of URL
    from urllib.parse import urlparse
    path = urlparse(url).path
    name = Path(path).name
    return name or "download"
