"""
ClamAV malware scanner integration.

Verdicts
--------
CLEAN      — scanner confirmed no threats found.
INFECTED   — scanner found a known threat; file must be quarantined.
ERROR      — scanner returned an unexpected response; fail closed.
TIMEOUT    — scan timed out; fail closed.
UNAVAILABLE— scanner could not be reached; fail closed if configured.

Fail-closed policy
------------------
Any verdict that is not CLEAN results in QUARANTINED storage.  A file is
never released to approved storage without a confirmed CLEAN verdict.

The clamav_fail_closed setting controls whether UNAVAILABLE causes the
entire download to fail or merely to be quarantined.  In both cases the file
never reaches APPROVED state when the scanner is unavailable.

Implementation note
-------------------
clamd is used via its TCP socket interface.  The file path is passed to
the clamd SCAN command; clamd reads the file directly from the filesystem.
This avoids loading the entire file into memory just for scanning.
"""
from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Import clamd at module level so patch("services.scanner.clamd") works.
# Gracefully handle the case where clamd is not installed.
try:
    import clamd  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    clamd = None  # type: ignore[assignment]


class ScanVerdict(str, enum.Enum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class ScanResult:
    verdict: ScanVerdict
    detail: str | None = None     # threat name or error message
    scanner: str = "clamav"


class ScannerUnavailableError(Exception):
    """Raised when the scanner cannot be reached and fail_closed=True."""


class ClamAvScanner:
    """
    Scans files using a ClamAV daemon over TCP.

    Parameters
    ----------
    host:            ClamAV daemon hostname.
    port:            ClamAV daemon port (default 3310).
    timeout_seconds: Scan deadline in seconds.
    fail_closed:     When True, treat UNAVAILABLE as a hard error.
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 3310,
        timeout_seconds: float = 60.0,
        fail_closed: bool = True,
    ) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout_seconds
        self._fail_closed = fail_closed

    async def scan(self, file_path: Path) -> ScanResult:
        """
        Scan the file at file_path and return a ScanResult.

        Never returns a CLEAN verdict unless the scanner explicitly confirmed it.

        The clamd client is blocking (socket I/O plus a filesystem read by the
        daemon), so it runs in a worker thread: one slow scan must not stall the
        event loop and, with it, every other request.  On timeout the caller
        gets TIMEOUT and the file is never approved; the worker thread is
        detached and exits on its own socket timeout.
        """
        import asyncio

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self._do_scan, str(file_path)),
                timeout=self._timeout,
            )
            return result
        except TimeoutError:
            logger.error(
                "clamav_scan_timeout",
                extra={"file": str(file_path), "timeout": self._timeout},
            )
            return ScanResult(
                verdict=ScanVerdict.TIMEOUT,
                detail=f"Scan timed out after {self._timeout}s",
            )
        except ScannerUnavailableError:
            logger.error(
                "clamav_unavailable",
                extra={"host": self._host, "port": self._port},
            )
            if self._fail_closed:
                raise
            return ScanResult(
                verdict=ScanVerdict.UNAVAILABLE,
                detail="ClamAV is unavailable; file quarantined by policy.",
            )

    async def is_available(self) -> bool:
        """
        Ping ClamAV and return True only when a real scan can be performed.

        Without the clamd library no scan can be performed, so availability is
        False — readiness must not report a stub-only scanner as available.
        """
        import asyncio

        if clamd is None:
            return False
        try:
            await asyncio.wait_for(
                asyncio.to_thread(self._ping), timeout=5.0
            )
            return True
        except Exception:
            return False

    # ── Internal ──────────────────────────────────────────────────────────────

    def _do_scan(self, file_path: str) -> ScanResult:
        """Run SCAN command against file_path via clamd TCP socket (blocking)."""
        if clamd is None:
            logger.warning("clamd library not installed; using stub scan")
            return self._stub_scan(file_path)

        try:
            cd = clamd.ClamdNetworkSocket(
                host=self._host,
                port=self._port,
                timeout=self._timeout,
            )
            response = cd.scan(file_path)
        except clamd.ConnectionError as exc:
            raise ScannerUnavailableError(
                f"Could not connect to ClamAV at {self._host}:{self._port}: {exc}"
            ) from exc
        except Exception as exc:
            # Never store the raw client exception: it can embed the local
            # file path (which must not reach the API) and daemon internals.
            logger.error(
                "clamav_scan_error",
                extra={"file": file_path, "error_type": type(exc).__name__},
            )
            return ScanResult(
                verdict=ScanVerdict.ERROR,
                detail="ClamAV returned an error while scanning.",
            )

        # response is {file_path: ("OK" | "FOUND", threat_name | None)}
        if not response or file_path not in response:
            return ScanResult(
                verdict=ScanVerdict.ERROR,
                detail="ClamAV returned an unexpected response format.",
            )

        status, threat = response[file_path]
        if status == "OK":
            return ScanResult(verdict=ScanVerdict.CLEAN, detail=None)
        if status == "FOUND":
            return ScanResult(
                verdict=ScanVerdict.INFECTED,
                detail=threat or "unknown threat",
            )

        # Unknown status — never treat as clean.
        return ScanResult(
            verdict=ScanVerdict.ERROR,
            detail=f"Unknown ClamAV status: {status!r}",
        )

    def _ping(self) -> None:
        """Ping the daemon (blocking; call via a worker thread)."""
        if clamd is None:
            return

        cd = clamd.ClamdNetworkSocket(
            host=self._host, port=self._port, timeout=5.0
        )
        cd.ping()

    @staticmethod
    def _stub_scan(file_path: str) -> ScanResult:
        """
        Stub used when the clamd library is not installed.

        Returns UNAVAILABLE so the file is never silently approved.
        This is always fail-closed behaviour.
        """
        logger.warning(
            "clamav_stub_scan",
            extra={
                "file": file_path,
                "note": "clamd library absent; returning UNAVAILABLE",
            },
        )
        return ScanResult(
            verdict=ScanVerdict.UNAVAILABLE,
            detail="clamd library not installed; scan could not be performed.",
        )
