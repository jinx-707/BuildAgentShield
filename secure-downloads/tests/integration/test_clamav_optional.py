"""
OPTIONAL real-ClamAV integration test.

This is deliberately separate from every other scanner test.  The rest of the
suite uses a scripted stand-in and proves the quarantine/approval *logic*; it
does not prove a real ClamAV integration.  This module proves the real one, and
is skipped unless a clamd daemon is reachable.

Enable it explicitly:

    SECURE_DOWNLOADS_CLAMAV_EICAR_TEST=1 \
    CLAMAV_HOST=127.0.0.1 CLAMAV_PORT=3310 \
    .venv/bin/python -m pytest tests/integration/test_clamav_optional.py -v

The only "malware" used is the EICAR test string, which is not a virus.
"""
from __future__ import annotations

import os

import pytest

from services import scanner as scanner_module
from services.scanner import ClamAvScanner, ScanVerdict

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
BENIGN_PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


def _clamd_endpoint() -> tuple[str, int] | None:
    if os.environ.get("SECURE_DOWNLOADS_CLAMAV_EICAR_TEST") != "1":
        return None
    if scanner_module.clamd is None:
        return None
    host = os.environ.get("CLAMAV_HOST", "127.0.0.1")
    port = int(os.environ.get("CLAMAV_PORT", "3310"))
    try:
        cd = scanner_module.clamd.ClamdNetworkSocket(host=host, port=port, timeout=3)
        cd.ping()
    except Exception:
        return None
    return host, port


_ENDPOINT = _clamd_endpoint()
pytestmark = [
    pytest.mark.skipif(
        _ENDPOINT is None,
        reason="real clamd not reachable; set SECURE_DOWNLOADS_CLAMAV_EICAR_TEST=1",
    ),
    pytest.mark.real_clamav,
]


async def test_real_clamav_is_available():
    assert _ENDPOINT is not None
    host, port = _ENDPOINT
    assert await ClamAvScanner(host=host, port=port).is_available() is True


async def test_real_clamav_detects_eicar(tmp_path):
    assert _ENDPOINT is not None
    host, port = _ENDPOINT
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)

    result = await ClamAvScanner(host=host, port=port, timeout_seconds=30).scan(sample)

    assert result.verdict == ScanVerdict.INFECTED
    assert result.detail


async def test_real_clamav_reports_benign_pdf_clean(tmp_path):
    assert _ENDPOINT is not None
    host, port = _ENDPOINT
    sample = tmp_path / "benign.pdf"
    sample.write_bytes(BENIGN_PDF)

    result = await ClamAvScanner(host=host, port=port, timeout_seconds=30).scan(sample)

    assert result.verdict == ScanVerdict.CLEAN
    assert result.detail is None
