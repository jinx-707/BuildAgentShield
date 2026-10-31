"""
Download Security Demo.
Run: python -m examples.download_security_demo
"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("PAYMENT_MODE", "test")

from app.capabilities.online.downloads.url_validator import validate_download_url
from app.capabilities.online.downloads.file_validator import validate_file
from app.capabilities.online.downloads.malware_scanner import MockMalwareScanner, ScanStatus
from app.capabilities.online.downloads.file_hasher import hash_bytes
from app.capabilities.online.downloads.quarantine_manager import QuarantineManager
from app.core.exceptions import SSRFAttemptError, URLValidationError, FileValidationError


async def demo():
    print("=" * 60)
    print("AgentShield Download Security Demo")
    print("=" * 60)

    # ── 1. Malicious URLs ─────────────────────────────────────────────────
    print("\n[1] Malicious Download URL Blocking")
    urls = [
        ("http://127.0.0.1/malware.exe", "Loopback SSRF"),
        ("http://10.0.0.1/internal", "Private network"),
        ("http://169.254.169.254/credentials", "Cloud metadata"),
        ("file:///etc/shadow", "File access"),
        ("ftp://malware.example.com/file.exe", "FTP scheme"),
        ("https://example.com/document.pdf", "Legitimate download"),
    ]
    for url, desc in urls:
        try:
            validate_download_url(url)
            print(f"  ✓ ALLOWED: {desc}")
        except (SSRFAttemptError, URLValidationError) as e:
            print(f"  ✓ BLOCKED: {desc} — {str(e)[:50]}")

    # ── 2. File Validation ────────────────────────────────────────────────
    print("\n[2] File Signature Validation")
    with tempfile.TemporaryDirectory() as tmpdir:
        test_files = [
            (b"%PDF-1.4 sample content", ".pdf", "PDF file"),
            (b"\x7fELF fake elf binary", ".pdf", "ELF binary disguised as PDF"),
            (b"MZ windows pe header", ".jpg", "Windows PE disguised as JPG"),
            (b"\x89PNG\r\n\x1a\n" + b"\x00" * 100, ".png", "Valid PNG"),
        ]
        for content, ext, desc in test_files:
            path = os.path.join(tmpdir, f"test{ext}")
            with open(path, "wb") as f:
                f.write(content)
            try:
                validate_file(file_path=path, max_size_bytes=1_000_000)
                print(f"  ✓ ALLOWED: {desc}")
            except FileValidationError as e:
                print(f"  ✓ BLOCKED: {desc} — {str(e)[:60]}")

    # ── 3. Malware Detection ──────────────────────────────────────────────
    print("\n[3] Malware Scanner")
    scanner = MockMalwareScanner()
    test_contents = [
        (b"Normal text document content", "test.txt", "Clean file"),
        (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
         "eicar_test.txt", "EICAR test string"),
        (b"malicious payload", "malware_payload.txt", "Malware filename heuristic"),
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        for content, filename, desc in test_contents:
            path = os.path.join(tmpdir, filename)
            with open(path, "wb") as f:
                f.write(content)
            result = scanner.scan_file(path)
            marker = "✓" if result.status in (ScanStatus.CLEAN, ScanStatus.INFECTED) else "?"
            status = "CLEAN" if result.status == ScanStatus.CLEAN else f"INFECTED ({result.threat_name})"
            print(f"  {marker} {status}: {desc}")

    # ── 4. File Hashing ───────────────────────────────────────────────────
    print("\n[4] SHA-256 Integrity Verification")
    content = b"Important document content that must not be tampered with"
    original_hash = hash_bytes(content)
    tampered = content + b" (modified)"
    tampered_hash = hash_bytes(tampered)
    print(f"  ✓ Original hash: {original_hash[:32]}...")
    print(f"  ✓ Tampered hash: {tampered_hash[:32]}... (different)")
    print(f"  ✓ Integrity check: hashes differ = {original_hash != tampered_hash}")

    # ── 5. Quarantine ─────────────────────────────────────────────────────
    print("\n[5] Quarantine Management")
    with tempfile.TemporaryDirectory() as tmpdir:
        q_dir = os.path.join(tmpdir, "quarantine")
        mgr = QuarantineManager(quarantine_dir=q_dir)

        src = os.path.join(tmpdir, "malware.bin")
        with open(src, "wb") as f:
            f.write(b"malicious content here")

        record = mgr.quarantine(
            file_path=src,
            original_url="https://evil.com/malware.bin",
            mime_type="application/octet-stream",
            scan_result="Mock.Malware.Test",
            security_decision="QUARANTINE",
            quarantine_reason="Malware detected by scanner",
        )
        print(f"  ✓ Quarantined: {record.quarantine_id}")
        print(f"  ✓ SHA-256: {record.sha256[:32]}...")
        print(f"  ✓ Original file removed: {not os.path.exists(src)}")
        # Verify path not exposed externally
        d = record.to_dict()
        print(f"  ✓ Path hidden in external response: {'quarantine_path' not in d}")

    print("\n" + "=" * 60)
    print("Download security demo complete.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(demo())
