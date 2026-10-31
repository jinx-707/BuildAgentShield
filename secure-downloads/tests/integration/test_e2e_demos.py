"""
End-to-end acceptance scenarios (Prompt 3, DEMO 1–10) against the real API.

Transport is a real local HTTPS server whose bytes are served over a real TLS
socket, so the production download path is exercised: URL validation, DNS/IP
policy, TLS verification, bounded streaming, framing acceptance, checksum
verification, the scan gate, and zone transitions.

Clearly-labelled simulation boundaries
--------------------------------------
* The malware scanner is a scripted stand-in (tests.conftest.FakeScanner).
  These tests therefore prove the quarantine/approval LOGIC, not a real
  ClamAV integration.  Real-ClamAV coverage is opt-in and distinct (see
  tests/integration/test_clamav_optional.py).
* The analysis provider is the explicit local mock (ANALYSIS_PROVIDER=
  local_mock).  These tests do not exercise a real vendor integration; the
  real-HTTP adapter is covered against a local HTTP server and a closed port
  in tests/integration/test_analysis_adapter_http.py and the outage test here.

Every test asserts the security outcome that matters: unapproved bytes are
never advertised as APPROVED, temporary files do not survive failures, and
one tenant cannot observe another tenant's resources.
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from config.settings import Settings
from models.download import DownloadState
from security.ssrf import SystemDnsResolver
from storage.manager import StorageRef, StorageZone
from tests.conftest import FakeScanner
from tests.integration.raw_http import closed_port
from tests.integration.tls_http import TlsRawServer, generate_self_signed_cert, tls_url
from tests.pdf_fixtures import make_pdf

API_TOKEN = "e2e-api-token"
TENANT = "tenant-e2e"

PDF = make_pdf(("Quarterly report body",))
PDF_SHA = hashlib.sha256(PDF).hexdigest()

MAX_FILE_BYTES = 100_000

pytestmark = pytest.mark.e2e


# ── Helpers ───────────────────────────────────────────────────────────────────

def _route_pdf(handler) -> None:
    handler.write_raw(
        "200 OK",
        [
            ("Content-Type", "application/pdf"),
            ("Content-Length", str(len(PDF))),
            ("Content-Disposition", 'attachment; filename="../../escape.pdf"'),
        ],
        PDF,
        close=True,
    )


def _route_short(handler) -> None:
    """Declares 9,999 bytes but sends 50 and closes: truncated response."""
    handler.write_raw(
        "200 OK",
        [("Content-Type", "application/pdf"), ("Content-Length", "9999")],
        PDF[:50],
        close=True,
    )


def _route_oversize(handler) -> None:
    # Valid PDF magic bytes so the rejection comes from the byte limit, not
    # from the MIME allowlist.
    body = b"%PDF-1.7\n" + b"x" * (MAX_FILE_BYTES + 5_000)
    handler.write_raw(
        "200 OK",
        [("Content-Type", "application/pdf"), ("Content-Length", str(len(body)))],
        body,
        close=True,
    )


def _route_slow(handler) -> None:
    time.sleep(1.5)
    _route_pdf(handler)


def _route_redirect_private(handler) -> None:
    handler.write_raw(
        "302 Found",
        [
            ("Location", "https://169.254.169.254/latest/meta-data/"),
            ("Content-Length", "0"),
        ],
        b"",
        close=True,
    )


def _route_redirect_loop(handler) -> None:
    handler.write_raw(
        "302 Found",
        [("Location", "/loop"), ("Content-Length", "0")],
        b"",
        close=True,
    )


@pytest.fixture
def tls_server(tmp_path):
    certfile, keyfile = generate_self_signed_cert(tmp_path)
    srv = TlsRawServer(
        {
            "/report.pdf": _route_pdf,
            "/short.pdf": _route_short,
            "/oversize.pdf": _route_oversize,
            "/slow.pdf": _route_slow,
            "/redirect-private": _route_redirect_private,
            "/loop": _route_redirect_loop,
        },
        certfile=certfile,
        keyfile=keyfile,
    )
    srv.certfile = certfile  # type: ignore[attr-defined]
    import threading

    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=10)


def base_settings(tmp_path, port: int, **overrides) -> Settings:
    base = {
        "environment": "test",
        "log_level": "WARNING",
        "api_auth_token": API_TOKEN,
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'e2e.db'}",
        "storage_root": str(tmp_path / "storage"),
        "egress_proxy_url": "",
        "egress_proxy_health_url": "",
        "require_egress_proxy": False,
        "proxy_auth_token": "",
        "allowed_domains": "",
        "default_domain_policy": "allow",
        # 443 lets policy checks reach the host/IP layer for URLs that omit a
        # port; the local test server's port is allowed for the E2E origin.
        "allowed_ports": f"443,{port}",
        "allow_private_networks": True,
        "dns_preflight_enabled": True,
        "clamav_host": "127.0.0.1",
        "clamav_port": closed_port(),
        "clamav_fail_closed": True,
        "rate_limit_enabled": False,
        "analysis_provider": "local_mock",
        "max_file_size_bytes": MAX_FILE_BYTES,
        "download_connect_timeout_seconds": 2.0,
        "download_read_timeout_seconds": 2.0,
        "download_total_timeout_seconds": 10.0,
        "analysis_job_timeout_seconds": 30.0,
        "analysis_max_attempts": 2,
        "analysis_retry_base_delay_seconds": 0.01,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def headers(tenant: str = TENANT) -> dict[str, str]:
    return {"Authorization": f"Bearer {API_TOKEN}", "X-Tenant-ID": tenant}


def post_download(client: TestClient, url: str, tenant: str = TENANT):
    return client.post(
        "/online/downloads",
        headers=headers(tenant),
        json={"url": url, "agent_id": "e2e-agent"},
    )


def wait_for_state(
    client: TestClient,
    download_id: str,
    states: set[str],
    *,
    tenant: str = TENANT,
    timeout: float = 15.0,
) -> dict:
    deadline = time.monotonic() + timeout
    body: dict = {}
    while time.monotonic() < deadline:
        resp = client.get(
            f"/online/downloads/{download_id}/status", headers=headers(tenant)
        )
        if resp.status_code == 200:
            body = resp.json()
            if body["state"] in states:
                return body
        time.sleep(0.05)
    raise AssertionError(f"download did not reach {states}; last={body}")


def wait_for_analysis(
    client: TestClient,
    download_id: str,
    states: set[str],
    *,
    tenant: str = TENANT,
    timeout: float = 15.0,
) -> dict:
    deadline = time.monotonic() + timeout
    body: dict = {}
    while time.monotonic() < deadline:
        resp = client.get(
            f"/online/downloads/{download_id}/analysis", headers=headers(tenant)
        )
        if resp.status_code == 200:
            body = resp.json()
            if body["state"] in states:
                return body
        time.sleep(0.05)
    raise AssertionError(f"analysis did not reach {states}; last={body}")


def zone_files(settings: Settings, zone: str) -> list[Path]:
    directory = Path(settings.storage_root) / zone
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir() if p.is_file())


def make_client(settings: Settings, *, verdict=None) -> TestClient:
    app = create_app(settings)
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()
    scanner = FakeScanner(verdict or _clean())
    app.state.orchestrator._scanner = scanner  # type: ignore[attr-defined]
    app.state.scanner = scanner
    client.scanner = scanner  # type: ignore[attr-defined]
    client.settings = settings  # type: ignore[attr-defined]
    return client


def _clean():
    from services.scanner import ScanVerdict

    return ScanVerdict.CLEAN


@pytest.fixture
def app_client(tls_server, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.certfile))
    settings = base_settings(tmp_path, tls_server.server_address[1])
    client = make_client(settings)
    try:
        yield client
    finally:
        client.__exit__(None, None, None)


# ── DEMO 1 — successful secure download ──────────────────────────────────────

class TestDemo1SecureDownload:
    def test_download_verifies_checksum_scans_and_approves(self, app_client, tls_server):
        resp = post_download(app_client, tls_url(tls_server, "/report.pdf"))
        assert resp.status_code == 202
        download_id = resp.json()["download_id"]

        final = wait_for_state(app_client, download_id, {"APPROVED"})
        assert final["failure_reason"] is None

        meta = app_client.get(
            f"/online/downloads/{download_id}/metadata", headers=headers()
        ).json()
        assert meta["file_sha256"] == PDF_SHA
        assert meta["file_size"] == len(PDF)
        assert meta["detected_mime_type"] == "application/pdf"
        assert meta["scan_result"] == "CLEAN"
        assert meta["state"] == "APPROVED"
        # The caller-controlled Content-Disposition path must be basenamed.
        assert meta["original_filename"] == "escape.pdf"
        assert "storage_ref" not in meta
        assert str(app_client.settings.storage_root) not in app_client.get(
            f"/online/downloads/{download_id}/metadata", headers=headers()
        ).text

        approved = zone_files(app_client.settings, "approved")
        assert len(approved) == 1
        assert approved[0].stat().st_mode & 0o077 == 0  # owner-only
        ref = StorageRef(zone=StorageZone.APPROVED, filename=approved[0].name)
        served = app_client.app.state.storage.get_approved_path(ref).read_bytes()
        assert served == PDF
        assert hashlib.sha256(served).hexdigest() == PDF_SHA
        assert zone_files(app_client.settings, "temporary") == []
        assert tls_server.state["requests"].get("/report.pdf") == 1


# ── DEMO 2 — SSRF and network policy ────────────────────────────────────────

class TestDemo2SsrfPrevention:
    @pytest.mark.parametrize(
        "target",
        [
            "https://127.0.0.1:{port}/report.pdf",
            "https://10.0.0.1/file",
            "https://172.16.0.1/file",
            "https://192.168.1.1/file",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/file",
            "https://[fe80::1]/file",
        ],
    )
    def test_private_targets_are_rejected_without_connecting(
        self, tls_server, tmp_path, monkeypatch, target
    ):
        monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.certfile))
        port = tls_server.server_address[1]
        settings = base_settings(
            tmp_path,
            port,
            allowed_ports=f"443,{port}",
            allow_private_networks=False,
            analysis_provider="disabled",
        )
        client = make_client(settings)
        try:
            before = dict(tls_server.state["requests"])
            url = target.format(port=port)
            resp = post_download(client, url)
            assert resp.status_code == 202
            final = wait_for_state(
                client, resp.json()["download_id"], {"REJECTED"}
            )
            assert "restricted" in (final["failure_reason"] or "").lower()
            assert tls_server.state["requests"] == before
        finally:
            client.__exit__(None, None, None)

    def test_private_dns_answer_is_rejected(self, tls_server, tmp_path, monkeypatch):
        async def resolve_private(self, hostname):
            return ["10.0.0.5"]

        monkeypatch.setattr(SystemDnsResolver, "resolve", resolve_private)
        settings = base_settings(
            tmp_path,
            tls_server.server_address[1],
            allowed_domains="rebind.example.com",
            allowed_ports=f"443,{tls_server.server_address[1]}",
            default_domain_policy="deny",
            allow_private_networks=False,
            analysis_provider="disabled",
        )
        client = make_client(settings)
        try:
            resp = post_download(client, "https://rebind.example.com/file")
            assert resp.status_code == 202
            final = wait_for_state(
                client, resp.json()["download_id"], {"REJECTED"}
            )
            assert "restricted" in (final["failure_reason"] or "").lower()
        finally:
            client.__exit__(None, None, None)

    def test_disallowed_domain_is_rejected(self, tls_server, tmp_path):
        settings = base_settings(
            tmp_path,
            tls_server.server_address[1],
            allowed_domains="only.example.com",
            default_domain_policy="deny",
            analysis_provider="disabled",
        )
        client = make_client(settings)
        try:
            resp = post_download(client, "https://other.example.com/file")
            assert resp.status_code == 202
            final = wait_for_state(
                client, resp.json()["download_id"], {"REJECTED"}
            )
            assert "domain" in (final["failure_reason"] or "").lower()
        finally:
            client.__exit__(None, None, None)

    def test_disallowed_port_is_rejected_before_connecting(self, tls_server, tmp_path):
        port = tls_server.server_address[1]
        settings = base_settings(
            tmp_path, port, analysis_provider="disabled"
        )
        client = make_client(settings)
        try:
            before = dict(tls_server.state["requests"])
            # The server's own port is allowed; 8443 is not.
            resp = post_download(
                client, f"https://127.0.0.1:{port}/report.pdf".replace(
                    str(port), "8443"
                )
            )
            assert resp.status_code == 202
            final = wait_for_state(
                client, resp.json()["download_id"], {"REJECTED"}
            )
            assert "port" in (final["failure_reason"] or "").lower()
            assert tls_server.state["requests"] == before
        finally:
            client.__exit__(None, None, None)

    def test_redirect_to_metadata_service_is_rejected(self, app_client, tls_server):
        before = dict(tls_server.state["requests"])
        resp = post_download(app_client, tls_url(tls_server, "/redirect-private"))
        assert resp.status_code == 202
        final = wait_for_state(app_client, resp.json()["download_id"], {"REJECTED"})
        assert "restricted" in (final["failure_reason"] or "").lower()
        # Only the first hop reached the allowed server; the blocked
        # destination was never contacted.
        assert tls_server.state["requests"].get("/redirect-private", 0) == (
            before.get("/redirect-private", 0) + 1
        )
        assert zone_files(app_client.settings, "approved") == []


# ── DEMO 3 — malicious HTTP responses ───────────────────────────────────────

class TestDemo3MaliciousResponses:
    def test_truncated_body_is_never_approved(self, app_client, tls_server):
        resp = post_download(app_client, tls_url(tls_server, "/short.pdf"))
        download_id = resp.json()["download_id"]
        final = wait_for_state(app_client, download_id, {"REJECTED", "FAILED"})
        assert final["state"] != "APPROVED"
        assert zone_files(app_client.settings, "approved") == []
        assert zone_files(app_client.settings, "temporary") == []

    def test_oversized_body_is_rejected_mid_stream(self, app_client, tls_server):
        resp = post_download(app_client, tls_url(tls_server, "/oversize.pdf"))
        download_id = resp.json()["download_id"]
        final = wait_for_state(app_client, download_id, {"REJECTED"})
        assert "size" in (final["failure_reason"] or "").lower()
        assert zone_files(app_client.settings, "approved") == []
        assert zone_files(app_client.settings, "temporary") == []

    def test_redirect_loop_is_rejected(self, app_client, tls_server):
        resp = post_download(app_client, tls_url(tls_server, "/loop"))
        download_id = resp.json()["download_id"]
        final = wait_for_state(app_client, download_id, {"REJECTED"})
        assert "redirect" in (final["failure_reason"] or "").lower()
        assert zone_files(app_client.settings, "temporary") == []


# ── DEMO 4 — malware quarantine (SIMULATED scanner) ─────────────────────────

class TestDemo4Quarantine:
    def test_infected_file_is_quarantined_and_unreachable(self, app_client, tls_server):
        from services.scanner import ScanVerdict

        app_client.scanner.verdict = ScanVerdict.INFECTED
        app_client.scanner.detail = "Eicar-Test-Signature"

        resp = post_download(app_client, tls_url(tls_server, "/report.pdf"))
        download_id = resp.json()["download_id"]
        wait_for_state(app_client, download_id, {"QUARANTINED"})

        meta = app_client.get(
            f"/online/downloads/{download_id}/metadata", headers=headers()
        ).json()
        assert meta["state"] == "QUARANTINED"
        assert meta["scan_result"] == "INFECTED"
        assert "Eicar" in (meta["scan_detail"] or "")

        assert zone_files(app_client.settings, "approved") == []
        quarantined = zone_files(app_client.settings, "quarantine")
        assert len(quarantined) == 1

        # Quarantined bytes can never be read through the approved accessor.
        q_ref = StorageRef(
            zone=StorageZone.QUARANTINE, filename=quarantined[0].name
        )
        with pytest.raises(ValueError):
            app_client.app.state.storage.get_approved_path(q_ref)

        analysis = app_client.post(
            f"/online/downloads/{download_id}/analysis", headers=headers()
        )
        assert analysis.status_code == 409
        assert analysis.json()["code"] == "INVALID_STATE"
        assert (
            app_client.get(
                f"/online/downloads/{download_id}/analysis/result",
                headers=headers(),
            ).status_code
            == 404
        )


# ── DEMO 5 — document analysis (local mock provider) ────────────────────────

class TestDemo5DocumentAnalysis:
    def test_approved_pdf_is_analyzed_and_normalized(self, app_client, tls_server):
        resp = post_download(app_client, tls_url(tls_server, "/report.pdf"))
        download_id = resp.json()["download_id"]
        wait_for_state(app_client, download_id, {"APPROVED"})

        job = app_client.post(
            f"/online/downloads/{download_id}/analysis", headers=headers()
        )
        assert job.status_code == 202
        wait_for_analysis(app_client, download_id, {"COMPLETED"})

        result = app_client.get(
            f"/online/downloads/{download_id}/analysis/result", headers=headers()
        )
        assert result.status_code == 200
        body = result.json()
        assert body["analysis_id"] == job.json()["analysis_id"]
        assert body["provider"] == "mock"
        assert body["sha256"] == PDF_SHA
        assert body["document_type"] == "pdf"
        assert "Quarterly report body" in body["extracted_text"]
        assert "MOCK_ANALYSIS_PROVIDER" in body["warnings"]

        # A different tenant cannot see the job or the result.
        assert (
            app_client.get(
                f"/online/downloads/{download_id}/analysis",
                headers=headers("tenant-other"),
            ).status_code
            == 404
        )


# ── DEMO 6 — tenant isolation on the download resources ─────────────────────

class TestDemo6TenantIsolation:
    def test_another_tenant_cannot_substitute_a_download_id(self, app_client, tls_server):
        resp = post_download(app_client, tls_url(tls_server, "/report.pdf"))
        download_id = resp.json()["download_id"]
        wait_for_state(app_client, download_id, {"APPROVED"})

        other = headers("tenant-other")
        for method, suffix in [
            ("get", "status"),
            ("get", "metadata"),
            ("post", "scan"),
            ("post", "analysis"),
            ("get", "analysis"),
            ("get", "analysis/result"),
            ("post", "analysis/retry"),
        ]:
            response = getattr(app_client, method)(
                f"/online/downloads/{download_id}/{suffix}", headers=other
            )
            assert response.status_code == 404, suffix
            assert "storage_ref" not in response.text


# ── DEMO 7 — concurrency and idempotency ────────────────────────────────────

class TestDemo7Concurrency:
    def test_concurrent_result_reads_are_consistent(self, app_client, tls_server):
        resp = post_download(app_client, tls_url(tls_server, "/report.pdf"))
        download_id = resp.json()["download_id"]
        wait_for_state(app_client, download_id, {"APPROVED"})
        app_client.post(f"/online/downloads/{download_id}/analysis", headers=headers())
        wait_for_analysis(app_client, download_id, {"COMPLETED"})

        url = f"/online/downloads/{download_id}/analysis/result"
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(
                pool.map(lambda _: app_client.get(url, headers=headers()), range(16))
            )
        assert {r.status_code for r in responses} == {200}
        assert len({r.json()["analysis_id"] for r in responses}) == 1

    def test_retry_while_running_is_refused(self, app_client, tls_server):
        resp = post_download(app_client, tls_url(tls_server, "/report.pdf"))
        download_id = resp.json()["download_id"]
        wait_for_state(app_client, download_id, {"APPROVED"})
        job = app_client.post(
            f"/online/downloads/{download_id}/analysis", headers=headers()
        ).json()

        # Force the durable row to RUNNING (as if a worker were mid-flight).
        db = app_client.settings.database_url.split("///", 1)[1]
        with sqlite3.connect(db, timeout=10) as conn:
            conn.execute(
                "UPDATE document_analyses SET state='RUNNING' WHERE id=?",
                (job["analysis_id"],),
            )
            conn.commit()

        retry = app_client.post(
            f"/online/downloads/{download_id}/analysis/retry", headers=headers()
        )
        assert retry.status_code == 409
        assert retry.json()["code"] == "INVALID_STATE"

    def test_tenant_concurrency_limit_is_deterministic(self, tls_server, tmp_path, monkeypatch):
        monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.certfile))
        settings = base_settings(
            tmp_path,
            tls_server.server_address[1],
            max_concurrent_downloads_per_tenant=1,
            analysis_provider="disabled",
        )
        client = make_client(settings)
        try:
            first = post_download(client, tls_url(tls_server, "/slow.pdf"))
            assert first.status_code == 202
            second = post_download(client, tls_url(tls_server, "/slow.pdf"))
            assert second.status_code == 429
            assert second.json()["code"] == "CONCURRENCY_LIMIT_EXCEEDED"
            wait_for_state(
                client, first.json()["download_id"], {"APPROVED"}, timeout=20
            )
            # After completion a new download is accepted again.
            third = post_download(client, tls_url(tls_server, "/report.pdf"))
            assert third.status_code == 202
            wait_for_state(
                client, third.json()["download_id"], {"APPROVED"}, timeout=20
            )
        finally:
            client.__exit__(None, None, None)


# ── DEMO 8 — failure recovery ───────────────────────────────────────────────

class TestDemo8Recovery:
    def test_restart_fails_interrupted_download_and_reclaims_temp(
        self, tls_server, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.certfile))
        settings = base_settings(
            tmp_path, tls_server.server_address[1], analysis_provider="disabled"
        )
        client = make_client(settings)
        # Seed a record that a previous process left mid-download.
        db = settings.database_url.split("///", 1)[1]
        temp_dir = Path(settings.storage_root) / "temporary"
        temp_dir.mkdir(parents=True, exist_ok=True)
        orphan = temp_dir / str(uuid.uuid4())
        orphan.write_bytes(b"%PDF-1.4 partial")
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        with sqlite3.connect(db, timeout=10) as conn:
            conn.execute(
                """
                INSERT INTO downloads (
                    id, tenant_id, agent_id, original_url, state,
                    original_filename, detected_mime_type, file_size, file_sha256,
                    storage_ref, created_at, updated_at, handoff_completed
                ) VALUES (?, ?, ?, ?, 'DOWNLOADING', NULL, NULL, NULL, NULL, ?, ?, ?, 0)
                """,
                (
                    "dl-interrupted",
                    TENANT,
                    "agent-1",
                    "https://example.com/file.pdf",
                    f"temporary/{orphan.name}",
                    now,
                    now,
                ),
            )
            conn.commit()
        client.__exit__(None, None, None)

        # A fresh process performs startup recovery.
        restarted = make_client(settings)
        try:
            status = restarted.get(
                "/online/downloads/dl-interrupted/status", headers=headers()
            ).json()
            assert status["state"] == "FAILED"
            assert "restart" in (status["failure_reason"] or "").lower()
            assert not orphan.exists()
        finally:
            restarted.__exit__(None, None, None)

    def test_unavailable_scanner_fails_closed(self, tls_server, tmp_path, monkeypatch):
        monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.certfile))
        settings = base_settings(
            tmp_path, tls_server.server_address[1], analysis_provider="disabled"
        )
        # Use the real scanner: its port points at a closed socket.
        app = create_app(settings)
        with TestClient(app, raise_server_exceptions=False) as client:
            client.settings = settings  # type: ignore[attr-defined]
            resp = post_download(client, tls_url(tls_server, "/report.pdf"))
            final = wait_for_state(
                client, resp.json()["download_id"], {"FAILED"}
            )
            assert "scan" in (final["failure_reason"] or "").lower()
            meta = client.get(
                f"/online/downloads/{resp.json()['download_id']}/metadata",
                headers=headers(),
            ).json()
            assert meta["scan_result"] == "ERROR"
            assert meta["scan_detail"] == "The malware scan could not be completed."
            assert str(tmp_path) not in str(meta)
            assert zone_files(settings, "approved") == []
            assert zone_files(settings, "temporary") == []

    def test_required_proxy_outage_blocks_download(self, tls_server, tmp_path, monkeypatch):
        monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.certfile))
        dead = closed_port()
        settings = base_settings(
            tmp_path,
            tls_server.server_address[1],
            require_egress_proxy=True,
            egress_proxy_url=f"http://127.0.0.1:{dead}",
            egress_proxy_health_url=f"http://127.0.0.1:{dead}/health",
            analysis_provider="disabled",
        )
        client = make_client(settings)
        try:
            before = dict(tls_server.state["requests"])
            resp = post_download(client, tls_url(tls_server, "/report.pdf"))
            final = wait_for_state(
                client, resp.json()["download_id"], {"REJECTED", "FAILED"}
            )
            assert final["state"] != "APPROVED"
            assert tls_server.state["requests"] == before
            assert zone_files(settings, "temporary") == []
        finally:
            client.__exit__(None, None, None)

    def test_provider_outage_is_retryable_and_identifiable(
        self, tls_server, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.certfile))
        dead = closed_port()
        provider_dir = tmp_path / "provider-app"
        provider_dir.mkdir()
        # Rebuild the app against a closed real-HTTP provider endpoint.
        provider_settings = base_settings(
            provider_dir,
            tls_server.server_address[1],
            analysis_provider="http",
            analysis_endpoint_url=f"http://127.0.0.1:{dead}/v1/analyze",
            analysis_api_token="provider-token",
            analysis_allow_insecure_local=True,
            analysis_allow_private_endpoints=True,
            analysis_use_egress_proxy=False,
        )
        client = TestClient(
            create_app(provider_settings), raise_server_exceptions=False
        )
        scanner = FakeScanner()
        client.__enter__()
        client.app.state.orchestrator._scanner = scanner  # type: ignore[attr-defined]
        client.app.state.scanner = scanner
        try:
            resp = post_download(client, tls_url(tls_server, "/report.pdf"))
            download_id = resp.json()["download_id"]
            wait_for_state(client, download_id, {"APPROVED"})
            client.post(f"/online/downloads/{download_id}/analysis", headers=headers())
            failed = wait_for_analysis(client, download_id, {"FAILED"}, timeout=20)
            assert failed["retryable"] is True
            assert failed["error_code"] in {
                "ANALYSIS_UNAVAILABLE",
                "ANALYSIS_PROVIDER_ERROR",
            }
            retry = client.post(
                f"/online/downloads/{download_id}/analysis/retry", headers=headers()
            )
            assert retry.status_code == 202
        finally:
            client.__exit__(None, None, None)


# ── DEMO 9 — resource exhaustion ────────────────────────────────────────────

class TestDemo9ResourceExhaustion:
    def test_slow_origin_times_out_without_artifacts(self, app_client, tls_server):
        app_client.settings  # noqa: B018 - readability
        app_client.app.state.orchestrator._streamer._total_timeout = 0.5
        resp = post_download(app_client, tls_url(tls_server, "/slow.pdf"))
        final = wait_for_state(app_client, resp.json()["download_id"], {"FAILED"})
        assert "deadline" in (final["failure_reason"] or "").lower()
        assert zone_files(app_client.settings, "temporary") == []

    def test_pdf_beyond_page_limit_fails_non_retryably(self, tls_server, tmp_path, monkeypatch):
        monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.certfile))
        pages = make_pdf(("one", "two", "three"))
        tls_server.routes["/report.pdf"] = lambda h: h.write_raw(
            "200 OK",
            [("Content-Type", "application/pdf"), ("Content-Length", str(len(pages)))],
            pages,
            close=True,
        )
        settings = base_settings(
            tmp_path,
            tls_server.server_address[1],
            analysis_max_pages=1,
            analysis_provider="local_mock",
        )
        client = make_client(settings)
        try:
            resp = post_download(client, tls_url(tls_server, "/report.pdf"))
            download_id = resp.json()["download_id"]
            wait_for_state(client, download_id, {"APPROVED"})
            client.post(f"/online/downloads/{download_id}/analysis", headers=headers())
            failed = wait_for_analysis(client, download_id, {"FAILED"})
            assert failed["error_code"] == "DOCUMENT_TOO_MANY_PAGES"
            assert failed["retryable"] is False
        finally:
            client.__exit__(None, None, None)


# ── DEMO 10 — configuration and deployment safety ───────────────────────────

class TestDemo10Configuration:
    def test_permissive_analysis_provider_is_flagged_not_ready(self, app_client):
        ready = app_client.get("/health/ready")
        assert ready.status_code == 503
        body = ready.json()
        assert "local_mock" in " ".join(body["issues"])
        # Liveness is intentionally unaffected.
        assert app_client.get("/health/live").json() == {"status": "ok"}

    def test_production_with_mock_provider_cannot_be_constructed(self, tmp_path):
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="ANALYSIS_PROVIDER"):
            Settings(
                _env_file=None,
                environment="production",
                api_auth_token="token",
                database_url=f"sqlite+aiosqlite:///{tmp_path / 'p.db'}",
                storage_root=str(tmp_path / "storage"),
                egress_proxy_url="http://proxy.internal:3128",
                egress_proxy_health_url="http://proxy.internal:3128/health",
                require_egress_proxy=True,
                allowed_domains="files.example.com",
                default_domain_policy="deny",
                allow_private_networks=False,
                dns_preflight_enabled=True,
                analysis_provider="local_mock",
            )
