"""
End-to-end API tests for document analysis.

A real FastAPI app (lifespan, migrations, worker pool) runs against a
file-backed SQLite database and real storage zones.  The provider is the
explicit local mock; no external service is contacted.
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from config.settings import Settings
from integrations.handoff import MockDocumentAnalysisAdapter
from tests.integration.raw_http import closed_port
from tests.pdf_fixtures import make_pdf

API_TOKEN = "api-token-value"
TENANT = "tenant-x"
PDF_BYTES = make_pdf(("Quarterly report body",))
PDF_SHA = hashlib.sha256(PDF_BYTES).hexdigest()


def make_settings(tmp_path, **overrides) -> Settings:
    base = {
        "environment": "test",
        "log_level": "WARNING",
        "api_auth_token": API_TOKEN,
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        "storage_root": str(tmp_path / "storage"),
        "egress_proxy_url": "",
        "egress_proxy_health_url": "",
        "require_egress_proxy": False,
        "proxy_auth_token": "",
        "allowed_domains": "files.example.com",
        "default_domain_policy": "deny",
        "allowed_ports": "443",
        "allow_private_networks": False,
        "dns_preflight_enabled": True,
        "clamav_host": "127.0.0.1",
        "clamav_port": closed_port(),
        "clamav_fail_closed": True,
        "rate_limit_enabled": False,
        "analysis_provider": "local_mock",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def headers(tenant: str = TENANT) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "X-Tenant-ID": tenant,
    }


def db_path(settings: Settings) -> str:
    return settings.database_url.split("///", 1)[1]


def seed_download(
    settings: Settings,
    *,
    download_id: str = "dl-api-1",
    state: str = "APPROVED",
    tenant_id: str = TENANT,
) -> str:
    """Insert a download row (and its approved file) outside the app."""
    filename = str(uuid.uuid4())
    storage_ref = f"approved/{filename}"
    approved_dir = Path(settings.storage_root) / "approved"
    approved_dir.mkdir(parents=True, exist_ok=True)
    (approved_dir / filename).write_bytes(PDF_BYTES)

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    with sqlite3.connect(db_path(settings), timeout=10) as conn:
        conn.execute(
            """
            INSERT INTO downloads (
                id, tenant_id, agent_id, original_url, state,
                original_filename, detected_mime_type, file_size, file_sha256,
                storage_ref, created_at, updated_at, handoff_completed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                download_id,
                tenant_id,
                "agent-1",
                "https://example.com/report.pdf",
                state,
                "report.pdf",
                "application/pdf",
                len(PDF_BYTES),
                PDF_SHA,
                storage_ref,
                now,
                now,
            ),
        )
        conn.commit()
    return storage_ref


def seed_pending_analysis(
    settings: Settings,
    *,
    download_id: str,
    tenant_id: str = TENANT,
    state: str = "PENDING",
) -> str:
    job_id = str(uuid.uuid4())
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    with sqlite3.connect(db_path(settings), timeout=10) as conn:
        conn.execute(
            """
            INSERT INTO document_analyses (
                id, download_id, tenant_id, state, provider, correlation_id,
                attempts, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'mock', ?, 0, ?, ?)
            """,
            (job_id, download_id, tenant_id, state, str(uuid.uuid4()), now, now),
        )
        conn.commit()
    return job_id


def wait_for_state(
    client: TestClient,
    download_id: str,
    states: set[str],
    *,
    tenant: str = TENANT,
    timeout: float = 8.0,
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


@pytest.fixture
def app_client(tmp_path):
    settings = make_settings(tmp_path)
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.settings = settings  # type: ignore[attr-defined]
        yield client


class TestHappyPath:
    def test_initiate_status_result_and_metadata(self, app_client):
        settings = app_client.settings
        seed_download(settings)

        resp = app_client.post(
            "/online/downloads/dl-api-1/analysis", headers=headers()
        )
        assert resp.status_code == 202
        job = resp.json()
        assert job["download_id"] == "dl-api-1"
        assert job["provider"] == "mock"
        assert job["state"] in {"PENDING", "RUNNING", "COMPLETED"}

        final = wait_for_state(app_client, "dl-api-1", {"COMPLETED"})
        assert final["analysis_id"] == job["analysis_id"]
        assert final["provider_analysis_id"]

        result_resp = app_client.get(
            "/online/downloads/dl-api-1/analysis/result", headers=headers()
        )
        assert result_resp.status_code == 200
        result = result_resp.json()
        assert result["analysis_id"] == job["analysis_id"]
        assert result["provider"] == "mock"
        assert result["document_type"] == "pdf"
        assert result["page_count"] == 1
        assert "Quarterly report body" in result["extracted_text"]
        assert result["sha256"] == PDF_SHA
        assert result["provider_analysis_id"] == final["provider_analysis_id"]
        assert "MOCK_ANALYSIS_PROVIDER" in result["warnings"]
        # The mock supplies no summary/confidence; the service must not invent them.
        assert result["summary"] is None
        assert result["confidence"] is None
        assert result["findings"] == []
        # No storage reference or filesystem path is exposed.
        assert "storage_ref" not in result
        assert "approved/" not in result_resp.text

        metadata = app_client.get(
            "/online/downloads/dl-api-1/metadata", headers=headers()
        )
        assert metadata.status_code == 200
        body = metadata.json()
        assert body["analysis_id"] == job["analysis_id"]
        assert body["analysis_state"] == "COMPLETED"
        assert body["analysis_provider"] == "mock"
        assert body["handoff_completed"] is True
        assert "storage_ref" not in body
        assert str(settings.storage_root) not in metadata.text

        adapter = app_client.app.state.handoff_service._adapter
        assert isinstance(adapter, MockDocumentAnalysisAdapter)
        assert len(adapter.submissions) == 1

    def test_duplicate_initiation_is_idempotent(self, app_client):
        seed_download(app_client.settings)
        first = app_client.post(
            "/online/downloads/dl-api-1/analysis", headers=headers()
        ).json()
        wait_for_state(app_client, "dl-api-1", {"COMPLETED"})

        second = app_client.post(
            "/online/downloads/dl-api-1/analysis", headers=headers()
        )
        assert second.status_code == 202
        assert second.json()["analysis_id"] == first["analysis_id"]

        time.sleep(0.1)
        assert len(app_client.app.state.handoff_service._adapter.submissions) == 1


class TestResultGate:
    def test_result_is_409_before_completion(self, app_client):
        seed_download(app_client.settings)
        job_id = seed_pending_analysis(
            app_client.settings, download_id="dl-api-1"
        )

        status = app_client.get(
            "/online/downloads/dl-api-1/analysis", headers=headers()
        )
        assert status.status_code == 200
        assert status.json()["analysis_id"] == job_id
        assert status.json()["state"] == "PENDING"

        result = app_client.get(
            "/online/downloads/dl-api-1/analysis/result", headers=headers()
        )
        assert result.status_code == 409
        assert result.json()["code"] == "ANALYSIS_NOT_COMPLETED"

    def test_no_job_is_404(self, app_client):
        seed_download(app_client.settings)
        for path in ("analysis", "analysis/result"):
            resp = app_client.get(
                f"/online/downloads/dl-api-1/{path}", headers=headers()
            )
            assert resp.status_code == 404


class TestApprovalBoundary:
    def test_quarantined_download_never_reaches_analysis(self, app_client):
        seed_download(app_client.settings, state="QUARANTINED")

        resp = app_client.post(
            "/online/downloads/dl-api-1/analysis", headers=headers()
        )
        assert resp.status_code == 409
        assert resp.json()["code"] == "INVALID_STATE"

        # No job exists and no result can be read.
        assert (
            app_client.get(
                "/online/downloads/dl-api-1/analysis", headers=headers()
            ).status_code
            == 404
        )
        result = app_client.get(
            "/online/downloads/dl-api-1/analysis/result", headers=headers()
        )
        assert result.status_code == 404
        assert app_client.app.state.handoff_service._adapter.submissions == []

    def test_unapproved_states_are_all_refused(self, app_client):
        seed_download(app_client.settings, download_id="dl-state", state="PENDING")
        resp = app_client.post(
            "/online/downloads/dl-state/analysis", headers=headers()
        )
        assert resp.status_code == 409
        assert resp.json()["code"] == "INVALID_STATE"


class TestRetryFlow:
    @pytest.fixture
    def failing_client(self, tmp_path, monkeypatch):
        import integrations.analysis_adapter as adapter_module

        def build_failing(settings):
            return MockDocumentAnalysisAdapter(should_fail=True)

        monkeypatch.setattr(adapter_module, "build_analysis_adapter", build_failing)
        settings = make_settings(tmp_path)
        app = create_app(settings)
        with TestClient(app, raise_server_exceptions=False) as client:
            client.settings = settings  # type: ignore[attr-defined]
            yield client

    def test_failed_job_can_be_retried(self, failing_client):
        seed_download(failing_client.settings)
        failing_client.post(
            "/online/downloads/dl-api-1/analysis", headers=headers()
        )

        failed = wait_for_state(failing_client, "dl-api-1", {"FAILED"})
        assert failed["retryable"] is True
        assert failed["error_code"] == "ANALYSIS_UNAVAILABLE"

        result = failing_client.get(
            "/online/downloads/dl-api-1/analysis/result", headers=headers()
        )
        assert result.status_code == 409

        retry = failing_client.post(
            "/online/downloads/dl-api-1/analysis/retry", headers=headers()
        )
        assert retry.status_code == 202
        assert retry.json()["state"] in {"PENDING", "RUNNING"}

        attempts = 0
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            body = failing_client.get(
                "/online/downloads/dl-api-1/analysis", headers=headers()
            ).json()
            attempts = body["attempts"]
            if body["state"] == "FAILED" and attempts >= 2:
                break
            time.sleep(0.05)
        assert attempts >= 2


class TestAuthorizationAndTenancy:
    @pytest.fixture
    def seeded_client(self, app_client):
        seed_download(app_client.settings)
        yield app_client

    def test_every_analysis_endpoint_requires_authentication(self, seeded_client):
        paths = [
            ("post", "analysis"),
            ("get", "analysis"),
            ("get", "analysis/result"),
            ("post", "analysis/retry"),
        ]
        for method, suffix in paths:
            resp = getattr(seeded_client, method)(
                f"/online/downloads/dl-api-1/{suffix}",
                headers={"X-Tenant-ID": TENANT},
            )
            assert resp.status_code == 401, suffix

    def test_tenant_header_is_required(self, seeded_client):
        resp = seeded_client.get(
            "/online/downloads/dl-api-1/analysis",
            headers={"Authorization": f"Bearer {API_TOKEN}"},
        )
        assert resp.status_code == 422

    def test_cross_tenant_access_is_not_found(self, seeded_client):
        seeded_client.post(
            "/online/downloads/dl-api-1/analysis", headers=headers()
        )
        other = headers("tenant-y")

        status = seeded_client.get(
            "/online/downloads/dl-api-1/analysis", headers=other
        )
        assert status.status_code == 404
        result = seeded_client.get(
            "/online/downloads/dl-api-1/analysis/result", headers=other
        )
        assert result.status_code == 404
        metadata = seeded_client.get(
            "/online/downloads/dl-api-1/metadata", headers=other
        )
        assert metadata.status_code == 404
        retry = seeded_client.post(
            "/online/downloads/dl-api-1/analysis/retry", headers=other
        )
        assert retry.status_code == 404

    def test_cross_tenant_initiation_is_not_found(self, seeded_client):
        resp = seeded_client.post(
            "/online/downloads/dl-api-1/analysis", headers=headers("tenant-y")
        )
        assert resp.status_code == 404


class TestDisabledAnalysis:
    def test_disabled_provider_returns_409(self, tmp_path):
        settings = make_settings(tmp_path, analysis_provider="disabled")
        app = create_app(settings)
        with TestClient(app, raise_server_exceptions=False) as client:
            seed_download(settings)
            resp = client.post(
                "/online/downloads/dl-api-1/analysis", headers=headers()
            )
            assert resp.status_code == 409
            assert resp.json()["code"] == "ANALYSIS_DISABLED"
