"""
Authorization and tenant-isolation matrix for every public download endpoint.

The API uses one bearer credential for all callers and trusts the X-Tenant-ID
header to select a tenant pseudonym.  These tests therefore verify the
enforcement that *does* exist: authentication is required, a tenant header is
required, and every resource lookup is scoped by (tenant_id, download_id), so a
caller cannot observe another tenant's download even with a correct or guessed
download id.  They do not — and cannot — prove that two holders of the shared
token are isolated identities; see the README limitation.

Requests are made against a real app with a file-backed database and seeded
rows, not against service mocks.
"""
from __future__ import annotations

import hashlib
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from config.settings import Settings
from tests.integration.raw_http import closed_port
from tests.pdf_fixtures import make_pdf

API_TOKEN = "matrix-api-token"
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"

PDF_BYTES = make_pdf(("Tenant matrix body",))
PDF_SHA = hashlib.sha256(PDF_BYTES).hexdigest()

pytestmark = pytest.mark.integration

# Every route that takes a {download_id}, plus the collection POST.
_DOWNLOAD_ID_ROUTES = [
    ("get", "status"),
    ("get", "metadata"),
    ("post", "scan"),
    ("post", "analysis"),
    ("get", "analysis"),
    ("get", "analysis/result"),
    ("post", "analysis/retry"),
]


def make_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        log_level="CRITICAL",
        api_auth_token=API_TOKEN,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'matrix.db'}",
        storage_root=str(tmp_path / "storage"),
        egress_proxy_url="",
        require_egress_proxy=False,
        allowed_domains="files.example.com",
        default_domain_policy="deny",
        allowed_ports="443",
        allow_private_networks=False,
        dns_preflight_enabled=False,
        clamav_host="127.0.0.1",
        clamav_port=closed_port(),
        rate_limit_enabled=False,
        analysis_provider="local_mock",
        analysis_max_attempts=2,
        analysis_retry_base_delay_seconds=0.01,
    )


def auth_headers(tenant: str = TENANT_A) -> dict[str, str]:
    return {"Authorization": f"Bearer {API_TOKEN}", "X-Tenant-ID": tenant}


def db_path(settings: Settings) -> str:
    return settings.database_url.split("///", 1)[1]


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def seed_download(
    settings: Settings,
    *,
    download_id: str,
    tenant_id: str = TENANT_A,
    state: str = "APPROVED",
    with_file: bool = True,
) -> str | None:
    storage_ref = None
    if with_file:
        filename = str(uuid.uuid4())
        storage_ref = f"approved/{filename}"
        directory = Path(settings.storage_root) / "approved"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / filename).write_bytes(PDF_BYTES)

    now = _now()
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
                "https://files.example.com/report.pdf",
                state,
                "report.pdf" if with_file else None,
                "application/pdf" if with_file else None,
                len(PDF_BYTES) if with_file else None,
                PDF_SHA if with_file else None,
                storage_ref,
                now,
                now,
            ),
        )
        conn.commit()
    return storage_ref


def seed_failed_analysis(
    settings: Settings, *, download_id: str, tenant_id: str = TENANT_A
) -> str:
    job_id = str(uuid.uuid4())
    now = _now()
    with sqlite3.connect(db_path(settings), timeout=10) as conn:
        conn.execute(
            """
            INSERT INTO document_analyses (
                id, download_id, tenant_id, state, provider, correlation_id,
                attempts, error_code, retryable, created_at, updated_at
            ) VALUES (?, ?, ?, 'FAILED', 'mock', ?, 1, 'ANALYSIS_UNAVAILABLE', 1, ?, ?)
            """,
            (job_id, download_id, tenant_id, str(uuid.uuid4()), now, now),
        )
        conn.commit()
    return job_id


@pytest.fixture
def client(tmp_path):
    settings = make_settings(tmp_path)
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        test_client.settings = settings  # type: ignore[attr-defined]
        yield test_client


class TestAuthenticationRequired:
    def test_collection_post_requires_token(self, client):
        resp = client.post(
            "/online/downloads",
            headers={"X-Tenant-ID": TENANT_A},
            json={"url": "https://files.example.com/report.pdf"},
        )
        assert resp.status_code == 401
        assert resp.json()["code"] == "API_AUTH_REQUIRED"
        assert "WWW-Authenticate" in resp.headers

    def test_every_download_endpoint_requires_token(self, client):
        seed_download(client.settings, download_id="dl-a")
        for method, suffix in _DOWNLOAD_ID_ROUTES:
            resp = getattr(client, method)(
                f"/online/downloads/dl-a/{suffix}",
                headers={"X-Tenant-ID": TENANT_A},
            )
            assert resp.status_code == 401, suffix
            assert resp.json()["code"] == "API_AUTH_REQUIRED", suffix

    def test_wrong_token_is_rejected_on_every_endpoint(self, client):
        seed_download(client.settings, download_id="dl-a")
        bad = {
            "Authorization": "Bearer wrong-token",
            "X-Tenant-ID": TENANT_A,
        }
        for method, suffix in _DOWNLOAD_ID_ROUTES:
            resp = getattr(client, method)(
                f"/online/downloads/dl-a/{suffix}", headers=bad
            )
            assert resp.status_code == 401, suffix
            assert resp.json()["code"] == "API_AUTH_FAILED", suffix

    def test_tenant_header_is_required_everywhere(self, client):
        seed_download(client.settings, download_id="dl-a")
        only_token = {"Authorization": f"Bearer {API_TOKEN}"}
        for method, suffix in _DOWNLOAD_ID_ROUTES:
            resp = getattr(client, method)(
                f"/online/downloads/dl-a/{suffix}", headers=only_token
            )
            assert resp.status_code == 422, suffix

        resp = client.post(
            "/online/downloads",
            headers=only_token,
            json={"url": "https://files.example.com/report.pdf"},
        )
        assert resp.status_code == 422

    def test_health_endpoints_do_not_require_a_token(self, client):
        assert client.get("/health/live").status_code == 200


class TestTenantScoping:
    @pytest.fixture
    def seeded(self, client):
        seed_download(client.settings, download_id="dl-a", tenant_id=TENANT_A)
        seed_failed_analysis(
            client.settings, download_id="dl-a", tenant_id=TENANT_A
        )
        seed_download(client.settings, download_id="dl-b", tenant_id=TENANT_B)
        seed_failed_analysis(
            client.settings, download_id="dl-b", tenant_id=TENANT_B
        )
        return client

    def test_owner_can_read_own_resources(self, seeded):
        for method, suffix in _DOWNLOAD_ID_ROUTES:
            resp = getattr(seeded, method)(
                f"/online/downloads/dl-a/{suffix}", headers=auth_headers(TENANT_A)
            )
            # scan/analysis paths legitimately return state errors, but never
            # 401/404 for the owner.
            assert resp.status_code not in {401, 404}, (suffix, resp.text)

    def test_other_tenant_gets_not_found_on_every_resource(self, seeded):
        for method, suffix in _DOWNLOAD_ID_ROUTES:
            resp = getattr(seeded, method)(
                f"/online/downloads/dl-a/{suffix}", headers=auth_headers(TENANT_B)
            )
            assert resp.status_code == 404, (suffix, resp.text)
            assert resp.json()["code"] == "NOT_FOUND", suffix
            lowered = resp.text.lower()
            assert "storage_ref" not in lowered
            assert str(seeded.settings.storage_root).lower() not in lowered

    def test_other_tenant_cannot_substitute_its_own_id(self, seeded):
        # Tenant B's own id is valid, but it must not resolve tenant A's row
        # when the request path names tenant A's download.
        resp = seeded.get(
            "/online/downloads/dl-a/status", headers=auth_headers(TENANT_B)
        )
        assert resp.status_code == 404

    def test_tenant_lookup_does_not_expose_foreign_metadata(self, seeded):
        resp = seeded.get(
            "/online/downloads/dl-a/metadata", headers=auth_headers(TENANT_B)
        )
        assert resp.status_code == 404
        body = resp.json()
        assert "tenant-a" not in resp.text
        assert PDF_SHA not in resp.text
        assert "report.pdf" not in body.get("message", "")

    def test_unknown_download_id_is_not_found(self, seeded):
        unknown = str(uuid.uuid4())
        for method, suffix in _DOWNLOAD_ID_ROUTES:
            resp = getattr(seeded, method)(
                f"/online/downloads/{unknown}/{suffix}",
                headers=auth_headers(TENANT_A),
            )
            assert resp.status_code == 404, suffix

    def test_guessed_id_is_not_authorization(self, seeded):
        # The download id alone grants nothing without the matching tenant.
        unguessable = "dl-a"  # deliberately known to the attacker
        resp = seeded.get(
            f"/online/downloads/{unguessable}/status", headers=auth_headers(TENANT_B)
        )
        assert resp.status_code == 404

    def test_metadata_is_scoped_and_path_free(self, seeded):
        resp = seeded.get(
            "/online/downloads/dl-a/metadata", headers=auth_headers(TENANT_A)
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_id"] == TENANT_A
        assert body["download_id"] == "dl-a"
        assert body["file_sha256"] == PDF_SHA
        assert "storage_ref" not in body
        assert str(seeded.settings.storage_root) not in resp.text

    def test_analysis_retry_cross_tenant_is_not_found(self, seeded):
        # Tenant A's failed job is retryable for A, not for B.
        resp = seeded.post(
            "/online/downloads/dl-a/analysis/retry", headers=auth_headers(TENANT_B)
        )
        assert resp.status_code == 404

    def test_scan_cross_tenant_does_not_trigger(self, seeded):
        seed_download(
            seeded.settings,
            download_id="dl-downloaded",
            tenant_id=TENANT_A,
            state="DOWNLOADED",
            with_file=False,
        )
        resp = seeded.post(
            "/online/downloads/dl-downloaded/scan", headers=auth_headers(TENANT_B)
        )
        assert resp.status_code == 404
        owner = seeded.get(
            "/online/downloads/dl-downloaded/status", headers=auth_headers(TENANT_A)
        )
        assert owner.json()["state"] == "DOWNLOADED"
