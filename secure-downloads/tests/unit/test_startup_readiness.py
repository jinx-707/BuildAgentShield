"""
F7 — liveness, dependency readiness and security-configuration readiness.

These three signals must stay separate:

* /health/live answers even when the configuration is unsafe or every
  dependency is down — it must never trigger restarts of a healthy process.
* /health/ready is the security + dependency gate: it must not report ready
  for a service that cannot safely accept a download.
* startup itself fails closed for a production-like environment whose
  configuration is unsafe.

The app runs with a real file-backed SQLite database (Alembic migrations
included) and real storage zones.  Only out-of-process dependencies (ClamAV,
the egress proxy health endpoint) are substituted — with a real socket server
where the answer matters.
"""
from __future__ import annotations

import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import app as app_module
from api.app import create_app
from config.settings import Settings
from models.database import get_async_engine
from services.scanner import ClamAvScanner
from tests.integration.raw_http import closed_port, serve_raw, url_for

SECRET_TOKEN = "sup3r-secret-api-token"
PROXY_PASSWORD = "pr0xy-basic-auth-password"


# ── Settings / app helpers ────────────────────────────────────────────────────

def build_settings(tmp_path, **overrides) -> Settings:
    """A complete, explicitly non-production configuration for app tests."""
    base = {
        "environment": "test",
        "log_level": "WARNING",
        "api_auth_token": SECRET_TOKEN,
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'readiness.db'}",
        "storage_root": str(tmp_path / "storage"),
        "egress_proxy_url": "",
        "egress_proxy_health_url": "",
        "require_egress_proxy": False,
        "proxy_auth_token": "",
        "allowed_domains": "files.example.com",
        "blocked_domains": "",
        "default_domain_policy": "deny",
        "allowed_ports": "443",
        "allow_private_networks": False,
        "dns_preflight_enabled": True,
        "clamav_host": "127.0.0.1",
        "clamav_port": closed_port(),
        "clamav_fail_closed": True,
        "rate_limit_enabled": False,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def client_for(tmp_path, **overrides) -> TestClient:
    app = create_app(build_settings(tmp_path, **overrides))
    return TestClient(app, raise_server_exceptions=False)


async def _scanner_available(self) -> bool:  # pragma: no cover - patched stub
    return True


@pytest.fixture
def scanner_up(monkeypatch):
    """Stand in for a reachable ClamAV daemon."""
    monkeypatch.setattr(ClamAvScanner, "is_available", _scanner_available)


# ── Liveness ──────────────────────────────────────────────────────────────────

def test_live_answers_even_when_configuration_is_unsafe(tmp_path):
    """
    Liveness is process-level only.

    A configuration that makes /health/ready return 503 must not make the
    orchestrator look dead to a supervisor.
    """
    with client_for(
        tmp_path,
        api_auth_token="",
        dns_preflight_enabled=False,
        require_egress_proxy=True,
        egress_proxy_url="",
    ) as client:
        resp = client.get("/health/live")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_live_is_exempt_from_api_authentication(tmp_path):
    with client_for(tmp_path) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code in {200, 503}
        # Non-health endpoints still require the token.
        assert client.get("/online/downloads").status_code == 401


# ── Security-configuration readiness ──────────────────────────────────────────

def test_ready_is_503_and_names_unsafe_configuration(tmp_path, scanner_up):
    """The gate that matters: unsafe config is never reported as ready."""
    with client_for(
        tmp_path,
        api_auth_token="",
        dns_preflight_enabled=False,
        require_egress_proxy=True,
        egress_proxy_url="",
    ) as client:
        resp = client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["security_configuration"] == "not_ready"
    assert body["checks"]["egress_proxy"] == "not_configured"
    joined = " ".join(body["issues"])
    assert "API_AUTH_TOKEN" in joined
    assert "REQUIRE_EGRESS_PROXY" in joined
    assert "DNS_PREFLIGHT_ENABLED" in joined


def test_ready_is_200_for_a_clean_configuration(tmp_path, scanner_up):
    with client_for(tmp_path) as client:
        resp = client.get("/health/ready")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["issues"] == []
    assert body["checks"] == {
        "security_configuration": "ok",
        "egress_proxy": "not_required",
        "database": "ok",
        "storage": "ok",
        "scanner": "available",
    }


def test_ready_flags_private_networks_allowed(tmp_path, scanner_up):
    """ALLOW_PRIVATE_NETWORKS is unsafe in any environment: never 'ready'."""
    with client_for(tmp_path, allow_private_networks=True) as client:
        resp = client.get("/health/ready")

    assert resp.status_code == 503
    assert "ALLOW_PRIVATE_NETWORKS" in " ".join(resp.json()["issues"])


# ── Proxy attestation as a readiness gate ─────────────────────────────────────

def test_ready_is_503_when_proxy_reports_permissive_mode(tmp_path):
    """A reachable proxy that says it is not enforcing must block readiness."""
    srv, shutdown = serve_raw(
        {
            "/health": lambda h: h.write_raw(
                "200 OK",
                [("Content-Type", "application/json")],
                b'{"status": "ok", "mode": "permissive"}',
            )
        }
    )
    try:
        health_url = url_for(srv, "/health")
        with client_for(
            tmp_path,
            require_egress_proxy=True,
            egress_proxy_url=health_url.rsplit("/", 1)[0],
            egress_proxy_health_url=health_url,
        ) as client:
            resp = client.get("/health/ready")
        assert resp.status_code == 503
        body = resp.json()
        assert body["checks"]["egress_proxy"] == "not_enforcing"
        assert "EGRESS_PROXY_UNAVAILABLE" in " ".join(body["issues"])
        # The fixed-text issue must not echo the endpoint it probed.
        assert health_url not in resp.text
    finally:
        shutdown()


def test_ready_is_503_when_proxy_health_is_unreachable(tmp_path):
    """A dependency outage is visible in the readiness payload."""
    dead_port = closed_port()
    with client_for(
        tmp_path,
        require_egress_proxy=True,
        egress_proxy_url=f"http://127.0.0.1:{dead_port}",
        egress_proxy_health_url=f"http://127.0.0.1:{dead_port}/health",
    ) as client:
        resp = client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["checks"]["egress_proxy"] == "not_enforcing"
    assert body["checks"]["database"] == "ok"


def test_ready_is_503_when_proxy_mode_is_unattestable(tmp_path, scanner_up):
    """A proxy without a health endpoint cannot be trusted as enforcing."""
    with client_for(
        tmp_path,
        require_egress_proxy=True,
        egress_proxy_url="http://127.0.0.1:3128",
        egress_proxy_health_url="",
    ) as client:
        resp = client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["checks"]["egress_proxy"] == "unattestable"
    assert "EGRESS_PROXY_HEALTH_URL" in " ".join(body["issues"])


def test_ready_is_503_when_scanner_is_unavailable(tmp_path):
    """
    Fail-closed scanning means an unreachable ClamAV can approve nothing.

    clamav_port points at a closed port, so the real availability probe fails.
    """
    with client_for(tmp_path) as client:
        resp = client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["checks"]["scanner"] == "unavailable"
    assert "ClamAV" in " ".join(body["issues"])


# ── Dependency probes ─────────────────────────────────────────────────────────

def test_ready_is_503_when_database_is_unreachable(tmp_path, scanner_up):
    with client_for(tmp_path) as client:
        # Replace the working engine with one aimed at a path SQLite cannot open.
        client.app.state.engine = get_async_engine(
            f"sqlite+aiosqlite:///{tmp_path / 'missing-dir' / 'gone.db'}"
        )
        resp = client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["checks"]["database"] == "unreachable"
    assert "Database is unreachable." in body["issues"]


def test_ready_is_503_when_storage_is_not_writable(tmp_path, scanner_up):
    storage_root = tmp_path / "storage"
    with client_for(tmp_path) as client:
        temp_zone = storage_root / "temporary"
        temp_zone.chmod(stat.S_IRUSR | stat.S_IXUSR)  # r-x: no writes
        try:
            resp = client.get("/health/ready")
        finally:
            temp_zone.chmod(stat.S_IRWXU)

    assert resp.status_code == 503
    body = resp.json()
    assert body["checks"]["storage"] == "error"
    assert "Storage temporary zone is not writable." in body["issues"]


# ── No secret leakage ─────────────────────────────────────────────────────────

def test_ready_payload_never_contains_secrets(tmp_path):
    srv, shutdown = serve_raw(
        {
            "/health": lambda h: h.write_raw(
                "500 Internal Server Error",
                [("Content-Length", "0")],
                b"",
            )
        }
    )
    try:
        proxy_url = (
            f"http://agentshield:{PROXY_PASSWORD}@127.0.0.1:{srv.server_address[1]}"
        )
        with client_for(
            tmp_path,
            api_auth_token="",  # unsafe config -> 503 with issue text
            require_egress_proxy=True,
            egress_proxy_url=proxy_url,
            egress_proxy_health_url=url_for(srv, "/health"),
        ) as client:
            resp = client.get("/health/ready")

        assert resp.status_code == 503
        text = resp.text
        assert PROXY_PASSWORD not in text
        assert SECRET_TOKEN not in text
        assert "Proxy-Authorization" not in text
        # Issues are configuration names and conditions only.
        assert "API_AUTH_TOKEN" in " ".join(resp.json()["issues"])
    finally:
        shutdown()


def test_live_and_ready_are_distinct_endpoints(tmp_path, scanner_up):
    with client_for(tmp_path) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")

    assert live.json() == {"status": "ok"}
    assert ready.json()["status"] == "ready"
    assert "checks" not in live.json()


# ── Startup fails closed ──────────────────────────────────────────────────────

def production_settings(tmp_path, **overrides) -> Settings:
    """A configuration that satisfies every production fail-closed rule."""
    base = {
        "environment": "production",
        "log_level": "WARNING",
        "api_auth_token": SECRET_TOKEN,
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'prod.db'}",
        "storage_root": str(tmp_path / "storage"),
        "egress_proxy_url": "http://proxy.internal:3128",
        "egress_proxy_health_url": "http://proxy.internal:3128/health",
        "require_egress_proxy": True,
        "allowed_domains": "files.example.com",
        "default_domain_policy": "deny",
        "allow_private_networks": False,
        "dns_preflight_enabled": True,
        "rate_limit_enabled": False,
        # Production requires the real provider integration.
        "analysis_provider": "http",
        "analysis_endpoint_url": "https://analysis.example.com/v1/analyze",
        "analysis_api_token": "analysis-secret-token",
        "analysis_use_egress_proxy": True,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def test_production_settings_refuse_unsafe_configuration(tmp_path):
    """Configuration problems are rejected before the app is even built."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="API_AUTH_TOKEN"):
        production_settings(tmp_path, api_auth_token="")
    with pytest.raises(ValidationError, match="EGRESS_PROXY_HEALTH_URL"):
        production_settings(tmp_path, egress_proxy_health_url="")
    with pytest.raises(ValidationError, match="DNS_PREFLIGHT_ENABLED"):
        production_settings(tmp_path, dns_preflight_enabled=False)
    with pytest.raises(ValidationError, match="ALLOW_PRIVATE_NETWORKS"):
        production_settings(tmp_path, allow_private_networks=True)
    with pytest.raises(ValidationError, match="REQUIRE_EGRESS_PROXY"):
        production_settings(tmp_path, require_egress_proxy=False)
    with pytest.raises(ValidationError, match="ALLOWED_DOMAINS"):
        production_settings(tmp_path, allowed_domains="")
    with pytest.raises(ValidationError, match="EGRESS_PROXY_URL"):
        production_settings(tmp_path, egress_proxy_url="")


def test_startup_refuses_to_run_with_drifted_production_config(
    tmp_path, monkeypatch
):
    """
    The lifespan safety net.

    Settings validation is the primary gate; this is the backstop for any
    config that reaches startup with a security issue while production-like.
    """

    def pretend_there_is_an_issue(settings):
        return ["API_AUTH_TOKEN is not set: all non-health endpoints are unauthenticated."]

    monkeypatch.setattr(app_module, "security_issues", pretend_there_is_an_issue)
    app = create_app(production_settings(tmp_path))

    with pytest.raises(RuntimeError, match="Refusing to start with unsafe production"):
        with TestClient(app):
            pass  # pragma: no cover - startup must fail before this runs


def test_startup_logs_issues_but_boots_in_non_production(tmp_path, monkeypatch, caplog):
    """A permissive environment surfaces the same issues without blocking boot."""

    def pretend_there_is_an_issue(settings):
        return ["DNS_PREFLIGHT_ENABLED is false: the pre-connection SSRF check is disabled."]

    monkeypatch.setattr(app_module, "security_issues", pretend_there_is_an_issue)
    app = create_app(build_settings(tmp_path))

    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
        assert client.app.state.security_issues == [
            "DNS_PREFLIGHT_ENABLED is false: the pre-connection SSRF check is disabled."
        ]
        # /health/ready must still refuse to call this ready.
        assert client.get("/health/ready").status_code == 503


def test_startup_fails_when_database_is_unreachable(tmp_path):
    """No record-keeping means no auditable lifecycle: do not start half-alive."""
    app = create_app(
        build_settings(
            tmp_path,
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'no-such-dir' / 'x.db'}",
        )
    )
    with pytest.raises(Exception) as exc_info:
        with TestClient(app):
            pass  # pragma: no cover

    assert exc_info.value.__class__ is not AssertionError


def test_storage_zones_are_created_at_startup(tmp_path):
    with client_for(tmp_path) as client:
        root = Path(client.app.state.settings.storage_root)
        for zone in ("temporary", "quarantine", "approved"):
            assert (root / zone).is_dir()
            # owner-only permissions, as documented in storage/manager.py
            assert (root / zone).stat().st_mode & 0o077 == 0
