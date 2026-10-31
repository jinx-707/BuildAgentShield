"""Tests for the integration health-check endpoint (/v1/integrations/health)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def _make_app(**overrides):
    values = {
        "environment": "test",
        "log_level": "WARNING",
        "database_url": "",
        "browser_worker_url": "http://browser-worker.test:8080",
        "browser_worker_timeout_seconds": 1.0,
        "browser_worker_health_timeout_seconds": 1.0,
        "policy_backend": "mock",
        "inspection_backend": "mock",
        "allowed_domains": "example.com",
        "dns_preflight_enabled": False,
        "egress_proxy_url": "",
        "egress_proxy_health_url": "",
        "api_auth_token": "",
    }
    values.update(overrides)
    settings = Settings(_env_file=None, **values)
    app = create_app(settings=settings)
    app.state.settings = settings
    return TestClient(app, raise_server_exceptions=False)


class TestIntegrationsHealthMockBackends:
    """Mock backends must be reported as Mock, never Connected."""

    def test_p1_and_p2_reported_as_mock(self):
        client = _make_app(
            policy_backend="mock",
            inspection_backend="mock",
            egress_proxy_health_url="",
        )
        r = client.get("/v1/integrations/health")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["p1_engine"]["status"] == "Mock"
        assert body["p1_engine"]["backend"] == "mock"
        assert body["p2_adapters"]["status"] == "Mock"
        assert body["p2_adapters"]["backend"] == "mock"
        # Egress proxy health URL not configured -> Not configured
        assert body["p3_adapters"]["egress_proxy"]["status"] == "Not configured"

    def test_scenarios_returned_with_checked_at(self):
        client = _make_app()
        r = client.get("/v1/integrations/health")
        assert r.status_code == 200, r.text
        body = r.json()
        scenario_ids = {s["scenario_id"] for s in body["scenarios"]}
        expected = {
            "prompt-injection",
            "phishing",
            "ssrf",
            "dns-rebinding",
            "malicious-download",
            "resource-exhaustion",
            "data-exfiltration",
        }
        assert expected.issubset(scenario_ids), scenario_ids
        for s in body["scenarios"]:
            assert "status" in s
            assert "checked_at" in s
            assert "threat_category" in s


class TestIntegrationsHealthRealBackends:
    """Real backends require a successful functional capability check."""

    @patch("app.api.integrations._http_health")
    def test_p1_connected_when_policy_engine_authorizes(self, mock_http_health):
        mock_http_health.return_value = (True, {"status": "ok", "mode": "enforcing"})

        fake_engine = MagicMock()
        fake_engine.name = "real-policy"
        fake_decision = MagicMock()
        fake_decision.allowed = True
        fake_engine.authorize = AsyncMock(return_value=fake_decision)

        client = _make_app(
            policy_backend="egress-policy",
            egress_proxy_health_url="http://proxy:9090/health/ready",
        )
        client.app.state.policy_engine = fake_engine

        r = client.get("/v1/integrations/health")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["p1_engine"]["status"] == "Connected"
        assert body["p1_engine"]["backend"] == "egress-policy"
        fake_engine.authorize.assert_called_once()

    @patch("app.api.integrations._http_health")
    def test_p1_degraded_when_capability_check_fails(self, mock_http_health):
        mock_http_health.return_value = (True, {"status": "ok", "mode": "enforcing"})

        fake_engine = MagicMock()
        fake_engine.name = "real-policy"
        fake_engine.authorize = MagicMock(side_effect=RuntimeError("boom"))

        client = _make_app(
            policy_backend="egress-policy",
            egress_proxy_health_url="http://proxy:9090/health/ready",
        )
        client.app.state.policy_engine = fake_engine

        r = client.get("/v1/integrations/health")
        assert r.status_code == 200, r.text
        assert r.json()["p1_engine"]["status"] == "Degraded"

    @patch("app.api.integrations._http_health")
    def test_p3_connected_when_both_reachable(self, mock_http_health):
        # egress proxy healthy, browser worker healthy
        mock_http_health.side_effect = [
            (True, {"status": "ok", "mode": "enforcing"}),  # egress
            (True, {"status": "ok"}),  # browser worker
        ]

        client = _make_app(
            egress_proxy_health_url="http://proxy:9090/health/ready",
            browser_worker_url="http://worker:8080",
        )

        r = client.get("/v1/integrations/health")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["p3_adapters"]["egress_proxy"]["status"] == "Connected"
        assert body["p3_adapters"]["browser_worker"]["status"] == "Connected"

    @patch("app.api.integrations._http_health")
    def test_p3_disconnected_when_egress_unreachable(self, mock_http_health):
        mock_http_health.return_value = (False, "unreachable: connection refused")

        client = _make_app(
            egress_proxy_health_url="http://proxy:9090/health/ready",
        )
        r = client.get("/v1/integrations/health")
        assert r.status_code == 200, r.text
        assert r.json()["p3_adapters"]["egress_proxy"]["status"] == "Disconnected"
