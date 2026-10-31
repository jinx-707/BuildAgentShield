"""Regression tests for the attack simulation lab target initialization.

These tests do not require a database or Docker. They verify that the attack
simulation lab reuses the dedicated Docker attack target services through
their internal Compose DNS names instead of spawning a local loopback mock
HTTP server.

The previous implementation bound a ThreadingHTTPServer to 127.0.0.1 inside
the API container ("mock target server failed to start"), was unreachable
from the browser worker / egress proxy (separate containers), and duplicated
the dedicated attack targets that already run as healthy Docker services.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.services.attack_simulation import (
    AttackSimulationLab,
    default_attack_targets,
)


# ---------------------------------------------------------------------------
# Successful target initialization
# ---------------------------------------------------------------------------


def test_default_attack_targets_returns_compose_dns_urls():
    """The lab initializes from the dedicated Compose DNS target URLs."""
    targets = default_attack_targets()
    assert targets == {
        "prompt-injection": "http://prompt-injection-target:8081",
        "phishing": "http://phishing-target:8082",
        "ssrf": "http://ssrf-target:8083",
        "mock-metadata": "http://mock-metadata:8088",
        "malicious-download": "http://malicious-download-target:8084",
        "resource-exhaustion": "http://resource-exhaustion-target:8085",
        "dns-rebinding": "http://dns-rebinding-target:8086",
        "data-exfiltration": "http://data-exfiltration-sink:8087",
    }
    assert all(url.startswith("http://") for url in targets.values())


def test_attack_simulation_lab_uses_configured_targets():
    """AttackSimulationLab exposes the configured target URLs by scenario key."""
    targets = {
        "ssrf": "http://ssrf-target:8083",
        "mock-metadata": "http://mock-metadata:8088",
        "prompt-injection": "http://prompt-injection-target:8081",
    }
    lab = AttackSimulationLab(base_url="http://api:8000", targets=targets)
    assert lab._target_url("ssrf") == "http://ssrf-target:8083"
    assert lab._target_url("mock-metadata") == "http://mock-metadata:8088"
    assert lab._target_url("prompt-injection") == "http://prompt-injection-target:8081"


def test_attack_simulation_lab_defaults_to_compose_dns_targets():
    """With no targets supplied, the lab falls back to the Compose DNS defaults."""
    lab = AttackSimulationLab(base_url="http://api:8000")
    assert lab._target_url("ssrf") == "http://ssrf-target:8083"
    assert lab._target_url("phishing") == "http://phishing-target:8082"


def test_attack_simulation_lab_unknown_target_raises():
    """An unknown scenario key raises KeyError rather than silently misrouting."""
    lab = AttackSimulationLab(
        base_url="http://api:8000", targets={"ssrf": "http://ssrf-target:8083"}
    )
    with pytest.raises(KeyError):
        lab._target_url("nonexistent-scenario")


# ---------------------------------------------------------------------------
# No local mock server is started (startup timeout / port conflict eliminated)
# ---------------------------------------------------------------------------


def test_attack_simulation_lab_starts_no_local_server():
    """The lab must not bind a loopback socket or start a background thread.

    This eliminates the "mock target server failed to start" failure mode
    (no 15-second startup wait) and the port-conflict failure mode (no port
    is bound at all).
    """
    lab = AttackSimulationLab(
        base_url="http://api:8000", targets={"ssrf": "http://ssrf-target:8083"}
    )
    # No server socket, no background thread, no deferred-start flag.
    assert not hasattr(lab, "_server") or lab._server is None
    assert not hasattr(lab, "_thread")
    assert not hasattr(lab, "_targets_started")
    # targets is a plain dict of URLs, not a server exposing .url.
    assert isinstance(lab._targets, dict)
    assert not hasattr(lab._targets, "url")


# ---------------------------------------------------------------------------
# Target unavailable / failed simulation cleanup
# ---------------------------------------------------------------------------


def test_post_enforcement_closes_client_on_target_unavailable(monkeypatch):
    """_post_enforcement releases its httpx.Client even when the target / API
    is unreachable (failed simulation cleanup, no leaked client)."""

    closed = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self._closed = False

        def post(self, *args, **kwargs):
            raise RuntimeError("connection refused: target unavailable")

        def close(self):
            closed.append(True)
            self._closed = True

    import app.services.attack_simulation as asim

    monkeypatch.setattr(asim.httpx, "Client", FakeClient)

    lab = AttackSimulationLab(
        base_url="http://127.0.0.1:1", targets={"ssrf": "http://ssrf-target:8083"}
    )
    with pytest.raises(RuntimeError, match="connection refused"):
        lab._post_enforcement(
            "/v1/ai-agent/action",
            {"action": "navigate", "target": "http://ssrf-target:8083/metadata", "session_id": "s1"},
        )
    assert closed == [True], "httpx.Client.close() must be called even on failure"


def test_attack_simulation_lab_close_releases_client():
    """lab.close() releases the held HTTP client (cleanup)."""
    lab = AttackSimulationLab(
        base_url="http://api:8000", targets={"ssrf": "http://ssrf-target:8083"}
    )
    lab.close()
    assert lab._closed is True


# ---------------------------------------------------------------------------
# Route-level execution (organization isolation, evidence, audit)
# ---------------------------------------------------------------------------


def _org_token(org_id: str) -> str:
    from app.enterprise.auth import create_access_token

    return create_access_token(subject="user-1", organization_id=org_id, roles=["owner"])


@pytest.fixture
def lab_targets():
    return {
        "ssrf": "http://ssrf-target:8083",
        "prompt-injection": "http://prompt-injection-target:8081",
    }


def test_run_uses_dedicated_targets_not_local_mock(lab_targets, monkeypatch):
    """The route passes dedicated Docker target URLs (not a local mock) to the lab."""
    captured = {}

    def fake_run_all(self, *, organization_id, agent_id, session_id):
        captured["targets"] = dict(self._targets)
        captured["organization_id"] = organization_id
        return [
            {
                "scenario_id": "ssrf-metadata",
                "scenario_name": "SSRF against mock metadata endpoint",
                "enforcement_result": "PASS",
                "policy_decision": "deny",
                "evidence": {"target": "http://ssrf-target:8083", "response_status": 403},
            }
        ]

    monkeypatch.setattr(
        AttackSimulationLab, "run_all", fake_run_all
    )
    lab = AttackSimulationLab(base_url="http://api:8000", targets=lab_targets)
    lab.run_all(organization_id="org-1", agent_id=None, session_id=None)
    assert captured["targets"] == lab_targets
    assert captured["organization_id"] == "org-1"
    # No loopback / local mock URL is present.
    for url in captured["targets"].values():
        assert "127.0.0.1" not in url and "localhost" not in url


@pytest.mark.skipif(True, reason="placeholder: database-backed tests live in test_cyber_range.py")
def test_placeholder():
    pass
