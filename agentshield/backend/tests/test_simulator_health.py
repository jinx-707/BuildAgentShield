from __future__ import annotations

from tests.conftest import admin_headers


def test_health_readiness_and_metrics_are_public(client):
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    ready = client.get("/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] in {"ok", "degraded"}
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "agentshield_gateway_decisions_total" in metrics.text


def test_tools_and_policies_are_listed(client):
    headers = admin_headers(client)
    tools = client.get("/v1/tools", headers=headers)
    assert tools.status_code == 200
    tool_names = {item["name"] for item in tools.json()["items"]}
    assert {"read_document", "send_email", "initiate_payment"} <= tool_names
    policies = client.get("/v1/policies", headers=headers)
    assert policies.status_code == 200
    assert len(policies.json()["items"]) >= 5


def test_all_simulator_scenarios_pass(client):
    headers = admin_headers(client)
    scenarios = client.get("/v1/simulator/scenarios", headers=headers)
    assert scenarios.status_code == 200
    assert len(scenarios.json()["items"]) >= 10

    response = client.post("/v1/simulator/run", headers=headers, json={})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 10
    assert body["passed"] == body["total"]
    assert body["mode"] == "mock"
    for item in body["items"]:
        assert item["passed"] is True, item
        assert item["actual"] in {"Blocked", "Quarantined", "Approval"}


def test_simulator_single_scenario_and_unknown_scenario(client):
    headers = admin_headers(client)
    ok = client.post(
        "/v1/simulator/run",
        headers=headers,
        json={"scenario_ids": ["pdf"]},
    )
    assert ok.status_code == 200
    assert ok.json()["total"] == 1
    bad = client.post(
        "/v1/simulator/run",
        headers=headers,
        json={"scenario_ids": ["does_not_exist"]},
    )
    assert bad.status_code == 400


def test_overview_stats_shape_and_decision_filters(client):
    headers = admin_headers(client)
    stats = client.get("/v1/stats/overview?period=24h", headers=headers)
    assert stats.status_code == 200
    body = stats.json()
    assert body["series"]
    assert set(body["risk_distribution"]) == {"critical", "high", "medium", "low"}
    assert body["integrations"]
    assert body["mode"] == "mock"

    denied = client.get("/v1/audit?decision=blocked&page_size=200", headers=headers)
    assert denied.status_code == 200
    assert all(item["decision"] == "Blocked" for item in denied.json()["items"])
