from __future__ import annotations

from tests.conftest import (
    add_second_tenant,
    add_user,
    admin_headers,
    auth_headers,
    create_agent,
    login,
)


def test_dashboard_login_and_bad_credentials(client):
    body = login(client)
    assert body["user"]["role"] == "admin"
    assert body["access_token"]
    assert client.post(
        "/v1/auth/login",
        json={"email": "admin@agentshield.local", "password": "wrong-password"},
    ).status_code == 401
    assert client.get("/v1/agents").status_code == 401


def test_agent_api_key_authentication_and_disabled_agent(client):
    headers = admin_headers(client)
    agent, key = create_agent(client, headers)
    assert client.get("/v1/agents", headers={"X-Agent-Key": key}).status_code == 401
    patch = client.patch(
        f"/v1/agents/{agent['id']}", json={"status": "Disabled"}, headers=headers
    )
    assert patch.status_code == 200
    response = client.post(
        "/v1/tools/execute",
        headers={"X-Agent-Key": key},
        json={
            "request_id": "req_disabled_agent_01",
            "tool_name": "read_document",
            "arguments": {"document": "readme.md"},
            "provenance": {"source": "test", "trust": "trusted"},
        },
    )
    assert response.status_code == 403


def test_viewer_role_cannot_manage_agents_or_policies(client, settings):
    admin = login(client)
    tenant_id = admin["user"]["tenant_id"]
    viewer_token = add_user(settings, tenant_id, "viewer")
    headers = auth_headers(viewer_token)
    assert client.get("/v1/agents", headers=headers).status_code == 200
    assert client.post(
        "/v1/agents",
        headers=headers,
        json={"name": "forbidden-agent", "permissions": []},
    ).status_code == 403
    assert client.patch(
        "/v1/policies/pol_001", headers=headers, json={"active": False}
    ).status_code == 403
    assert client.get("/v1/audit/verify", headers=headers).status_code == 403


def test_security_analyst_can_verify_audit_but_not_manage_agents(client, settings):
    admin = login(client)
    table = add_user(settings, admin["user"]["tenant_id"], "security_analyst")
    headers = auth_headers(table)
    assert client.get("/v1/audit/verify", headers=headers).status_code == 200
    assert client.post(
        "/v1/agents",
        headers=headers,
        json={"name": "analyst-agent", "permissions": []},
    ).status_code == 403


def test_cross_tenant_agent_and_approval_access_is_denied(client, settings):
    other = add_second_tenant(settings)
    admin = admin_headers(client)
    response = client.get(f"/v1/agents/{other['agent_id']}", headers=admin)
    assert response.status_code == 404
    response = client.get(f"/v1/approvals/{other['approval_id']}", headers=admin)
    assert response.status_code == 404
    response = client.get(
        f"/v1/agents/{other['agent_id']}", headers=auth_headers(other["token"])
    )
    assert response.status_code == 200
    response = client.get(
        f"/v1/approvals/{other['approval_id']}", headers=auth_headers(other["token"])
    )
    assert response.status_code == 200


def test_other_tenant_cannot_approve_primary_tenant_approval(client, settings):
    other = add_second_tenant(settings)
    headers = admin_headers(client)
    approvals = client.get("/v1/approvals", headers=headers).json()["items"]
    approval_id = approvals[0]["id"]
    response = client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers=auth_headers(other["token"]),
        json={"comment": "cross-tenant attempt"},
    )
    assert response.status_code == 404
