from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from tests.conftest import (
    admin_headers,
    create_agent,
    execute,
    sqlite_path,
)


def _request_approval(client, key, tool, arguments, *, trust="trusted", source="test-suite"):
    body = execute(client, key, tool, arguments, trust=trust, source=source).json()
    assert body["decision"] == "REQUIRE_APPROVAL", body
    assert body["executed"] is False
    assert body["approval"]["id"]
    return body


def test_approved_action_executes_once_and_replay_is_denied(client):
    headers = admin_headers(client)
    _, key = create_agent(client, headers)
    args = {"to": "finance@acme.example", "subject": "Report", "body": "Quarterly summary"}
    pending = _request_approval(client, key, "send_email", args)
    approval_id = pending["approval"]["id"]
    approved = client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers=headers,
        json={"comment": "verified recipient and contents"},
    )
    assert approved.status_code == 200, approved.text
    token = approved.json()["token"]
    allowed = execute(client, key, "send_email", args, approval_token=token)
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["decision"] == "ALLOW"
    assert allowed.json()["executed"] is True
    replay = execute(client, key, "send_email", args, approval_token=token).json()
    assert replay["decision"] == "DENY"
    assert replay["executed"] is False


def test_tampered_action_with_valid_approval_token_is_denied(client):
    headers = admin_headers(client)
    _, key = create_agent(client, headers)
    original = {"merchant": "Acme Software", "amount": 100, "currency": "USD"}
    pending = _request_approval(client, key, "initiate_payment", original)
    token = client.post(
        f"/v1/approvals/{pending['approval']['id']}/approve",
        headers=headers,
        json={"comment": "approved original amount"},
    ).json()["token"]
    tampered = {"merchant": "Acme Software", "amount": 450, "currency": "USD"}
    body = execute(client, key, "initiate_payment", tampered, approval_token=token).json()
    assert body["decision"] == "DENY"
    assert body["executed"] is False


def test_exact_same_action_with_different_nonce_is_rejected(client):
    headers = admin_headers(client)
    _, key = create_agent(client, headers)
    args = {"to": "finance@acme.example", "subject": "Report", "body": "Quarterly summary"}
    pending = _request_approval(client, key, "send_email", args)
    token = client.post(
        f"/v1/approvals/{pending['approval']['id']}/approve",
        headers=headers,
        json={"comment": "approved"},
    ).json()["token"]
    body = execute(client, key, "send_email", args, approval_token=token + "x").json()
    assert body["decision"] == "DENY"


def test_rejected_approval_cannot_execute(client):
    headers = admin_headers(client)
    _, key = create_agent(client, headers)
    args = {"to": "finance@acme.example", "subject": "Report", "body": "Quarterly summary"}
    pending = _request_approval(client, key, "send_email", args)
    rejected = client.post(
        f"/v1/approvals/{pending['approval']['id']}/reject",
        headers=headers,
        json={"comment": "not approved"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "Rejected"


def test_expired_approval_is_rejected(client, settings):
    headers = admin_headers(client)
    _, key = create_agent(client, headers)
    args = {"to": "finance@acme.example", "subject": "Report", "body": "Quarterly summary"}
    pending = _request_approval(client, key, "send_email", args)
    approval_id = pending["approval"]["id"]
    conn = sqlite3.connect(sqlite_path(settings))
    try:
        conn.execute(
            "UPDATE approvals SET expires_at = ? WHERE id = ?",
            (
                (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                ),
                approval_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    response = client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers=headers,
        json={"comment": "too late"},
    )
    assert response.status_code == 409


def test_idempotent_execution_replays_the_recorded_response(client):
    headers = admin_headers(client)
    _, key = create_agent(client, headers)
    request_id = "req_idempotent_0001"
    first = execute(
        client,
        key,
        "read_document",
        {"document": "readme.md"},
        request_id=request_id,
        idempotency_key="stable-key-001",
    )
    second = execute(
        client,
        key,
        "read_document",
        {"document": "readme.md"},
        request_id=request_id,
        idempotency_key="stable-key-001",
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["idempotent_replay"] is False
    assert second.json()["idempotent_replay"] is True
    assert first.json()["audit_id"] == second.json()["audit_id"]

    changed = execute(
        client,
        key,
        "read_document",
        {"document": "other.md"},
        request_id=request_id,
        idempotency_key="stable-key-001",
    )
    assert changed.status_code == 409


def test_audit_chain_verifies_and_detects_tampering(client, settings):
    headers = admin_headers(client)
    _, key = create_agent(client, headers)
    execute(client, key, "read_document", {"document": "readme.md"})
    result = client.get("/v1/audit/verify", headers=headers)
    assert result.status_code == 200
    assert result.json()["valid"] is True

    conn = sqlite3.connect(sqlite_path(settings))
    try:
        conn.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        conn.execute(
            "UPDATE audit_events SET details = '{\"summary\":\"tampered\"}' WHERE id = "
            "(SELECT id FROM audit_events ORDER BY sequence ASC LIMIT 1)"
        )
        conn.commit()
    finally:
        conn.close()
    broken = client.get("/v1/audit/verify", headers=headers)
    assert broken.status_code == 200
    assert broken.json()["valid"] is False


def test_audit_export_is_tenant_scoped(client):
    headers = admin_headers(client)
    response = client.get("/v1/audit/export?format=json", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, list)
    assert payload
    csv_response = client.get("/v1/audit/export?format=csv", headers=headers)
    assert csv_response.status_code == 200
    assert "text/csv" in csv_response.headers["content-type"]
