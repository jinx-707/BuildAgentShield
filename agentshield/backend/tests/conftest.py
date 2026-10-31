from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import utcnow
from app.main import create_app
from app.security import create_user_token, hash_password


ADMIN_PASSWORD = "admin-change-me"


def build_settings(db_path: Path, **overrides: Any) -> Settings:
    values = {
        "database_url": f"sqlite+aiosqlite:///{db_path.as_posix()}",
        "jwt_secret": "test-jwt-secret-that-is-long-enough",
        "api_key_pepper": "test-api-key-pepper",
        "approval_signing_secret": "test-approval-signing-secret",
        "admin_email": "admin@agentshield.local",
        "admin_password": ADMIN_PASSWORD,
        "admin_tenant_slug": "acme",
        "admin_tenant_name": "Acme workspace",
        "seed_demo_data": True,
        "p1_engine": "mock",
        "p2_adapters": "mock",
        "p3_adapters": "mock",
        "opa_url": None,
        "rate_limit_per_minute": 100000,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "agentshield-test.db"


@pytest.fixture
def settings(db_path: Path) -> Settings:
    return build_settings(db_path)


@pytest.fixture
def client(settings: Settings):
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, email: str = "admin@agentshield.local", password: str = ADMIN_PASSWORD) -> dict[str, Any]:
    response = client.post("/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def admin_headers(client: TestClient) -> dict[str, str]:
    return auth_headers(login(client)["access_token"])


def create_agent(
    client: TestClient,
    headers: dict[str, str],
    *,
    name: str | None = None,
    permissions: list[str] | None = None,
    scopes: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    payload = {
        "name": name or f"test-agent-{uuid.uuid4().hex[:8]}",
        "role": "Test agent",
        "permissions": permissions
        or [
            "documents.read",
            "local_files.read",
            "system_files.read",
            "environment.read",
            "terminal.run",
            "files.delete",
            "browser.read",
            "email.send",
            "dlp.export",
            "downloads.write",
            "payments.execute",
            "external_api.call",
            "mcp.call",
        ],
        "scopes": scopes
        or {
            "allowed_paths": ["workspace", "/workspace"],
            "allowed_domains": ["acme.example", "example.test"],
            "allowed_merchants": ["Acme Software"],
            "payment_budget": 500,
            "allowed_env": ["SAFE_FLAG"],
            "allowed_system_paths": ["/workspace/public.txt"],
            "allowed_servers": ["safe-server"],
        },
    }
    response = client.post("/v1/agents", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    body = response.json()
    return body["agent"], body["api_key"]


def tool_request(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    request_id: str | None = None,
    trust: str = "trusted",
    classification: str = "internal",
    source: str = "test-suite",
) -> dict[str, Any]:
    return {
        "request_id": request_id or f"req_{uuid.uuid4().hex[:20]}",
        "tool_name": tool_name,
        "arguments": arguments,
        "provenance": {
            "source": source,
            "trust": trust,
            "data_classification": classification,
            "tainted": trust == "untrusted",
        },
        "reason": "automated security test",
    }


def execute(
    client: TestClient,
    agent_key: str,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    request_id: str | None = None,
    approval_token: str | None = None,
    idempotency_key: str | None = None,
    trust: str = "trusted",
    classification: str = "internal",
    source: str = "test-suite",
):
    headers = {"X-Agent-Key": agent_key}
    if approval_token:
        headers["X-Approval-Token"] = approval_token
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    return client.post(
        "/v1/tools/execute",
        headers=headers,
        json=tool_request(
            tool_name,
            arguments,
            request_id=request_id,
            trust=trust,
            classification=classification,
            source=source,
        ),
    )


def sqlite_path(settings: Settings) -> str:
    return settings.database_url.replace("sqlite+aiosqlite:///", "")


def add_user(settings: Settings, tenant_id: str, role: str, email: str | None = None) -> str:
    user_id = f"usr_{uuid.uuid4().hex[:20]}"
    email = email or f"{role}-{user_id}@agentshield.local"
    conn = sqlite3.connect(sqlite_path(settings))
    try:
        conn.execute(
            "INSERT INTO users (id, tenant_id, email, password_hash, role, active, created_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?)",
            (
                user_id,
                tenant_id,
                email,
                hash_password("test-password"),
                role,
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f"),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    token, _ = create_user_token(
        settings, user_id=user_id, tenant_id=tenant_id, role=role, email=email
    )
    return token


def add_second_tenant(settings: Settings) -> dict[str, str]:
    tenant_id = f"ten_{uuid.uuid4().hex[:20]}"
    agent_id = f"agt_{uuid.uuid4().hex[:20]}"
    user_id = f"usr_{uuid.uuid4().hex[:20]}"
    approval_id = f"apr_{uuid.uuid4().hex[:20]}"
    conn = sqlite3.connect(sqlite_path(settings))
    try:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        conn.execute(
            "INSERT INTO tenants (id, slug, name, created_at) VALUES (?, ?, ?, ?)",
            (tenant_id, f"other-{tenant_id[-8:]}", "Other tenant", now),
        )
        conn.execute(
            "INSERT INTO agents (id, tenant_id, name, role, status, permissions, scopes, request_count, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (
                agent_id,
                tenant_id,
                "other-agent",
                "Other",
                "Active",
                '["documents.read"]',
                '{"allowed_paths": ["workspace"]}',
                now,
                now,
            ),
        )
        conn.execute(
            "INSERT INTO users (id, tenant_id, email, password_hash, role, active, created_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?)",
            (user_id, tenant_id, "other-admin@agentshield.local", hash_password("test-password"), "admin", now),
        )
        conn.execute(
            "INSERT INTO approvals (id, tenant_id, agent_id, tool_name, arguments_snapshot, action_hash, action_summary, risk_score, status, reason, requested_by, review_comment, expires_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 50, 'Pending', 'other tenant approval', 'seed', '', ?, ?)",
            (
                approval_id,
                tenant_id,
                agent_id,
                "read_document",
                '{"document":"private.md"}',
                "a" * 64,
                "read_document private.md",
                (datetime.now(timezone.utc) + __import__("datetime").timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S.%f"),
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    token, _ = create_user_token(
        settings,
        user_id=user_id,
        tenant_id=tenant_id,
        role="admin",
        email="other-admin@agentshield.local",
    )
    return {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "user_id": user_id,
        "approval_id": approval_id,
        "token": token,
    }


def current_utc() -> datetime:
    return utcnow()
