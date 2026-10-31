"""Regression tests for campaign listing and attack simulation execution.

Requires a real PostgreSQL database (DATABASE_URL). Skips when DATABASE_URL is
not configured.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.db.ai_models import AttackSimulationRun
from app.db.base import Base, init_db
from app.config import Settings
from tests.conftest import FakeWorkerClient, make_test_app

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pg_available = bool(DATABASE_URL)


def pg_engine():
    return create_engine(DATABASE_URL, pool_pre_ping=True)


@pytest.fixture(scope="function")
def pg_db():
    if not pg_available:
        pytest.skip("DATABASE_URL not configured; PostgreSQL integration tests skipped")
    engine = pg_engine()
    # Tables are expected to exist from Alembic migrations; do not call
    # create_all() because pre-existing schema mismatches (e.g. capabilities
    # organization_id VARCHAR vs organizations.id UUID) would prevent it.
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def make_app_with_db(db):
    settings = Settings(
        _env_file=None,
        environment="test",
        log_level="WARNING",
        database_url=DATABASE_URL,
        browser_worker_url="http://browser-worker.test:8080",
        allowed_domains="example.com",
        policy_backend="mock",
        inspection_backend="mock",
        api_auth_token="",
    )
    init_db(settings)
    return make_test_app(settings, FakeWorkerClient())


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _seed_org_and_user(db):
    """Seed a minimal organization + user into the database using raw SQL."""
    org_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    unique = uuid.uuid4().hex[:8]
    now = datetime.now(timezone.utc).isoformat()

    db.execute(
        text(
            "INSERT INTO organizations (id, name, slug, is_active, created_at, updated_at)"
            " VALUES (:id, :name, :slug, true, :now, :now)"
        ),
        {"id": org_id, "name": f"Test Org {unique}", "slug": f"test-org-{unique}", "now": now},
    )
    db.execute(
        text(
            "INSERT INTO users (id, email, password_hash, full_name, is_active, created_at, updated_at)"
            " VALUES (:id, :email, :hash, :name, true, :now, :now)"
        ),
        {
            "id": user_id,
            "email": f"user+{unique}@test.org",
            "hash": "$2b$12$hash",
            "name": "Test User",
            "now": now,
        },
    )
    db.execute(
        text(
            "INSERT INTO organization_users (id, organization_id, user_id, role, is_active, created_at, updated_at)"
            " VALUES (:id, :org_id, :user_id, 'owner', true, :now, :now)"
        ),
        {"id": str(uuid.uuid4()), "org_id": org_id, "user_id": user_id, "now": now},
    )
    db.commit()
    return org_id, user_id


def _seed_agent(db, org_id: str) -> str:
    """Seed an active agent in the given organization and return its agent_id."""
    agent_id = f"agent-{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        text(
            "INSERT INTO agents (id, organization_id, name, agent_id, status, credentials_hash, permissions, created_at, updated_at)"
            " VALUES (:id, :org_id, :name, :agent_id, 'active', :hash, '[]'::jsonb, :now, :now)"
        ),
        {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": "test-agent",
            "agent_id": agent_id,
            "hash": "$2b$12$hash",
            "now": now,
        },
    )
    db.commit()
    return agent_id


# ---------------------------------------------------------------------------
# Campaign listing tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_list_campaigns_empty(pg_db):
    org_id, user_id = _seed_org_and_user(pg_db)

    from app.enterprise.auth import create_access_token

    token = create_access_token(
        subject=user_id, organization_id=org_id, roles=["owner"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.get(
            "/v1/simulations/campaigns?limit=100&offset=0",
            headers=auth_headers(token),
        )
        assert r.status_code == 200, r.text
        assert r.json() == []


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_list_campaigns_with_records(pg_db):
    org_id, user_id = _seed_org_and_user(pg_db)
    campaign_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    pg_db.execute(
        text(
            "INSERT INTO simulation_campaigns (id, organization_id, user_id, name, description, policy_version, status, scenario_ids, execution_mode, max_concurrency, created_at, updated_at)"
            " VALUES (:id, :org_id, :user_id, :name, :desc, :policy, 'QUEUED', :scenarios, 'sequential', 1, :created, :updated)"
        ),
        {
            "id": campaign_id,
            "org_id": org_id,
            "user_id": user_id,
            "name": "Test Campaign",
            "desc": "A test campaign",
            "policy": "default",
            "scenarios": json.dumps(["unauthorized-destination"]),
            "created": now,
            "updated": now,
        },
    )
    pg_db.commit()

    from app.enterprise.auth import create_access_token

    token = create_access_token(
        subject=user_id, organization_id=org_id, roles=["owner"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.get(
            "/v1/simulations/campaigns?limit=100&offset=0",
            headers=auth_headers(token),
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body) == 1
        item = body[0]
        assert item["id"] == campaign_id
        assert item["name"] == "Test Campaign"
        assert item["status"] == "QUEUED"
        assert item["organization_id"] == org_id


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_list_campaigns_pagination(pg_db):
    org_id, user_id = _seed_org_and_user(pg_db)
    now = datetime.now(timezone.utc).isoformat()

    for i in range(5):
        pg_db.execute(
            text(
                "INSERT INTO simulation_campaigns (id, organization_id, user_id, name, description, policy_version, status, scenario_ids, execution_mode, max_concurrency, created_at, updated_at)"
                " VALUES (:id, :org_id, :user_id, :name, :desc, :policy, 'QUEUED', :scenarios, 'sequential', 1, :created, :updated)"
            ),
            {
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "user_id": user_id,
                "name": f"Campaign {i}",
                "desc": f"desc {i}",
                "policy": "default",
                "scenarios": json.dumps(["unauthorized-destination"]),
                "created": now,
                "updated": now,
            },
        )
    pg_db.commit()

    from app.enterprise.auth import create_access_token

    token = create_access_token(
        subject=user_id, organization_id=org_id, roles=["owner"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.get(
            "/v1/simulations/campaigns?limit=2&offset=0",
            headers=auth_headers(token),
        )
        assert r.status_code == 200, r.text
        assert len(r.json()) == 2

        r = client.get(
            "/v1/simulations/campaigns?limit=2&offset=2",
            headers=auth_headers(token),
        )
        assert r.status_code == 200, r.text
        assert len(r.json()) == 2


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_list_campaigns_organization_isolation(pg_db):
    org_a_id, user_a_id = _seed_org_and_user(pg_db)
    org_b_id, user_b_id = _seed_org_and_user(pg_db)
    now = datetime.now(timezone.utc).isoformat()

    pg_db.execute(
        text(
            "INSERT INTO simulation_campaigns (id, organization_id, user_id, name, description, policy_version, status, scenario_ids, execution_mode, max_concurrency, created_at, updated_at)"
            " VALUES (:id, :org_id, :user_id, :name, :desc, :policy, 'QUEUED', :scenarios, 'sequential', 1, :created, :updated)"
        ),
        {
            "id": str(uuid.uuid4()),
            "org_id": org_a_id,
            "user_id": user_a_id,
            "name": "Org A Campaign",
            "desc": "desc",
            "policy": "default",
            "scenarios": json.dumps(["unauthorized-destination"]),
            "created": now,
            "updated": now,
        },
    )
    pg_db.commit()

    from app.enterprise.auth import create_access_token

    token_b = create_access_token(
        subject=user_b_id, organization_id=org_b_id, roles=["owner"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.get(
            "/v1/simulations/campaigns?limit=100&offset=0",
            headers=auth_headers(token_b),
        )
        assert r.status_code == 200, r.text
        assert r.json() == []


# ---------------------------------------------------------------------------
# Attack simulation execution tests
# ---------------------------------------------------------------------------


def _make_simulation_run_request(org_id: str, agent_id: str | None = None) -> dict:
    payload = {
        "organization_id": org_id,
        "agent_id": agent_id or f"agent-{uuid.uuid4().hex[:16]}",
    }
    return payload


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_simulation_successful_execution(pg_db):
    org_id, user_id = _seed_org_and_user(pg_db)

    from app.enterprise.auth import create_access_token

    token = create_access_token(
        subject=user_id, organization_id=org_id, roles=["owner"]
    )
    agent_id = _seed_agent(pg_db, org_id)
    app = make_app_with_db(pg_db)

    fake_results = [
        {
            "scenario_id": "unauthorized-destination",
            "scenario_name": "Unauthorized destination access",
            "enforcement_result": "PASS",
            "policy_decision": "deny",
            "evidence": {"attempted_url": "http://example.com/", "response_status": 403},
        }
    ]

    with patch(
        "app.services.attack_simulation.AttackSimulationLab.run_all",
        return_value=fake_results,
    ):
        with TestClient(app) as client:
            r = client.post(
                "/v1/attack-simulation/run",
                json=_make_simulation_run_request(org_id, agent_id),
                headers=auth_headers(token),
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert "results" in body
            assert len(body["results"]) == 1
            assert body["results"][0]["scenario_id"] == "unauthorized-destination"
            assert body["results"][0]["enforcement_result"] == "PASS"


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_simulation_invalid_payload(pg_db):
    org_id, user_id = _seed_org_and_user(pg_db)

    from app.enterprise.auth import create_access_token

    token = create_access_token(
        subject=user_id, organization_id=org_id, roles=["owner"]
    )
    app = make_app_with_db(pg_db)

    with TestClient(app) as client:
        r = client.post(
            "/v1/attack-simulation/run",
            json={"scenario_ids": ["unauthorized-destination"]},
            headers=auth_headers(token),
        )
        assert r.status_code == 422, r.text


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_simulation_cross_tenant_forbidden(pg_db):
    org_a_id, user_a_id = _seed_org_and_user(pg_db)
    org_b_id, _ = _seed_org_and_user(pg_db)

    from app.enterprise.auth import create_access_token

    token_a = create_access_token(
        subject=user_a_id, organization_id=org_a_id, roles=["owner"]
    )
    app = make_app_with_db(pg_db)

    with TestClient(app) as client:
        r = client.post(
            "/v1/attack-simulation/run",
            json=_make_simulation_run_request(org_b_id),
            headers=auth_headers(token_a),
        )
        assert r.status_code == 403, r.text


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_simulation_api_response_structure(pg_db):
    org_id, user_id = _seed_org_and_user(pg_db)

    from app.enterprise.auth import create_access_token

    token = create_access_token(
        subject=user_id, organization_id=org_id, roles=["owner"]
    )
    agent_id = _seed_agent(pg_db, org_id)
    app = make_app_with_db(pg_db)

    fake_results = [
        {
            "scenario_id": "ssrf-metadata",
            "scenario_name": "SSRF against mock metadata endpoint",
            "enforcement_result": "PASS",
            "policy_decision": "deny",
            "evidence": {"target": "http://127.0.0.1:1/metadata", "response_status": 403},
        }
    ]

    with patch(
        "app.services.attack_simulation.AttackSimulationLab.run_all",
        return_value=fake_results,
    ):
        with TestClient(app) as client:
            r = client.post(
                "/v1/attack-simulation/run",
                json=_make_simulation_run_request(org_id, agent_id),
                headers=auth_headers(token),
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert "results" in body
            assert len(body["results"]) == 1
            assert body["results"][0]["scenario_id"] == "ssrf-metadata"
            assert body["results"][0]["enforcement_result"] == "PASS"
            assert body["results"][0]["policy_decision"] == "deny"
