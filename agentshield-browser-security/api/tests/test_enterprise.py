"""Enterprise control plane tests.

Require a real PostgreSQL database (DATABASE_URL). Verify multi-tenant
isolation, RBAC, persistent audit, and policy versioning against the actual
database. Skip when DATABASE_URL is not configured.
"""

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import (
    Organization,
    User,
    OrganizationUser,
    Agent,
    Policy,
    AuditEvent,
    PolicyVersion,
)
from app.enterprise.auth import (
    hash_password,
    create_access_token,
    create_agent,
)
from app.schemas.browser import PolicyRequest
from app.security.database_policy_engine import DatabasePolicyEngine
from tests.conftest import FakeWorkerClient, make_test_app
from app.config import Settings
from app.db.base import init_db

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pg_available = bool(DATABASE_URL)


def pg_engine():
    return create_engine(DATABASE_URL, pool_pre_ping=True)


@pytest.fixture(scope="module")
def pg_db():
    if not pg_available:
        pytest.skip("DATABASE_URL not configured; PostgreSQL integration tests skipped")
    engine = pg_engine()
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


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


# ---------------------------------------------------------------------------
# Organization isolation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_organization_isolation(pg_db):
    org_a = Organization(name="Org A", slug="org-a")
    pg_db.add(org_a)
    pg_db.flush()
    user_a = User(email="a@example.com", password_hash=hash_password("pw"))
    pg_db.add(user_a)
    pg_db.flush()
    pg_db.add(
        OrganizationUser(
            organization_id=org_a.id, user_id=user_a.id, role="owner"
        )
    )
    pg_db.add(
        Agent(
            organization_id=org_a.id,
            name="Agent A",
            agent_id="agent-a",
            credentials_hash=hash_password("s"),
            status="active",
        )
    )

    org_b = Organization(name="Org B", slug="org-b")
    pg_db.add(org_b)
    pg_db.flush()
    pg_db.add(
        Agent(
            organization_id=org_b.id,
            name="Agent B",
            agent_id="agent-b",
            credentials_hash=hash_password("s"),
            status="active",
        )
    )
    pg_db.commit()

    token_a = create_access_token(
        subject=str(user_a.id), organization_id=str(org_a.id), roles=["owner"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.get(
            f"/v1/organizations/{org_a.id}/agents",
            headers=auth_headers(token_a),
        )
        assert r.status_code == 200, r.text
        ids = [a["agent_id"] for a in r.json()]
        assert "agent-a" in ids
        assert "agent-b" not in ids

        r = client.get(
            f"/v1/organizations/{org_b.id}/agents",
            headers=auth_headers(token_a),
        )
        assert r.status_code == 403, r.text


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_cross_tenant_audit_access_forbidden(pg_db):
    org_a = Organization(name="Org A", slug="org-a")
    pg_db.add(org_a)
    pg_db.flush()
    user_a = User(email="a@example.com", password_hash=hash_password("pw"))
    pg_db.add(user_a)
    pg_db.flush()
    pg_db.add(
        OrganizationUser(organization_id=org_a.id, user_id=user_a.id, role="owner")
    )

    org_b = Organization(name="Org B", slug="org-b")
    pg_db.add(org_b)
    pg_db.flush()
    pg_db.add(
        AuditEvent(
            organization_id=org_b.id,
            event_type="navigation.deny",
            actor="agent-b",
            decision="deny",
            severity="high",
        )
    )
    pg_db.commit()

    token_a = create_access_token(
        subject=str(user_a.id), organization_id=str(org_a.id), roles=["owner"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.get(
            f"/v1/organizations/{org_b.id}/audit",
            headers=auth_headers(token_a),
        )
        assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# Role-based permissions
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_viewer_cannot_create_agent(pg_db):
    org = Organization(name="Org", slug="org")
    pg_db.add(org)
    pg_db.flush()
    user = User(email="v@example.com", password_hash=hash_password("pw"))
    pg_db.add(user)
    pg_db.flush()
    pg_db.add(
        OrganizationUser(organization_id=org.id, user_id=user.id, role="viewer")
    )
    pg_db.commit()

    token = create_access_token(
        subject=str(user.id), organization_id=str(org.id), roles=["viewer"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.post(
            f"/v1/organizations/{org.id}/agents",
            json={"name": "Bad Agent"},
            headers=auth_headers(token),
        )
        assert r.status_code == 403, r.text


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_owner_can_create_agent(pg_db):
    org = Organization(name="Org", slug="org")
    pg_db.add(org)
    pg_db.flush()
    user = User(email="o@example.com", password_hash=hash_password("pw"))
    pg_db.add(user)
    pg_db.flush()
    pg_db.add(
        OrganizationUser(organization_id=org.id, user_id=user.id, role="owner")
    )
    pg_db.commit()

    token = create_access_token(
        subject=str(user.id), organization_id=str(org.id), roles=["owner"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.post(
            f"/v1/organizations/{org.id}/agents",
            json={"name": "Good Agent"},
            headers=auth_headers(token),
        )
        assert r.status_code == 201, r.text
        assert "agent_id" in r.json()
        assert "secret" in r.json()


# ---------------------------------------------------------------------------
# Agent credential revocation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_agent_credential_revocation(pg_db):
    org = Organization(name="Org", slug="org")
    pg_db.add(org)
    pg_db.flush()
    user = User(email="o@example.com", password_hash=hash_password("pw"))
    pg_db.add(user)
    pg_db.flush()
    pg_db.add(
        OrganizationUser(organization_id=org.id, user_id=user.id, role="owner")
    )
    agent = create_agent(pg_db, organization_id=str(org.id), name="Revokable")
    pg_db.commit()

    token = create_access_token(
        subject=str(user.id), organization_id=str(org.id), roles=["owner"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.post(
            f"/v1/agents/{agent.agent_id}/revoke",
            headers=auth_headers(token),
        )
        assert r.status_code == 200, r.text

    pg_db.expire_all()
    revoked = pg_db.query(Agent).filter(Agent.id == agent.id).first()
    assert revoked.status == "revoked"


# ---------------------------------------------------------------------------
# Policy versioning and rollback
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_policy_versioning_and_rollback(pg_db):
    org = Organization(name="Org", slug="org")
    pg_db.add(org)
    pg_db.flush()
    user = User(email="o@example.com", password_hash=hash_password("pw"))
    pg_db.add(user)
    pg_db.flush()
    pg_db.add(
        OrganizationUser(organization_id=org.id, user_id=user.id, role="owner")
    )
    pg_db.commit()

    token = create_access_token(
        subject=str(user.id), organization_id=str(org.id), roles=["owner"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.post(
            f"/v1/organizations/{org.id}/policies",
            json={
                "name": "Pol",
                "allowed_domains": ["example.com"],
                "default_domain_policy": "deny",
            },
            headers=auth_headers(token),
        )
        assert r.status_code == 201, r.text
        policy = r.json()
        assert policy["version"] == 1
        policy_id = policy["id"]

        r = client.patch(
            f"/v1/policies/{policy_id}",
            json={"allowed_domains": ["trusted.example.com"]},
            headers=auth_headers(token),
        )
        assert r.status_code == 200, r.text
        assert r.json()["version"] == 2

        r = client.get(
            f"/v1/organizations/{org.id}/policies/{policy_id}/versions",
            headers=auth_headers(token),
        )
        assert r.status_code == 200, r.text
        versions = r.json()
        assert len(versions) >= 2

        r = client.post(
            f"/v1/organizations/{org.id}/policies/{policy_id}/rollback",
            json={"version": 1},
            headers=auth_headers(token),
        )
        assert r.status_code == 200, r.text
        assert r.json()["allowed_domains"] == ["example.com"]


# ---------------------------------------------------------------------------
# Persistent audit events
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_persistent_audit_events(pg_db):
    org = Organization(name="Org", slug="org")
    pg_db.add(org)
    pg_db.flush()
    pg_db.add(
        AuditEvent(
            organization_id=org.id,
            event_type="session.create",
            actor="agent-1",
            decision="allow",
            severity="info",
        )
    )
    pg_db.commit()

    user = User(email="v@example.com", password_hash=hash_password("pw"))
    pg_db.add(user)
    pg_db.flush()
    pg_db.add(
        OrganizationUser(organization_id=org.id, user_id=user.id, role="viewer")
    )
    pg_db.commit()

    token = create_access_token(
        subject=str(user.id), organization_id=str(org.id), roles=["viewer"]
    )
    app = make_app_with_db(pg_db)
    with TestClient(app) as client:
        r = client.get(
            f"/v1/organizations/{org.id}/audit",
            headers=auth_headers(token),
        )
        assert r.status_code == 200, r.text
        events = r.json()
        assert len(events) >= 1
        assert events[0]["event_type"] == "session.create"


# ---------------------------------------------------------------------------
# Real policy enforcement after policy changes
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not pg_available, reason="requires PostgreSQL")
def test_policy_change_reflected_in_enforcement(pg_db):
    org = Organization(name="Org", slug="org")
    pg_db.add(org)
    pg_db.flush()
    pg_db.add(
        Policy(
            organization_id=org.id,
            name="Deny All",
            agent_id=None,
            is_active=True,
            is_default=True,
            version=1,
            allowed_domains=[],
            blocked_domains=[],
            default_domain_policy="deny",
            allowed_ports=["80", "443"],
            allow_private_networks=False,
        )
    )
    pg_db.commit()

    engine = DatabasePolicyEngine(
        allowed_domains="example.com",
        default_domain_policy="deny",
    )

    import asyncio

    decision1 = asyncio.new_event_loop().run_until_complete(
        engine.authorize(
            PolicyRequest(
                request_id="r1",
                url="https://example.com/",
                organization_id=str(org.id),
                agent_id=None,
            )
        )
    )
    assert decision1.allowed is False

    pol = pg_db.query(Policy).first()
    pol.allowed_domains = ["example.com"]
    pg_db.commit()

    engine2 = DatabasePolicyEngine(
        allowed_domains="example.com",
        default_domain_policy="deny",
    )
    decision2 = asyncio.new_event_loop().run_until_complete(
        engine2.authorize(
            PolicyRequest(
                request_id="r2",
                url="https://example.com/",
                organization_id=str(org.id),
                agent_id=None,
            )
        )
    )
    assert decision2.allowed is True
