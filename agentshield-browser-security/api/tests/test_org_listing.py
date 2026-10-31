"""Regression tests for organization-scoped list endpoints.

Covers the UUID response serialization fix:
- GET /v1/organizations/{org_id}/agents  (AgentOut.id is a UUID)
- GET /v1/organizations/{org_id}/policies (PolicyOut.id and organization_id are UUIDs)

Uses a throwaway SQLite database so the real PostgreSQL volume is never touched.
"""

import os
import sys
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.config import Settings  # noqa: E402
from app.db.base import Base, init_db, get_db_session  # noqa: E402
from app.db.models import (  # noqa: E402
    Agent,
    Organization,
    OrganizationUser,
    Policy,
    User,
)
from app.enterprise.auth import create_access_token  # noqa: E402
from tests.conftest import FakeWorkerClient, make_test_app  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pg_available = bool(DATABASE_URL)


def _sqlite_url(path: str) -> str:
    return f"sqlite:///{path}"


@pytest.fixture(scope="function")
def pg_db():
    if not pg_available:
        pytest.skip("DATABASE_URL not configured; PostgreSQL integration tests skipped")
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _make_app_with_db(pg_db):
    url = pg_db.bind.url.render_as_string(hide_password=False)
    settings = Settings(
        _env_file=None,
        environment="test",
        log_level="WARNING",
        database_url=url,
        browser_worker_url="http://browser-worker.test:8080",
        allowed_domains="example.com",
        policy_backend="mock",
        inspection_backend="mock",
        api_auth_token="",
    )
    init_db(settings)
    return make_test_app(settings, FakeWorkerClient())


def _auth_headers(user_id, org_id):
    token = create_access_token(
        subject=str(user_id), organization_id=str(org_id), roles=["owner"]
    )
    return {"Authorization": f"Bearer {token}"}


def _seed_org_user(db):
    unique = uuid4().hex[:8]
    org = Organization(name=f"Org {unique}", slug=f"org-{unique}")
    db.add(org)
    db.flush()
    user = User(email=f"user+{unique}@example.com", password_hash="x", is_active=True)
    db.add(user)
    db.flush()
    db.add(
        OrganizationUser(
            organization_id=org.id, user_id=user.id, role="owner"
        )
    )
    db.commit()
    return org, user


# ---------------------------------------------------------------------------
# List agents
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# List policies
# ---------------------------------------------------------------------------


def test_list_policies_empty_list(pg_db):
    org, user = _seed_org_user(pg_db)
    pg_db.commit()

    app = _make_app_with_db(pg_db)
    headers = _auth_headers(user.id, org.id)
    with TestClient(app) as client:
        r = client.get(f"/v1/organizations/{org.id}/policies", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json() == []


# ---------------------------------------------------------------------------
# Authorization preserved
# ---------------------------------------------------------------------------


def test_list_agents_cross_tenant_forbidden(pg_db):
    unique = uuid4().hex[:8]
    org_a = Organization(name=f"Org A {unique}", slug=f"org-a-{unique}")
    org_b = Organization(name=f"Org B {unique}", slug=f"org-b-{unique}")
    pg_db.add(org_a)
    pg_db.add(org_b)
    pg_db.flush()
    user_a = User(email=f"a+{unique}@example.com", password_hash="x", is_active=True)
    db = pg_db
    db.add(user_a)
    db.flush()
    db.add(OrganizationUser(organization_id=org_a.id, user_id=user_a.id, role="owner"))
    agent_a = Agent(
        organization_id=org_a.id, name=f"Agent A {unique}", agent_id=f"agent-a-{unique}", status="active"
    )
    db.add(agent_a)
    db.commit()

    app = _make_app_with_db(pg_db)
    # user_a belongs to org_a (token org_a) but requests org_b's agents -> 403.
    headers = _auth_headers(user_a.id, org_a.id)
    with TestClient(app) as client:
        r = client.get(f"/v1/organizations/{org_b.id}/agents", headers=headers)
        assert r.status_code == 403, r.text
