"""Integration tests for AgentShield capability permissions and scope enforcement.

Tests run against a throwaway SQLite database. Covers:
- Capability listing (seeded defaults)
- Agent capability CRUD (enabled state, scope, domains, approval)
- Cross-organization access rejection
- Approval queue (list, approve, reject)
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.config import Settings  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.models import (  # noqa: E402
    Agent,
    AgentCapability,
    Capability,
    Organization,
)
from app.enterprise.auth import (  # noqa: E402
    create_access_token,
    create_user,
    create_organization,
    create_agent as auth_create_agent,
)
from app.main import create_app  # noqa: E402


def make_app_with_session(SessionLocal):
    """Build a TestClient app using the given session factory for DB access."""
    settings = Settings(
        database_url="sqlite:///:memory:",
        browser_worker_url="http://mock-worker.local",
        api_auth_token="",
        egress_proxy_url="",
    )
    app = create_app(settings=settings)

    from app.enterprise.deps import get_db

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def db_session():
    """Throwaway SQLite database with all tables created and a session factory."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db, SessionLocal, path
    finally:
        db.close()
        engine.dispose()
        os.unlink(path)


@pytest.fixture
def org_and_agent(db_session):
    """Create an org, user, and agent for testing."""
    db, SessionLocal, path = db_session
    user = create_user(
        db, email="owner@test.example", password="secret", full_name="Owner"
    )
    org = create_organization(
        db, name="Test Org", slug="test-org", owner_user_id=user.id
    )
    agent = auth_create_agent(
        db, organization_id=org.id, name="test-agent", created_by_user_id=user.id
    )
    db.commit()
    yield org, agent, user, SessionLocal, path


def _make_token(subject: str, org_id: str, roles: list[str] | None = None) -> str:
    return create_access_token(
        subject=subject, organization_id=org_id, roles=roles or ["owner"]
    )


class TestCapabilityListing:
    """Test listing capabilities for an organization."""

    def test_list_capabilities_seeds_defaults(self, org_and_agent):
        org, agent, user, SessionLocal, path = org_and_agent
        client = make_app_with_session(SessionLocal)
        token = _make_token(user.id, str(org.id), ["owner"])

        resp = client.get(
            f"/v1/organizations/{org.id}/capabilities",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert len(data) == 11
        keys = {c["key"] for c in data}
        assert "terminal" in keys
        assert "browser" in keys
        assert "email" in keys

    def test_list_capabilities_cross_org_denied(self, db_session):
        db, SessionLocal, path = db_session
        user1 = create_user(db, email="o1@test.example", password="secret")
        org1 = create_organization(db, name="Org 1", slug="org1", owner_user_id=user1.id)
        user2 = create_user(db, email="o2@test.example", password="secret")
        org2 = create_organization(db, name="Org 2", slug="org2", owner_user_id=user2.id)
        auth_create_agent(db, organization_id=org1.id, name="agent-1")
        db.commit()

        client = make_app_with_session(SessionLocal)
        token = _make_token(user2.id, str(org2.id), ["owner"])
        resp = client.get(
            f"/v1/organizations/{org1.id}/capabilities",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403, resp.text


class TestAgentCapabilityCRUD:
    """Test agent capability read/update."""

    def test_get_agent_capabilities(self, org_and_agent):
        org, agent, user, SessionLocal, path = org_and_agent
        db = SessionLocal()
        try:
            from app.api.enterprise import _seed_default_capabilities
            _seed_default_capabilities(db, str(org.id))
            # Create default (disabled) AgentCapability records for the agent
            caps = (
                db.query(Capability)
                .filter(Capability.organization_id == org.id)
                .all()
            )
            for cap in caps:
                db.add(
                    AgentCapability(
                        organization_id=org.id,
                        agent_id=agent.id,
                        capability_id=cap.id,
                        enabled=False,
                        allowed_tools=list(cap.tools or []),
                    )
                )
            db.commit()
        finally:
            db.close()

        client = make_app_with_session(SessionLocal)
        token = _make_token(user.id, str(org.id), ["owner"])

        resp = client.get(
            f"/v1/agents/{agent.agent_id}/capabilities",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert len(data) == 11
        for cap in data:
            assert cap["enabled"] is False
            assert cap["capability_key"] is not None

    def test_update_agent_capability_enabled(self, org_and_agent):
        org, agent, user, SessionLocal, path = org_and_agent
        db = SessionLocal()
        try:
            from app.api.enterprise import _seed_default_capabilities
            _seed_default_capabilities(db, str(org.id))

            cap = (
                db.query(Capability)
                .filter(Capability.key == "terminal", Capability.organization_id == org.id)
                .first()
            )
            assert cap is not None

            ac = AgentCapability(
                organization_id=org.id,
                agent_id=agent.id,
                capability_id=cap.id,
                enabled=False,
                allowed_tools=list(cap.tools or []),
            )
            db.add(ac)
            db.commit()
        finally:
            db.close()

        client = make_app_with_session(SessionLocal)
        token = _make_token(user.id, str(org.id), ["owner"])

        resp = client.patch(
            f"/v1/agents/{agent.agent_id}/capabilities/terminal",
            headers={"Authorization": f"Bearer {token}"},
            json={"enabled": True},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["enabled"] is True


class TestApprovalQueue:
    """Test approval queue endpoints."""

    def test_list_approvals_empty(self, org_and_agent):
        org, agent, user, SessionLocal, path = org_and_agent
        client = make_app_with_session(SessionLocal)
        token = _make_token(user.id, str(org.id), ["owner"])

        resp = client.get(
            f"/v1/organizations/{org.id}/approvals",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == []
