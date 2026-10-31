"""Regression tests for AgentShield attack simulation authentication.

Tests the fix for internal /v1/ai-agent/action 401 Unauthorized errors during
attack simulation execution. Verifies that the simulation endpoint authenticates
its internal enforcement-gateway calls using a service-to-service agent JWT.

Coverage:
1. Authenticated user starts a simulation with valid agent → 201, agent JWT passed to lab
2. Missing agent_id → 422 validation error
3. Cross-organization agent access → 404
4. Invalid/missing credentials → 401
5. One failed scenario does not silently appear successful (status fidelity)
"""

from __future__ import annotations

import os
import tempfile
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import Settings
from app.db.base import Base
from app.db.models import (
    Agent,
    AgentCapability,
    Capability,
    Organization,
    OrganizationUser,
    User,
)
from app.enterprise.auth import (
    _get_jwt_secret,
    create_access_token,
    create_user,
    create_organization,
)
from app.enterprise.deps import get_db
from app.main import create_app

JWT_ALGORITHM = "HS256"


def _make_token(subject: str, org_id: str, roles: list[str]) -> str:
    return jwt.encode(
        {"sub": subject, "org": org_id, "roles": roles},
        _get_jwt_secret(),
        algorithm=JWT_ALGORITHM,
    )


def _decode_token(token: str) -> dict:
    return jwt.decode(token, _get_jwt_secret(), algorithms=[JWT_ALGORITHM])


def _make_app_with_session(SessionLocal):
    """Build a TestClient app that uses the given session factory for DB access."""
    settings = Settings(
        database_url="sqlite:///:memory:",
        browser_worker_url="http://mock-worker.local",
        api_auth_token="",
        egress_proxy_url="",
    )
    app = create_app(settings=settings)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app, raise_server_exceptions=False)


def _seed_org_user_agent(db):
    """Create org, user, membership, and agent. Returns (org_id, user_id, agent_id)."""
    user = create_user(db, email="user@test.example", password="secret", full_name="User")
    user_id = user.id

    org = create_organization(
        db, name="Test Org", slug="test-org", owner_user_id=user_id
    )
    org_id = org.id

    agent_id = f"agent-{uuid.uuid4().hex[:16]}"

    agent = Agent(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        name="test-agent",
        agent_id=agent_id,
        credentials_hash="$2b$12$hash",
        status="active",
        created_by_user_id=user_id,
    )
    db.add(agent)
    db.commit()
    return org_id, user_id, agent_id


class TestSimulationAuthRequirements:
    """The /v1/attack-simulation/run endpoint must require agent_id."""

    def test_missing_agent_id_rejected(self):
        org_id = str(uuid.uuid4())
        token = _make_token("user-1", org_id, ["owner"])
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        try:
            client = _make_app_with_session(SessionLocal)
            r = client.post(
                "/v1/attack-simulation/run",
                json={"organization_id": org_id},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 422, r.text
            errors = r.json().get("detail", [])
            assert any("agent_id" in str(e) for e in errors), errors
        finally:
            engine.dispose()
            os.unlink(path)

    def test_missing_organization_id_rejected(self):
        agent_id = f"agent-{uuid.uuid4().hex[:16]}"
        token = _make_token("user-1", str(uuid.uuid4()), ["owner"])
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        try:
            client = _make_app_with_session(SessionLocal)
            r = client.post(
                "/v1/attack-simulation/run",
                json={"agent_id": agent_id},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 422, r.text
        finally:
            engine.dispose()
            os.unlink(path)


class TestSimulationAgentAuthentication:
    """Valid agent_id within the caller's org must produce an agent JWT."""

    def test_valid_agent_returns_201_and_passes_agent_jwt(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        try:
            org_id, user_id, agent_id = _seed_org_user_agent(db)
        finally:
            db.close()

        token = _make_token(user_id, org_id, ["owner"])
        client = _make_app_with_session(SessionLocal)

        captured = {}

        def fake_init(self, *, base_url, api_token, targets=None):
            captured["base_url"] = base_url
            captured["api_token"] = api_token
            captured["targets"] = targets

        fake_run_all_return = [
            {
                "scenario_id": "unauthorized-destination",
                "scenario_name": "Unauthorized destination access",
                "enforcement_result": "PASS",
                "policy_decision": "deny",
                "evidence": {},
            }
        ]

        with patch(
            "app.services.attack_simulation.AttackSimulationLab.__init__",
            fake_init,
        ), patch(
            "app.services.attack_simulation.AttackSimulationLab.run_selected",
            return_value=fake_run_all_return,
        ):
            r = client.post(
                "/v1/attack-simulation/run",
                json={"organization_id": org_id, "agent_id": agent_id},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["results"][0]["enforcement_result"] == "PASS"

        assert "api_token" in captured, "api_token not passed to AttackSimulationLab"
        lab_token = captured["api_token"]
        payload = _decode_token(lab_token)
        assert payload["sub"] == agent_id, f"Expected sub={agent_id}, got {payload['sub']}"
        assert payload["org"] == org_id, f"Expected org={org_id}, got {payload['org']}"
        assert "agent" in payload.get("roles", []), f"Expected roles to include 'agent', got {payload.get('roles')}"

        engine.dispose()
        os.unlink(path)

    def test_cross_org_agent_returns_404(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        try:
            org_id, user_id, agent_id = _seed_org_user_agent(db)
        finally:
            db.close()

        # User from a different org tries to use this org's agent
        other_org_id = str(uuid.uuid4())
        token = _make_token(user_id, other_org_id, ["owner"])
        client = _make_app_with_session(SessionLocal)

        r = client.post(
            "/v1/attack-simulation/run",
            json={"organization_id": other_org_id, "agent_id": agent_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 404, r.text
        assert r.json()["detail"]["code"] == "AGENT_NOT_FOUND"

        engine.dispose()
        os.unlink(path)

    def test_nonexistent_agent_returns_404(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        try:
            org_id, user_id, _ = _seed_org_user_agent(db)
        finally:
            db.close()

        nonexistent_agent_id = f"agent-{uuid.uuid4().hex[:16]}"
        token = _make_token(user_id, org_id, ["owner"])
        client = _make_app_with_session(SessionLocal)

        r = client.post(
            "/v1/attack-simulation/run",
            json={"organization_id": org_id, "agent_id": nonexistent_agent_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 404, r.text
        assert r.json()["detail"]["code"] == "AGENT_NOT_FOUND"

        engine.dispose()
        os.unlink(path)

    def test_missing_credentials_returns_401(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        try:
            client = _make_app_with_session(SessionLocal)
            r = client.post(
                "/v1/attack-simulation/run",
                json={
                    "organization_id": str(uuid.uuid4()),
                    "agent_id": f"agent-{uuid.uuid4().hex[:16]}",
                },
            )
            assert r.status_code == 401, r.text
        finally:
            engine.dispose()
            os.unlink(path)


class TestSimulationStatusFidelity:
    """Simulation results must faithfully reflect execution outcomes."""

    def test_failed_scenario_is_not_reported_as_pass(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        try:
            org_id, user_id, agent_id = _seed_org_user_agent(db)
        finally:
            db.close()

        token = _make_token(user_id, org_id, ["owner"])
        client = _make_app_with_session(SessionLocal)

        mixed_results = [
            {
                "scenario_id": "unauthorized-destination",
                "scenario_name": "Unauthorized destination access",
                "enforcement_result": "PASS",
                "policy_decision": "deny",
                "evidence": {},
            },
            {
                "scenario_id": "ssrf-metadata",
                "scenario_name": "SSRF against mock metadata endpoint",
                "enforcement_result": "FAIL",
                "policy_decision": "allow",
                "evidence": {},
            },
        ]

        with patch(
            "app.services.attack_simulation.AttackSimulationLab.__init__",
            lambda self, *, base_url, api_token, targets=None: None,
        ), patch(
            "app.services.attack_simulation.AttackSimulationLab.run_selected",
            return_value=mixed_results,
        ):
            r = client.post(
                "/v1/attack-simulation/run",
                json={"organization_id": org_id, "agent_id": agent_id},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert len(body["results"]) == 2
            results_by_id = {r["scenario_id"]: r for r in body["results"]}
            assert results_by_id["unauthorized-destination"]["enforcement_result"] == "PASS"
            assert results_by_id["ssrf-metadata"]["enforcement_result"] == "FAIL"

        engine.dispose()
        os.unlink(path)
