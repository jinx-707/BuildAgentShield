"""Tests for the evidence collector API.

Covers endpoint registration and database dependency injection, per the
AgentShield Docker runtime stabilization work. The database dependency is
exercised against a throwaway SQLite database so no Postgres instance is
required.
"""

import os
import uuid
from importlib import reload

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect as sa_inspect
from sqlalchemy.orm import sessionmaker

import main
from main import app, get_db, EvidenceRecord, Base, EvidenceSubmitRequest

TEST_DB_URL = "sqlite:////tmp/evidence_collector_test.db"


def reload_app_with_db(db_url: str):
    """Reload the main module so the module-level engine binds to `db_url`."""
    os.environ["DATABASE_URL"] = db_url
    # Reduce noise from the settings env_file lookup.
    os.environ.pop("REDIS_URL", None)
    reloaded = reload(main)
    return reloaded.app, reloaded.get_db


@pytest.fixture()
def db_engine():
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    TestingSessionLocal = sessionmaker(
        bind=db_engine, autoflush=False, autocommit=False
    )
    db = TestingSessionLocal()
    yield db
    db.close()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


def test_endpoints_registered():
    paths = {r.path for r in app.routes if getattr(r, "path", None)}
    expected = {
        "/health",
        "/v1/evidence",
        "/v1/evidence/simulation/{simulation_id}",
        "/v1/evidence/campaign/{campaign_id}",
        "/v1/evidence/organization/{organization_id}",
    }
    assert expected.issubset(paths), f"missing routes: {expected - paths}"


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "evidence-collector"}


def test_db_dependency_is_wired_via_depends():
    """db must be injected with Depends(get_db), not declared as a bare
    Session parameter (which caused the FastAPIError at startup)."""
    target = None
    for route in app.routes:
        if getattr(route, "path", None) == "/v1/evidence" and getattr(
            route, "methods", None
        ) and "POST" in route.methods:
            target = route
            break
    assert target is not None, "POST /v1/evidence route not registered"

    dependant = target.dependant
    db_dep = None
    for dep in dependant.dependencies:
        if dep.call is get_db:
            db_dep = dep
            break
    assert db_dep is not None, "db parameter is not injected via Depends(get_db)"

    # The dependency is a generator (yields the session, then closes it).
    import inspect

    assert inspect.isgeneratorfunction(get_db)


def test_get_db_yields_session_and_closes(db_session):
    """get_db yields a SQLAlchemy Session and closes it when the generator is
    exhausted (the cleanup semantics FastAPI relies on).."""
    from sqlalchemy.orm import Session

    gen = get_db()
    db = next(gen)
    assert isinstance(db, Session)
    assert db.bind is not None
    # Exhausting the generator runs the `finally: db.close()` block.
    with pytest.raises(StopIteration):
        next(gen)


def test_submit_evidence_roundtrip(client):
    payload = {
        "simulation_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "scenario_id": "phishing",
        "source": "browser-worker",
        "evidence_type": "screenshot",
        "description": "a phishing page",
        "content": {"url": "https://example.com"},
    }
    response = client.post("/v1/evidence", json=payload)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["scenario_id"] == "phishing"
    assert body["evidence_type"] == "screenshot"
    assert "id" in body and "collected_at" in body

    sim_id = payload["simulation_id"]
    listed = client.get(f"/v1/evidence/simulation/{sim_id}")
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["id"] == body["id"]
