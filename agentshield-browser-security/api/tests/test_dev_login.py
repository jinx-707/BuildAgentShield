"""Development seed and login authentication tests.

Uses a throwaway SQLite database so the real PostgreSQL volume is never
touched. Covers seed reconciliation, password verification, and login token
issuance through the real FastAPI endpoint.
"""

import os
import sys
import tempfile
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# `scripts.seed_dev` lives at the repository root, one level above `api/`.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.config import Settings  # noqa: E402  (path inserted above)
from app.db.base import Base, init_db, get_db_session  # noqa: E402
from app.db.models import User, Organization, OrganizationUser  # noqa: E402
from app.enterprise.auth import (  # noqa: E402
    authenticate_user,
    create_user,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from scripts.seed_dev import seed, DEFAULT_EMAIL, DEFAULT_PASSWORD  # noqa: E402
from tests.conftest import FakeWorkerClient, make_test_app  # noqa: E402


def _sqlite_url(path: str) -> str:
    return f"sqlite:///{path}"


@pytest.fixture
def sqlite_db():
    """Throwaway SQLite database with all tables created."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(_sqlite_url(path), connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()
        os.unlink(path)


# ---------------------------------------------------------------------------
# Seed behaviour
# ---------------------------------------------------------------------------


def test_seed_creates_missing_admin(sqlite_db):
    seed(sqlite_db)

    user = sqlite_db.query(User).filter(User.email == DEFAULT_EMAIL).first()
    assert user is not None, "admin user should be created"
    assert user.is_active is True
    assert verify_password(DEFAULT_PASSWORD, user.password_hash)
    # No duplicate rows.
    assert sqlite_db.query(User).filter(User.email == DEFAULT_EMAIL).count() == 1


def test_seed_reconciles_existing_admin(sqlite_db):
    # Pre-create the admin with a stale password and deactivated account.
    user = User(
        email=DEFAULT_EMAIL,
        password_hash=hash_password("stale-password"),
        full_name="Old Admin",
        is_active=False,
    )
    sqlite_db.add(user)
    sqlite_db.commit()
    before_id = user.id

    seed(sqlite_db)

    user = sqlite_db.query(User).filter(User.email == DEFAULT_EMAIL).first()
    assert user is not None
    assert user.id == before_id, "existing row must be reconciled, not recreated"
    assert user.is_active is True, "deactivated account must be reactivated"
    assert verify_password(DEFAULT_PASSWORD, user.password_hash), "password must be rehashed"
    assert not verify_password("stale-password", user.password_hash)
    assert sqlite_db.query(User).filter(User.email == DEFAULT_EMAIL).count() == 1


# ---------------------------------------------------------------------------
# Password verification
# ---------------------------------------------------------------------------


def test_correct_password_authenticates(sqlite_db):
    create_user(
        sqlite_db,
        email="user@example.com",
        password="correct-password",
        full_name="Example User",
    )
    sqlite_db.commit()

    result = authenticate_user(sqlite_db, "user@example.com", "correct-password")
    assert result is not None
    assert result.email == "user@example.com"
    assert result.is_active is True


def test_incorrect_password_rejected(sqlite_db):
    create_user(
        sqlite_db,
        email="user@example.com",
        password="correct-password",
        full_name="Example User",
    )
    sqlite_db.commit()

    assert authenticate_user(sqlite_db, "user@example.com", "wrong-password") is None
    assert authenticate_user(sqlite_db, "nobody@example.com", "correct-password") is None


def test_inactive_user_rejected(sqlite_db):
    user = User(
        email="user@example.com",
        password_hash=hash_password("password"),
        is_active=False,
    )
    sqlite_db.add(user)
    sqlite_db.commit()

    assert authenticate_user(sqlite_db, "user@example.com", "password") is None


# ---------------------------------------------------------------------------
# Login endpoint token issuance
# ---------------------------------------------------------------------------


def test_login_returns_valid_token(sqlite_db):
    url = _sqlite_url(sqlite_db.bind.url.database)
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
    app = make_test_app(settings, FakeWorkerClient())

    # Seed creates the admin user, organization and membership.
    seed(sqlite_db)

    with TestClient(app) as client:
        response = client.post(
            "/v1/auth/login",
            json={"email": DEFAULT_EMAIL, "password": DEFAULT_PASSWORD},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["organization_name"] == "Acme Security"
        assert body["role"] == "owner"
        assert "access_token" in body and body["access_token"]

        # The issued token is a valid JWT with the expected claims.
        payload = decode_access_token(body["access_token"])
        assert payload is not None
        user = sqlite_db.query(User).filter(User.email == DEFAULT_EMAIL).first()
        assert payload["sub"] == str(user.id)
        assert payload["roles"] == ["owner"]


def test_login_rejects_wrong_password(sqlite_db):
    url = _sqlite_url(sqlite_db.bind.url.database)
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
    app = make_test_app(settings, FakeWorkerClient())
    seed(sqlite_db)

    with TestClient(app) as client:
        response = client.post(
            "/v1/auth/login",
            json={"email": DEFAULT_EMAIL, "password": "wrong-password"},
        )
        assert response.status_code == 401, response.text


def test_access_token_subject_is_string():
    """create_access_token must coerce a UUID subject to a string so it
    serialises to JSON inside the JWT."""
    token = create_access_token(subject=uuid4(), organization_id="org-1", roles=["owner"])
    payload = decode_access_token(token)
    assert payload is not None
    assert isinstance(payload["sub"], str)
    assert payload["org"] == "org-1"
    assert payload["roles"] == ["owner"]
