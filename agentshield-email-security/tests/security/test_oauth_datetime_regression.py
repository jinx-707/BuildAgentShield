"""
Regression tests for the OAuth state expiry datetime timezone fix.

Root cause: datetime.utcnow() produced a naive (timezone-unaware) timestamp,
which was stored in a DateTime(timezone=True) column. The validation logic in
OAuthStateRepository.validate_and_consume_state() compares expires_at against
datetime.now(timezone.utc) (a timezone-aware value). Comparing naive vs aware
datetimes raises a TypeError on CPython / newer SQLAlchemy, or silently
misbehaves when the database driver strips tz info differently between sessions.

Fix: replace datetime.utcnow() with datetime.now(timezone.utc) everywhere in
oauth_routes.py and providers/gmail/oauth.py so all timestamps are consistently
timezone-aware UTC from the moment they are created.
"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database.models import Base, OAuthState
from app.database.repository import OAuthStateRepository
from app.providers.gmail.oauth import GoogleOAuthHandler


# ---------------------------------------------------------------------------
# Unit-level: repository layer timezone correctness
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture()
async def isolated_session():
    """Completely isolated async session using its own in-memory SQLite engine."""
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_newly_created_state_is_immediately_valid(isolated_session: AsyncSession):
    """
    A state token created right now with a 10-minute window MUST pass validation
    when checked immediately. This fails with naive utcnow() on certain DB
    drivers because the tz comparison raises TypeError or treats the naive
    timestamp as local time.
    """
    repo = OAuthStateRepository(isolated_session)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    state = await repo.create_state(
        state_token="valid-regression-token-001",
        tenant_id="tenant-regression",
        agent_id="agent-regression",
        provider="google",
        requested_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        redirect_uri="https://example.com/callback",
        expires_at=expires_at,
    )
    await isolated_session.commit()

    result = await repo.validate_and_consume_state("valid-regression-token-001")
    assert result is not None, (
        "State token created with datetime.now(timezone.utc) MUST be valid immediately. "
        "If this fails the naive/aware datetime bug is still present."
    )
    assert result.state_token == "valid-regression-token-001"


@pytest.mark.asyncio
async def test_expired_state_is_rejected(isolated_session: AsyncSession):
    """A state token whose expires_at is in the past MUST be rejected."""
    repo = OAuthStateRepository(isolated_session)
    # Expired 5 minutes ago
    expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)

    await repo.create_state(
        state_token="expired-token-001",
        tenant_id="tenant-regression",
        agent_id="agent-regression",
        provider="google",
        requested_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        redirect_uri="https://example.com/callback",
        expires_at=expires_at,
    )
    await isolated_session.commit()

    result = await repo.validate_and_consume_state("expired-token-001")
    assert result is None, "Expired state token MUST be rejected."


@pytest.mark.asyncio
async def test_state_consumed_only_after_successful_validation(isolated_session: AsyncSession):
    """State is marked used=True only after a successful validate_and_consume_state call."""
    from sqlalchemy import select

    repo = OAuthStateRepository(isolated_session)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    await repo.create_state(
        state_token="consume-test-token-001",
        tenant_id="tenant-regression",
        agent_id="agent-regression",
        provider="google",
        requested_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        redirect_uri="https://example.com/callback",
        expires_at=expires_at,
    )
    await isolated_session.commit()

    # Verify it's not used yet
    stmt = select(OAuthState).where(OAuthState.state_token == "consume-test-token-001")
    row = (await isolated_session.execute(stmt)).scalar_one()
    assert row.used is False, "State MUST NOT be marked used before validation."

    # Consume it
    result = await repo.validate_and_consume_state("consume-test-token-001")
    assert result is not None

    # Verify now marked used
    await isolated_session.refresh(row)
    assert row.used is True, "State MUST be marked used=True after successful validation."


@pytest.mark.asyncio
async def test_consumed_state_cannot_be_replayed(isolated_session: AsyncSession):
    """A state that has been successfully consumed MUST NOT validate a second time."""
    repo = OAuthStateRepository(isolated_session)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    await repo.create_state(
        state_token="anti-replay-token-001",
        tenant_id="tenant-regression",
        agent_id="agent-regression",
        provider="google",
        requested_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        redirect_uri="https://example.com/callback",
        expires_at=expires_at,
    )
    await isolated_session.commit()

    first = await repo.validate_and_consume_state("anti-replay-token-001")
    assert first is not None, "First consumption MUST succeed."

    second = await repo.validate_and_consume_state("anti-replay-token-001")
    assert second is None, "Replayed state token MUST be rejected."


# ---------------------------------------------------------------------------
# Multi-session simulation: separate write and read sessions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_state_valid_across_separate_db_sessions():
    """
    Simulate the production request pattern: one DB session writes the state
    (the /start request), a separate DB session reads and validates it (the
    /callback request).  The timezone-aware expires_at must survive the
    round-trip and still compare correctly against datetime.now(timezone.utc).
    """
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    # --- Session A: /start request creates the state ---
    async with factory() as session_a:
        repo_a = OAuthStateRepository(session_a)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        await repo_a.create_state(
            state_token="cross-session-token-001",
            tenant_id="tenant-cross",
            agent_id="agent-cross",
            provider="google",
            requested_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            redirect_uri="https://example.com/callback",
            expires_at=expires_at,
        )
        await session_a.commit()

    # --- Session B: /callback request validates the state ---
    async with factory() as session_b:
        repo_b = OAuthStateRepository(session_b)
        result = await repo_b.validate_and_consume_state("cross-session-token-001")
        assert result is not None, (
            "State stored in session A MUST be valid when validated in session B. "
            "A naive datetime stored by the old code would fail here on some DB "
            "configurations."
        )
        await session_b.commit()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Timezone offset simulation: verify aware comparison is stable regardless
# of local system timezone or an offset-aware expires_at value
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_state_valid_with_explicit_utc_offset_expires_at():
    """
    Even if expires_at is stored with an explicit UTC+0 offset (as opposed to
    a naive timestamp), validation MUST succeed because both sides are
    timezone-aware UTC values.
    """
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    # Simulate a +00:00 offset-aware datetime (same instant, different tzinfo object)
    utc_offset = timezone(timedelta(hours=0))
    expires_at = datetime.now(utc_offset) + timedelta(minutes=10)

    async with factory() as session:
        repo = OAuthStateRepository(session)
        await repo.create_state(
            state_token="tz-offset-token-001",
            tenant_id="tenant-tz",
            agent_id="agent-tz",
            provider="google",
            requested_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            redirect_uri="https://example.com/callback",
            expires_at=expires_at,
        )
        await session.commit()

        result = await repo.validate_and_consume_state("tz-offset-token-001")
        assert result is not None, (
            "State with explicit UTC+0 offset expires_at MUST validate correctly."
        )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Provider layer: refresh_access_token must return timezone-aware expiry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_refresh_access_token_returns_tz_aware_expiry(monkeypatch):
    """
    GoogleOAuthHandler.refresh_access_token must return a timezone-aware
    datetime as the expiry. Previously it used datetime.utcnow() which
    returns a naive datetime.
    """
    import httpx

    class MockResponse:
        status_code = 200

        def json(self):
            return {"access_token": "refreshed-token", "expires_in": 3600}

    class MockClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockClient())

    handler = GoogleOAuthHandler(
        client_id="test-client-id",
        client_secret="test-client-secret",
        redirect_uri="https://example.com/callback",
    )

    new_token, expiry = await handler.refresh_access_token("mock-refresh-token")
    assert new_token == "refreshed-token"
    assert expiry.tzinfo is not None, (
        "refresh_access_token MUST return a timezone-aware datetime. "
        "naive datetime.utcnow() was the bug."
    )
    assert expiry > datetime.now(timezone.utc), "Expiry must be in the future."


# ---------------------------------------------------------------------------
# API-level regression: /start endpoint produces immediately-valid state
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_start_state_is_immediately_valid_in_db(async_client: AsyncClient, db_session: AsyncSession):
    """
    Calling /start and then immediately calling /callback with the returned
    state MUST succeed. This is the canonical end-to-end regression test for
    the naive-datetime bug.
    """
    from app.providers.gmail.oauth import GoogleOAuthHandler

    start_resp = await async_client.get("/online/email/oauth/google/start")
    assert start_resp.status_code == 200, f"Start failed: {start_resp.text}"
    state_token = start_resp.json()["state"]

    async def mock_exchange(self, code: str):
        return {
            "access_token": "regression-access-token",
            "refresh_token": "regression-refresh-token",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email",
        }

    async def mock_user_profile(self, access_token: str):
        return {"email": "regression.test@example.com", "id": "regression-id-001"}

    import pytest
    # Use monkeypatch-style attribute replacement since we don't have monkeypatch here;
    # save originals and restore manually.
    original_exchange = GoogleOAuthHandler.exchange_code_for_tokens
    original_profile = GoogleOAuthHandler.get_user_profile
    GoogleOAuthHandler.exchange_code_for_tokens = mock_exchange
    GoogleOAuthHandler.get_user_profile = mock_user_profile

    try:
        callback_resp = await async_client.get(
            "/online/email/oauth/google/callback",
            params={"code": "regression-code-001", "state": state_token},
        )
    finally:
        GoogleOAuthHandler.exchange_code_for_tokens = original_exchange
        GoogleOAuthHandler.get_user_profile = original_profile

    assert callback_resp.status_code == 200, (
        f"Callback MUST succeed for a freshly created state token. "
        f"If this returns 403, the naive datetime bug is still present. "
        f"Response: {callback_resp.text}"
    )
    data = callback_resp.json()
    assert data["status"] == "success"
    assert data["email"] == "regression.test@example.com"
    # Security: raw tokens MUST NOT be returned
    assert "access_token" not in data
    assert "refresh_token" not in data
