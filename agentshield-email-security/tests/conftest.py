"""Pytest test configuration, fixtures, and database lifecycle management."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.config import Settings, get_settings
from app.database.models import Base, OAuthAccount
from app.downloads.models import SecureDownload  # noqa: F401
from app.database.repository import OAuthAccountRepository
from app.database.session import get_db
from app.main import create_app
from app.security.token_crypto import TokenCrypto

# Use in-memory SQLite database for isolated test execution
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
test_session_factory = async_sessionmaker(
    bind=test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest.fixture(scope="session")
def event_loop():
    """Create session-scoped event loop for pytest-asyncio."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide isolated in-memory test database session per test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with test_session_factory() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def test_crypto() -> TokenCrypto:
    """Deterministic token crypto helper for testing."""
    return TokenCrypto(key=b"VGVzdEVuY3J5cHRpb25LZXkxMjM0NTY3ODkwMTI=")


@pytest_asyncio.fixture
async def seed_oauth_account(db_session: AsyncSession) -> OAuthAccount:
    """Seed test OAuth account with read and send scopes."""
    repo = OAuthAccountRepository(db_session)
    account = await repo.create_or_update_account(
        tenant_id="test-tenant",
        agent_id="test-agent",
        provider="google",
        account_email="agent.test@example.com",
        access_token="mock-valid-access-token",
        refresh_token="mock-valid-refresh-token",
        token_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        granted_scopes=[
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
    )
    await db_session.commit()
    return account


@pytest_asyncio.fixture
async def seed_readonly_account(db_session: AsyncSession) -> OAuthAccount:
    """Seed test OAuth account with read-only scope only."""
    repo = OAuthAccountRepository(db_session)
    account = await repo.create_or_update_account(
        tenant_id="test-tenant",
        agent_id="test-agent",
        provider="google",
        account_email="readonly.agent@example.com",
        access_token="mock-readonly-access-token",
        refresh_token="mock-readonly-refresh-token",
        token_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        granted_scopes=[
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
    )
    await db_session.commit()
    return account


@pytest_asyncio.fixture
async def async_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """HTTPX test client with DB override and default test gateway headers."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    headers = {
        "Authorization": "Bearer dev-secret-token",
        "X-Tenant-ID": "test-tenant",
        "X-Agent-ID": "test-agent",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as client:
        yield client
