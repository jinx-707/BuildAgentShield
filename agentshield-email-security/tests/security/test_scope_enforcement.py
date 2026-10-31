"""Security tests for OAuth scope enforcement (least privilege principle)."""

import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.models import OAuthAccount
from app.database.repository import OAuthAccountRepository


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def seed_compose_only_account(db_session: AsyncSession) -> OAuthAccount:
    """OAuth account that has gmail.compose but NOT gmail.send.

    Drafts should be allowed; sends must be blocked with OAUTH_SCOPE_INSUFFICIENT.
    """
    repo = OAuthAccountRepository(db_session)
    account = await repo.create_or_update_account(
        tenant_id="test-tenant",
        agent_id="test-agent",
        provider="google",
        account_email="compose.only@example.com",
        access_token="mock-compose-access-token",
        refresh_token="mock-compose-refresh-token",
        token_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        granted_scopes=[
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
    )
    await db_session.commit()
    return account


# ---------------------------------------------------------------------------
# Tests: send blocked by insufficient scope
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_send_blocked_when_account_only_has_readonly_scope(
    async_client: AsyncClient, seed_readonly_account: OAuthAccount
):
    """Attempting to send an email with an account that only has gmail.readonly MUST be blocked."""
    payload = {
        "account_id": str(seed_readonly_account.id),
        "to": [{"email": "colleague@example.com"}],
        "subject": "Unauthorized send attempt",
        "body_text": "This should be blocked due to insufficient OAuth scope.",
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert "detail" in data
    assert "scope" in str(data["detail"]).lower() or "OAUTH_SCOPE_INSUFFICIENT" in str(data["detail"])


@pytest.mark.asyncio
async def test_send_blocked_when_account_has_compose_but_not_send_scope(
    async_client: AsyncClient, seed_compose_only_account: OAuthAccount
):
    """gmail.compose does NOT grant the ability to send.

    An account holding only gmail.readonly + gmail.compose (but not gmail.send,
    gmail.modify, or mail.google.com) must be rejected with OAUTH_SCOPE_INSUFFICIENT
    when attempting POST /online/email/send.
    """
    payload = {
        "account_id": str(seed_compose_only_account.id),
        "to": [{"email": "target@example.com"}],
        "subject": "Scope boundary test",
        "body_text": "Compose scope should not permit sending.",
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert "detail" in data
    assert "scope" in str(data["detail"]).lower() or "OAUTH_SCOPE_INSUFFICIENT" in str(data["detail"])


# ---------------------------------------------------------------------------
# Tests: draft blocked by insufficient scope
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_draft_blocked_when_account_only_has_readonly_scope(
    async_client: AsyncClient, seed_readonly_account: OAuthAccount
):
    """Attempting to compose a draft with an account that only has gmail.readonly MUST be blocked."""
    payload = {
        "account_id": str(seed_readonly_account.id),
        "to": [{"email": "colleague@example.com"}],
        "subject": "Unauthorized draft attempt",
        "body_text": "This should be blocked due to lack of compose/modify scope.",
    }
    response = await async_client.post("/online/email/draft", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert "detail" in data
    assert "compose" in str(data["detail"]).lower() or "OAUTH_SCOPE_INSUFFICIENT" in str(data["detail"])
