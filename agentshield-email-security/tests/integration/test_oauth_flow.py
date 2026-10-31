"""Integration tests for Google OAuth 2.0 flow and token lifecycle."""

import pytest
from httpx import AsyncClient
from app.providers.gmail.oauth import GoogleOAuthHandler


@pytest.mark.asyncio
async def test_oauth_start_success(async_client: AsyncClient):
    response = await async_client.get("/online/email/oauth/google/start")
    assert response.status_code == 200
    data = response.json()
    assert "authorization_url" in data
    assert "state" in data
    assert "https://accounts.google.com/o/oauth2/v2/auth" in data["authorization_url"]
    assert "gmail.readonly" in data["authorization_url"]
    assert "gmail.send" in data["authorization_url"]
    assert "gmail.compose" in data["authorization_url"]
    assert "userinfo.email" in data["authorization_url"]
    # Confirm gmail.send is present in the scopes list returned to the caller
    assert "https://www.googleapis.com/auth/gmail.send" in data["scopes"]


@pytest.mark.asyncio
async def test_oauth_start_rejects_disallowed_scopes(async_client: AsyncClient):
    # Try requesting a dangerous or non-email scope (e.g. drive or root access)
    response = await async_client.get(
        "/online/email/oauth/google/start",
        params={"scopes": "https://www.googleapis.com/auth/drive.readonly"},
    )
    assert response.status_code == 400
    assert "not allowed by security policy" in response.json()["detail"]


@pytest.mark.asyncio
async def test_oauth_callback_rejects_invalid_state(async_client: AsyncClient):
    response = await async_client.get(
        "/online/email/oauth/google/callback",
        params={"code": "dummy-auth-code", "state": "forged-or-nonexistent-state"},
    )
    assert response.status_code == 403
    assert "Invalid, expired, or reused CSRF state token" in response.json()["detail"]


@pytest.mark.asyncio
async def test_oauth_callback_successful_exchange(async_client: AsyncClient, monkeypatch):
    # 1. Start flow to get valid state token stored in DB
    start_resp = await async_client.get("/online/email/oauth/google/start")
    state_token = start_resp.json()["state"]

    # 2. Mock GoogleOAuthHandler methods so we don't hit external Google servers in tests
    async def mock_exchange(self, code: str):
        return {
            "access_token": "mock-real-access-token",
            "refresh_token": "mock-real-refresh-token",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email",
        }

    async def mock_user_profile(self, access_token: str):
        return {"email": "authorized.user@company.com", "id": "12345"}

    monkeypatch.setattr(GoogleOAuthHandler, "exchange_code_for_tokens", mock_exchange)
    monkeypatch.setattr(GoogleOAuthHandler, "get_user_profile", mock_user_profile)

    # 3. Call callback endpoint
    callback_resp = await async_client.get(
        "/online/email/oauth/google/callback",
        params={"code": "valid-google-code", "state": state_token},
    )

    assert callback_resp.status_code == 200
    data = callback_resp.json()
    assert data["status"] == "success"
    assert data["email"] == "authorized.user@company.com"
    assert data["provider"] == "google"
    assert "account_id" in data

    # STRICT SECURITY ASSERTION: No tokens returned to AI agent / caller!
    assert "access_token" not in data
    assert "refresh_token" not in data
    assert "encrypted_access_token" not in data


@pytest.mark.asyncio
async def test_oauth_state_cannot_be_replayed(async_client: AsyncClient, monkeypatch):
    # Start flow
    start_resp = await async_client.get("/online/email/oauth/google/start")
    state_token = start_resp.json()["state"]

    async def mock_exchange(self, code: str):
        return {"access_token": "mock-token", "expires_in": 3600}

    async def mock_user_profile(self, access_token: str):
        return {"email": "user@example.com"}

    monkeypatch.setattr(GoogleOAuthHandler, "exchange_code_for_tokens", mock_exchange)
    monkeypatch.setattr(GoogleOAuthHandler, "get_user_profile", mock_user_profile)

    # First consumption succeeds
    first = await async_client.get(
        "/online/email/oauth/google/callback",
        params={"code": "code1", "state": state_token},
    )
    assert first.status_code == 200

    # Second consumption of the same state MUST fail (anti-replay CSRF protection)
    second = await async_client.get(
        "/online/email/oauth/google/callback",
        params={"code": "code2", "state": state_token},
    )
    assert second.status_code == 403



@pytest.mark.asyncio
async def test_oauth_start_includes_send_scope_in_url_and_response(async_client: AsyncClient):
    """gmail.send MUST appear in both the authorization URL and the returned scopes list."""
    response = await async_client.get("/online/email/oauth/google/start")
    assert response.status_code == 200
    data = response.json()

    send_scope = "https://www.googleapis.com/auth/gmail.send"
    assert send_scope in data["scopes"], (
        "gmail.send must be present in the scopes list returned by /oauth/google/start"
    )
    assert "gmail.send" in data["authorization_url"], (
        "gmail.send must be encoded in the Google authorization URL"
    )


@pytest.mark.asyncio
async def test_oauth_callback_persists_send_scope(async_client: AsyncClient, monkeypatch):
    """When Google grants gmail.send, it must be stored in granted_scopes on the account."""
    # 1. Start OAuth flow (defaults now include gmail.send)
    start_resp = await async_client.get("/online/email/oauth/google/start")
    assert start_resp.status_code == 200
    state_token = start_resp.json()["state"]

    # 2. Simulate Google granting the full default scope set including gmail.send
    async def mock_exchange(self, code: str):
        return {
            "access_token": "mock-send-access-token",
            "refresh_token": "mock-send-refresh-token",
            "expires_in": 3600,
            "scope": (
                "https://www.googleapis.com/auth/gmail.readonly "
                "https://www.googleapis.com/auth/gmail.send "
                "https://www.googleapis.com/auth/gmail.compose "
                "https://www.googleapis.com/auth/userinfo.email"
            ),
        }

    async def mock_user_profile(self, access_token: str):
        return {"email": "sender@example.com", "id": "99999"}

    monkeypatch.setattr(GoogleOAuthHandler, "exchange_code_for_tokens", mock_exchange)
    monkeypatch.setattr(GoogleOAuthHandler, "get_user_profile", mock_user_profile)

    # 3. Complete the callback
    callback_resp = await async_client.get(
        "/online/email/oauth/google/callback",
        params={"code": "valid-send-code", "state": state_token},
    )
    assert callback_resp.status_code == 200
    data = callback_resp.json()
    assert data["status"] == "success"

    # 4. gmail.send MUST appear in the persisted granted_scopes returned by the callback
    assert "https://www.googleapis.com/auth/gmail.send" in data["granted_scopes"], (
        "gmail.send granted by Google must be persisted in granted_scopes"
    )

    # STRICT SECURITY ASSERTION: tokens must never be exposed to the caller
    assert "access_token" not in data
    assert "refresh_token" not in data
    assert "encrypted_access_token" not in data
