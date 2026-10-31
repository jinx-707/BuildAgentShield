"""Google OAuth 2.0 implementation: CSRF-protected state generation, token exchange, refresh, and revocation."""

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode
import httpx
from app.config import get_settings

logger = logging.getLogger("agentshield.gmail.oauth")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


class GoogleOAuthHandler:
    """Manages secure Google OAuth 2.0 authorization flows."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
    ):
        settings = get_settings()
        self.client_id = client_id or settings.GOOGLE_CLIENT_ID
        self.client_secret = client_secret or settings.GOOGLE_CLIENT_SECRET
        self.redirect_uri = redirect_uri or settings.GOOGLE_REDIRECT_URI

    def generate_state_token(self, tenant_id: str, agent_id: str) -> str:
        """Generate a cryptographically secure, signed CSRF state token."""
        random_bytes = secrets.token_urlsafe(32)
        settings = get_settings()
        secret_key = settings.INTERNAL_SERVICE_TOKEN.encode("utf-8")
        signature = hmac.new(
            secret_key, f"{tenant_id}:{agent_id}:{random_bytes}".encode("utf-8"), hashlib.sha256
        ).hexdigest()[:16]
        return f"{random_bytes}_{signature}"

    def get_authorization_url(
        self,
        state_token: str,
        scopes: Optional[List[str]] = None,
    ) -> str:
        """Construct the Google OAuth 2.0 consent URL requesting offline access."""
        settings = get_settings()
        effective_scopes = scopes or settings.DEFAULT_OAUTH_SCOPES

        # Filter against allowed scopes to prevent scope creep
        allowed = set(settings.ALLOWED_OAUTH_SCOPES)
        clean_scopes = [s for s in effective_scopes if s in allowed]
        if not clean_scopes:
            clean_scopes = settings.DEFAULT_OAUTH_SCOPES

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(clean_scopes),
            "access_type": "offline",  # Request refresh token
            "prompt": "consent",       # Force consent so refresh token is returned
            "state": state_token,
            "include_granted_scopes": "true",
        }
        return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

    async def exchange_code_for_tokens(
        self, code: str
    ) -> Dict[str, any]:
        """Exchange authorization code for access and refresh tokens."""
        if not self.client_id or not self.client_secret:
            raise ValueError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be configured")

        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(GOOGLE_TOKEN_URL, data=data)
            if resp.status_code != 200:
                logger.error(f"Failed to exchange Google OAuth code: {resp.status_code} {resp.text}")
                raise ValueError(f"Google OAuth token exchange failed: {resp.text}")
            return resp.json()

    async def refresh_access_token(self, refresh_token: str) -> Tuple[str, datetime]:
        """Use refresh token to obtain a fresh access token."""
        data = {
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(GOOGLE_TOKEN_URL, data=data)
            if resp.status_code != 200:
                logger.error(f"Failed to refresh Google token: {resp.status_code}")
                raise ValueError("Token refresh failed: token may have been revoked")

            token_data = resp.json()
            new_access_token = token_data["access_token"]
            expires_in = token_data.get("expires_in", 3600)
            expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            return new_access_token, expiry

    async def get_user_profile(self, access_token: str) -> Dict[str, any]:
        """Retrieve the primary email address and profile of the authorized account."""
        headers = {"Authorization": f"Bearer {access_token}"}
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(GOOGLE_USERINFO_URL, headers=headers)
            if resp.status_code != 200:
                raise ValueError(f"Failed to retrieve user profile: {resp.status_code}")
            return resp.json()

    async def revoke_token(self, token: str) -> bool:
        """Revoke OAuth access or refresh token with Google."""
        params = {"token": token}
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(GOOGLE_REVOKE_URL, params=params)
            return resp.status_code == 200

