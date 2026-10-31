"""
OAuth token manager for Gmail and Microsoft Graph.
Handles token storage, refresh, expiration, and revocation.
Tokens are stored in files, NEVER in LLM context.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.core.exceptions import OAuthError

logger = logging.getLogger(__name__)


class GmailOAuthManager:
    """
    Manages Gmail OAuth 2.0 tokens.
    Uses google-auth-oauthlib for the OAuth flow.
    Requires GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET in environment.
    """

    SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.compose",
    ]

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        token_path: str = "./gmail_token.json",
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._token_path = Path(token_path)
        self._credentials: Any = None

    def get_authorization_url(self) -> str:
        """Generate OAuth authorization URL for user consent."""
        if not self._client_id:
            raise OAuthError("GMAIL_CLIENT_ID not configured")
        try:
            from google_auth_oauthlib.flow import Flow
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "redirect_uris": [self._redirect_uri],
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                    }
                },
                scopes=self.SCOPES,
            )
            flow.redirect_uri = self._redirect_uri
            auth_url, _ = flow.authorization_url(
                access_type="offline",
                include_granted_scopes="true",
            )
            return auth_url
        except ImportError:
            raise OAuthError("google-auth-oauthlib not installed")

    def exchange_code(self, code: str) -> None:
        """Exchange authorization code for tokens and save."""
        try:
            from google_auth_oauthlib.flow import Flow
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "redirect_uris": [self._redirect_uri],
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                    }
                },
                scopes=self.SCOPES,
            )
            flow.redirect_uri = self._redirect_uri
            flow.fetch_token(code=code)
            self._credentials = flow.credentials
            self._save_token()
        except Exception as e:
            raise OAuthError(f"Gmail OAuth code exchange failed: {e}")

    def get_credentials(self) -> Any:
        """Return valid credentials, refreshing if needed."""
        if self._credentials and self._credentials.valid:
            return self._credentials

        if self._token_path.exists():
            try:
                from google.oauth2.credentials import Credentials
                self._credentials = Credentials.from_authorized_user_file(
                    str(self._token_path), self.SCOPES
                )
            except Exception as e:
                raise OAuthError(f"Failed to load Gmail token: {e}")

        if self._credentials and self._credentials.expired and self._credentials.refresh_token:
            try:
                import google.auth.transport.requests
                self._credentials.refresh(google.auth.transport.requests.Request())
                self._save_token()
                return self._credentials
            except Exception as e:
                raise OAuthError(f"Gmail token refresh failed: {e}")

        if not self._credentials or not self._credentials.valid:
            raise OAuthError(
                "Gmail credentials not available. Complete OAuth flow at "
                "/online/email/oauth/callback"
            )

        return self._credentials

    def _save_token(self) -> None:
        """Save token to file (never logs the token value)."""
        if self._credentials:
            with open(self._token_path, "w") as f:
                f.write(self._credentials.to_json())
            logger.info("Gmail token saved to %s", self._token_path)

    def revoke(self) -> None:
        """Revoke the current token."""
        if self._credentials and self._credentials.token:
            try:
                import google.auth.transport.requests
                self._credentials.revoke(google.auth.transport.requests.Request())
                if self._token_path.exists():
                    os.remove(self._token_path)
                self._credentials = None
                logger.info("Gmail token revoked")
            except Exception as e:
                logger.error("Gmail token revocation failed: %s", e)

    def is_configured(self) -> bool:
        return bool(self._client_id and self._client_secret)


class OutlookOAuthManager:
    """
    Manages Microsoft Graph (Outlook) OAuth tokens via MSAL.
    Requires MSGRAPH_CLIENT_ID, MSGRAPH_CLIENT_SECRET, MSGRAPH_TENANT_ID.
    """

    SCOPES = [
        "https://graph.microsoft.com/Mail.Read",
        "https://graph.microsoft.com/Mail.Send",
    ]

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        redirect_uri: str,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._tenant_id = tenant_id
        self._redirect_uri = redirect_uri
        self._token_cache: dict[str, Any] = {}

    def get_authorization_url(self) -> tuple[str, str]:
        """Return (auth_url, state) for the OAuth flow."""
        if not self._client_id:
            raise OAuthError("MSGRAPH_CLIENT_ID not configured")
        try:
            import msal
            app = self._build_app()
            result = app.initiate_auth_code_flow(
                scopes=self.SCOPES,
                redirect_uri=self._redirect_uri,
            )
            return result["auth_uri"], result.get("state", "")
        except ImportError:
            raise OAuthError("msal package not installed")
        except Exception as e:
            raise OAuthError(f"MS Graph OAuth URL generation failed: {e}")

    def exchange_code(self, code: str, state: str) -> dict[str, Any]:
        """Exchange code for token."""
        try:
            app = self._build_app()
            result = app.acquire_token_by_authorization_code(
                code=code,
                scopes=self.SCOPES,
                redirect_uri=self._redirect_uri,
            )
            if "error" in result:
                raise OAuthError(f"MS Graph token error: {result.get('error_description', '')}")
            self._token_cache = result
            return result
        except OAuthError:
            raise
        except Exception as e:
            raise OAuthError(f"MS Graph code exchange failed: {e}")

    def get_access_token(self) -> str:
        """Return a valid access token."""
        if not self._client_id:
            raise OAuthError("MSGRAPH_CLIENT_ID not configured")
        try:
            app = self._build_app()
            accounts = app.get_accounts()
            if accounts:
                result = app.acquire_token_silent(
                    scopes=self.SCOPES,
                    account=accounts[0],
                )
                if result and "access_token" in result:
                    return result["access_token"]
            raise OAuthError(
                "Microsoft Graph credentials not available. "
                "Complete OAuth flow at /online/email/outlook/callback"
            )
        except OAuthError:
            raise
        except Exception as e:
            raise OAuthError(f"MS Graph token retrieval failed: {e}")

    def _build_app(self) -> Any:
        try:
            import msal
            return msal.ConfidentialClientApplication(
                client_id=self._client_id,
                client_credential=self._client_secret,
                authority=f"https://login.microsoftonline.com/{self._tenant_id}",
            )
        except ImportError:
            raise OAuthError("msal package not installed")

    def is_configured(self) -> bool:
        return bool(self._client_id and self._client_secret and self._tenant_id)
