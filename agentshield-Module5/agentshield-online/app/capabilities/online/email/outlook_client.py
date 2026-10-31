"""
Microsoft Graph (Outlook) client.
Separate from Gmail — provider-specific code is isolated.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.capabilities.online.email.oauth_manager import OutlookOAuthManager
from app.core.exceptions import EmailError, OAuthError
from app.core.result_models import EmailMessage, EmailSendResult, DraftResult

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class OutlookClient:
    """Microsoft Graph email client."""

    def __init__(self, oauth_manager: OutlookOAuthManager) -> None:
        self._oauth = oauth_manager

    def _auth_headers(self) -> dict[str, str]:
        token = self._oauth.get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    async def list_messages(
        self,
        query: str = "",
        max_results: int = 10,
    ) -> list[EmailMessage]:
        """List inbox messages, optionally filtered by query."""
        try:
            params: dict[str, Any] = {"$top": max_results, "$select": "id,subject,from,toRecipients,receivedDateTime,bodyPreview,hasAttachments"}
            if query:
                params["$search"] = f'"{query}"'
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{GRAPH_BASE}/me/messages",
                    params=params,
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
                data = resp.json()

            messages = []
            for item in data.get("value", []):
                sender = item.get("from", {}).get("emailAddress", {}).get("address", "")
                to_recipients = [
                    r["emailAddress"]["address"]
                    for r in item.get("toRecipients", [])
                ]
                messages.append(
                    EmailMessage(
                        message_id=item["id"],
                        subject=item.get("subject", "(no subject)"),
                        sender=sender,
                        recipients=to_recipients,
                        date=item.get("receivedDateTime", ""),
                        body_snippet=item.get("bodyPreview", ""),
                        has_attachments=item.get("hasAttachments", False),
                    )
                )
            return messages
        except (OAuthError, EmailError):
            raise
        except Exception as e:
            raise EmailError(f"Outlook list messages failed: {e}")

    async def get_message_body(self, message_id: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{GRAPH_BASE}/me/messages/{message_id}",
                    params={"$select": "body"},
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
                data = resp.json()
            return data.get("body", {}).get("content", "")
        except (OAuthError, EmailError):
            raise
        except Exception as e:
            raise EmailError(f"Outlook get message body failed: {e}")

    async def create_draft(
        self,
        to: list[str],
        subject: str,
        body: str,
        sender: str = "",
    ) -> DraftResult:
        payload = {
            "subject": subject,
            "body": {"contentType": "Text", "content": body},
            "toRecipients": [{"emailAddress": {"address": r}} for r in to],
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{GRAPH_BASE}/me/messages",
                    json=payload,
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
                data = resp.json()
            return DraftResult(
                draft_id=data["id"],
                subject=subject,
                recipients=to,
            )
        except (OAuthError, EmailError):
            raise
        except Exception as e:
            raise EmailError(f"Outlook draft creation failed: {e}")

    async def send_message(
        self,
        to: list[str],
        subject: str,
        body: str,
        sender: str = "",
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
    ) -> EmailSendResult:
        """Send via Graph API. Must be called after gateway approval only."""
        payload: dict[str, Any] = {
            "message": {
                "subject": subject,
                "body": {"contentType": "Text", "content": body},
                "toRecipients": [{"emailAddress": {"address": r}} for r in to],
            },
            "saveToSentItems": True,
        }
        if cc:
            payload["message"]["ccRecipients"] = [
                {"emailAddress": {"address": r}} for r in cc
            ]
        if bcc:
            payload["message"]["bccRecipients"] = [
                {"emailAddress": {"address": r}} for r in bcc
            ]
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{GRAPH_BASE}/me/sendMail",
                    json=payload,
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
            return EmailSendResult(
                message_id="graph_sent",
                status="sent",
            )
        except (OAuthError, EmailError):
            raise
        except Exception as e:
            raise EmailError(f"Outlook send failed: {e}")

    def is_available(self) -> bool:
        return self._oauth.is_configured()
