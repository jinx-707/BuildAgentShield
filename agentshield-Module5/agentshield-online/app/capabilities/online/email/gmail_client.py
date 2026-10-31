"""
Gmail API client — wraps google-api-python-client for email operations.
Requires completed OAuth flow via GmailOAuthManager.
"""
from __future__ import annotations

import base64
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from app.capabilities.online.email.oauth_manager import GmailOAuthManager
from app.core.exceptions import EmailError, OAuthError
from app.core.result_models import EmailMessage, EmailSendResult, DraftResult

logger = logging.getLogger(__name__)


class GmailClient:
    """
    Gmail API client with least-privilege OAuth scopes.
    Does not store passwords or raw credentials.
    """

    def __init__(self, oauth_manager: GmailOAuthManager) -> None:
        self._oauth = oauth_manager

    def _service(self) -> Any:
        try:
            from googleapiclient.discovery import build
            creds = self._oauth.get_credentials()
            return build("gmail", "v1", credentials=creds)
        except OAuthError:
            raise
        except Exception as e:
            raise EmailError(f"Gmail service build failed: {e}")

    async def list_messages(
        self,
        query: str = "",
        max_results: int = 10,
    ) -> list[EmailMessage]:
        """Search/list Gmail messages."""
        try:
            svc = self._service()
            resp = svc.users().messages().list(
                userId="me",
                q=query,
                maxResults=max_results,
            ).execute()

            messages = []
            for msg_ref in resp.get("messages", []):
                msg = await self._get_message(svc, msg_ref["id"])
                if msg:
                    messages.append(msg)
            return messages
        except (OAuthError, EmailError):
            raise
        except Exception as e:
            raise EmailError(f"Gmail list failed: {e}")

    async def _get_message(self, svc: Any, message_id: str) -> EmailMessage | None:
        try:
            msg = svc.users().messages().get(
                userId="me",
                id=message_id,
                format="metadata",
                metadataHeaders=["From", "To", "Subject", "Date"],
            ).execute()

            headers = {
                h["name"]: h["value"]
                for h in msg.get("payload", {}).get("headers", [])
            }
            return EmailMessage(
                message_id=message_id,
                thread_id=msg.get("threadId", ""),
                subject=headers.get("Subject", "(no subject)"),
                sender=headers.get("From", ""),
                recipients=[headers.get("To", "")],
                date=headers.get("Date", ""),
                body_snippet=msg.get("snippet", ""),
                has_attachments=self._has_attachments(msg),
            )
        except Exception as e:
            logger.warning("Could not fetch message %s: %s", message_id, e)
            return None

    def _has_attachments(self, msg: dict[str, Any]) -> bool:
        payload = msg.get("payload", {})
        parts = payload.get("parts", [])
        return any(p.get("filename") for p in parts)

    async def get_message_body(self, message_id: str) -> str:
        """Get the full decoded body of a message."""
        try:
            svc = self._service()
            msg = svc.users().messages().get(
                userId="me",
                id=message_id,
                format="full",
            ).execute()

            payload = msg.get("payload", {})
            body = self._extract_body(payload)
            return body
        except (OAuthError, EmailError):
            raise
        except Exception as e:
            raise EmailError(f"Gmail get body failed: {e}")

    def _extract_body(self, payload: dict[str, Any]) -> str:
        if "parts" in payload:
            for part in payload["parts"]:
                if part.get("mimeType") == "text/plain":
                    data = part.get("body", {}).get("data", "")
                    return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
        data = payload.get("body", {}).get("data", "")
        if data:
            return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
        return ""

    async def create_draft(
        self,
        to: list[str],
        subject: str,
        body: str,
        sender: str = "me",
    ) -> DraftResult:
        """Create a draft (does not send)."""
        try:
            svc = self._service()
            msg = self._build_message(to=to, subject=subject, body=body, sender=sender)
            draft = svc.users().drafts().create(
                userId="me",
                body={"message": {"raw": msg}},
            ).execute()
            return DraftResult(
                draft_id=draft["id"],
                subject=subject,
                recipients=to,
            )
        except (OAuthError, EmailError):
            raise
        except Exception as e:
            raise EmailError(f"Gmail draft creation failed: {e}")

    async def send_message(
        self,
        to: list[str],
        subject: str,
        body: str,
        sender: str = "me",
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
    ) -> EmailSendResult:
        """Send an email. Should only be called AFTER full gateway approval."""
        try:
            svc = self._service()
            raw = self._build_message(
                to=to, subject=subject, body=body,
                sender=sender, cc=cc, bcc=bcc,
            )
            sent = svc.users().messages().send(
                userId="me",
                body={"raw": raw},
            ).execute()
            return EmailSendResult(
                message_id=sent["id"],
                status="sent",
            )
        except (OAuthError, EmailError):
            raise
        except Exception as e:
            raise EmailError(f"Gmail send failed: {e}")

    def _build_message(
        self,
        to: list[str],
        subject: str,
        body: str,
        sender: str = "me",
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
    ) -> str:
        msg = MIMEMultipart()
        msg["to"] = ", ".join(to)
        msg["subject"] = subject
        if sender != "me":
            msg["from"] = sender
        if cc:
            msg["cc"] = ", ".join(cc)
        if bcc:
            msg["bcc"] = ", ".join(bcc)
        msg.attach(MIMEText(body, "plain"))
        return base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

    def is_available(self) -> bool:
        return self._oauth.is_configured()
