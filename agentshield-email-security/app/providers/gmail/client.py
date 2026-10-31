"""Gmail API client adapter implementing BaseEmailProvider."""

import base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
import logging
from typing import Any, Dict, List, Optional, Tuple
import httpx
from app.providers.base import (
    BaseEmailProvider,
    ProviderAuthenticationError,
    ProviderError,
    ProviderNotFoundError,
    ProviderRateLimitError,
)
from app.providers.gmail.message_parser import GmailMessageParser
from app.providers.gmail.oauth import GoogleOAuthHandler

logger = logging.getLogger("agentshield.gmail.client")

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"


class GmailClient(BaseEmailProvider):
    """Asynchronous Gmail API client communicating with Google REST endpoints."""

    def __init__(self, access_token: str, refresh_token: Optional[str] = None):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.oauth_handler = GoogleOAuthHandler()

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> Dict[str, Any]:
        url = f"{GMAIL_API_BASE}/{path.lstrip('/')}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.request(
                method, url, headers=self._headers(), params=params, json=json_data
            )

            # Handle token expiry (401)
            if resp.status_code == 401 and self.refresh_token:
                logger.info("Access token expired; refreshing...")
                try:
                    new_token, _ = await self.oauth_handler.refresh_access_token(self.refresh_token)
                    self.access_token = new_token
                    # Retry request with refreshed token
                    resp = await client.request(
                        method, url, headers=self._headers(), params=params, json=json_data
                    )
                except Exception as e:
                    logger.error(f"Failed to refresh token during request: {e}")
                    raise ProviderAuthenticationError("OAuth access token expired and refresh failed") from e

            if resp.status_code == 401:
                raise ProviderAuthenticationError("Invalid or expired Google OAuth credentials")
            elif resp.status_code == 429:
                raise ProviderRateLimitError("Gmail API rate limit exceeded (HTTP 429)")
            elif resp.status_code == 404:
                raise ProviderNotFoundError(f"Resource not found: {path}")
            elif resp.status_code >= 500:
                raise ProviderError(f"Gmail API server error {resp.status_code}: {resp.text}")
            elif resp.status_code >= 400:
                raise ProviderError(f"Gmail API error {resp.status_code}: {resp.text}")

            return resp.json() if resp.content else {}

    async def get_profile(self) -> Dict[str, Any]:
        return await self._request("GET", "profile")

    async def list_messages(
        self,
        query: Optional[str] = None,
        max_results: int = 10,
        page_token: Optional[str] = None,
        include_spam_trash: bool = False,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        params = {
            "maxResults": min(max_results, 50),
            "includeSpamTrash": str(include_spam_trash).lower(),
        }
        if query:
            params["q"] = query
        if page_token:
            params["pageToken"] = page_token

        data = await self._request("GET", "messages", params=params)
        messages_meta = data.get("messages", [])
        next_page = data.get("nextPageToken")

        hydrated: List[Dict[str, Any]] = []
        for m in messages_meta:
            msg_id = m.get("id")
            if msg_id:
                try:
                    full_msg = await self.get_message(msg_id)
                    hydrated.append(full_msg)
                except Exception as e:
                    logger.warning(f"Failed to fetch message {msg_id}: {e}")

        return hydrated, next_page

    async def get_message(self, message_id: str) -> Dict[str, Any]:
        return await self._request("GET", f"messages/{message_id}", params={"format": "full"})

    async def get_draft(self, draft_id: str) -> Dict[str, Any]:
        return await self._request("GET", f"drafts/{draft_id}", params={"format": "full"})

    @staticmethod
    def _build_mime_message(
        to: List[str],
        cc: List[str],
        bcc: List[str],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Create RFC 2822 base64url encoded MIME message."""
        msg = MIMEMultipart("mixed")
        msg["Subject"] = subject
        msg["To"] = ", ".join(to)
        if cc:
            msg["Cc"] = ", ".join(cc)
        if bcc:
            msg["Bcc"] = ", ".join(bcc)

        alt_part = MIMEMultipart("alternative")
        alt_part.attach(MIMEText(body_text, "plain", "utf-8"))
        if body_html:
            alt_part.attach(MIMEText(body_html, "html", "utf-8"))
        msg.attach(alt_part)

        if attachments:
            for att in attachments:
                part = MIMEBase("application", "octet-stream")
                content = base64.b64decode(att["content_base64"])
                part.set_payload(content)
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition", f"attachment; filename=\"{att['filename']}\""
                )
                msg.attach(part)

        raw_bytes = msg.as_bytes()
        return base64.urlsafe_b64encode(raw_bytes).decode("ascii")

    async def create_draft(
        self,
        to: List[str],
        cc: List[str],
        bcc: List[str],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        thread_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        raw_msg = self._build_mime_message(to, cc, bcc, subject, body_text, body_html)
        payload = {"message": {"raw": raw_msg}}
        if thread_id:
            payload["message"]["threadId"] = thread_id
        return await self._request("POST", "drafts", json_data=payload)

    async def update_draft(
        self,
        draft_id: str,
        to: List[str],
        cc: List[str],
        bcc: List[str],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        thread_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        raw_msg = self._build_mime_message(to, cc, bcc, subject, body_text, body_html)
        payload = {"id": draft_id, "message": {"raw": raw_msg}}
        if thread_id:
            payload["message"]["threadId"] = thread_id
        return await self._request("PUT", f"drafts/{draft_id}", json_data=payload)

    async def send_draft(self, draft_id: str) -> Dict[str, Any]:
        payload = {"id": draft_id}
        return await self._request("POST", "drafts/send", json_data=payload)

    async def send_email(
        self,
        to: List[str],
        cc: List[str],
        bcc: List[str],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        thread_id: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        raw_msg = self._build_mime_message(to, cc, bcc, subject, body_text, body_html, attachments)
        payload = {"raw": raw_msg}
        if thread_id:
            payload["threadId"] = thread_id
        return await self._request("POST", "messages/send", json_data=payload)

    async def forward_email(
        self,
        original_message_id: str,
        to: List[str],
        cc: List[str],
        additional_comment: Optional[str] = None,
        forward_attachments: bool = True,
    ) -> Dict[str, Any]:
        orig = await self.get_message(original_message_id)
        parsed = GmailMessageParser.to_email_message(orig)

        forward_subject = f"Fwd: {parsed.subject}"
        comment_header = f"{additional_comment}\n\n" if additional_comment else ""
        forward_body = (
            f"{comment_header}"
            f"---------- Forwarded message ---------\n"
            f"From: {parsed.sender.email}\n"
            f"Subject: {parsed.subject}\n"
            f"Date: {parsed.received_at}\n\n"
            f"{parsed.body_text or parsed.snippet}"
        )

        return await self.send_email(
            to=to,
            cc=cc,
            bcc=[],
            subject=forward_subject,
            body_text=forward_body,
        )

    async def get_attachment(self, message_id: str, attachment_id: str) -> Dict[str, Any]:
        return await self._request("GET", f"messages/{message_id}/attachments/{attachment_id}")

    async def revoke_access(self) -> bool:
        return await self.oauth_handler.revoke_token(self.access_token)
