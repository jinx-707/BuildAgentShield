"""Microsoft Graph Email provider adapter (interface designed for future implementation)."""

import logging
from typing import Any, Dict, List, Optional, Tuple
from app.providers.base import BaseEmailProvider

logger = logging.getLogger("agentshield.microsoft.client")


class MicrosoftGraphClient(BaseEmailProvider):
    """Microsoft 365 / Microsoft Graph API client adapter.

    Conforms to BaseEmailProvider contract. Integration implementation
    is scheduled for a future milestone.
    """

    def __init__(
        self,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    async def get_profile(self) -> Dict[str, Any]:
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

    async def list_messages(
        self,
        query: Optional[str] = None,
        max_results: int = 10,
        page_token: Optional[str] = None,
        include_spam_trash: bool = False,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

    async def get_message(self, message_id: str) -> Dict[str, Any]:
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

    async def get_draft(self, draft_id: str) -> Dict[str, Any]:
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

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
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

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
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

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
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

    async def send_draft(self, draft_id: str) -> Dict[str, Any]:
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

    async def forward_email(
        self,
        original_message_id: str,
        to: List[str],
        cc: List[str],
        additional_comment: Optional[str] = None,
        forward_attachments: bool = True,
    ) -> Dict[str, Any]:
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

    async def get_attachment(self, message_id: str, attachment_id: str) -> Dict[str, Any]:
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")

    async def revoke_access(self) -> bool:
        raise NotImplementedError("Microsoft Graph provider integration planned for future milestone.")
