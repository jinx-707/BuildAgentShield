"""Abstract email provider interface contract for Gmail and Microsoft Graph adapters."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class ProviderError(Exception):
    """Base exception for email provider failures."""
    pass


class ProviderAuthenticationError(ProviderError):
    """Raised when provider credentials or OAuth token are invalid or expired."""
    pass


class ProviderNotFoundError(ProviderError):
    """Raised when requested email message, draft, or mailbox resource is not found."""
    pass


class ProviderRateLimitError(ProviderError):
    """Raised when provider returns HTTP 429 rate limit or quota exceeded."""
    pass


class BaseEmailProvider(ABC):
    """Uniform abstract interface that all email service adapters must implement."""

    @abstractmethod
    async def get_profile(self) -> Dict[str, Any]:
        """Fetch basic account metadata (email address, total messages, etc.)."""
        pass

    @abstractmethod
    async def list_messages(
        self,
        query: Optional[str] = None,
        max_results: int = 10,
        page_token: Optional[str] = None,
        include_spam_trash: bool = False,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """List messages matching query/folder criteria. Returns (messages, next_page_token)."""
        pass

    @abstractmethod
    async def get_message(self, message_id: str) -> Dict[str, Any]:
        """Fetch single raw/structured message by provider ID."""
        pass

    @abstractmethod
    async def get_draft(self, draft_id: str) -> Dict[str, Any]:
        """Fetch draft details by draft ID."""
        pass

    @abstractmethod
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
        """Create a draft message without transmitting it."""
        pass

    @abstractmethod
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
        """Update an existing draft."""
        pass

    @abstractmethod
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
        """Transmit an outbound email."""
        pass

    @abstractmethod
    async def send_draft(self, draft_id: str) -> Dict[str, Any]:
        """Send an existing draft."""
        pass

    @abstractmethod
    async def forward_email(
        self,
        original_message_id: str,
        to: List[str],
        cc: List[str],
        additional_comment: Optional[str] = None,
        forward_attachments: bool = True,
    ) -> Dict[str, Any]:
        """Forward an existing email to new recipients."""
        pass

    @abstractmethod
    async def get_attachment(self, message_id: str, attachment_id: str) -> Dict[str, Any]:
        """Retrieve attachment binary data and metadata from provider."""
        pass

    @abstractmethod
    async def revoke_access(self) -> bool:
        """Revoke OAuth tokens with the identity provider."""
        pass
