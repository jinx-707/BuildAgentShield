"""InspectionClient interface and remote HTTP client for DLP and content inspection."""

import base64
import logging
from abc import ABC, abstractmethod
from typing import Optional, Union
import httpx
from app.config import get_settings
from app.schemas.email import EmailDraftRequest, EmailMessage, EmailSendRequest
from app.schemas.security import InspectionResult

logger = logging.getLogger("agentshield.email.inspection")


class InspectionError(Exception):
    """Raised when inspection detects severe policy or DLP violations."""
    pass


class InspectionServiceUnavailableError(InspectionError):
    """Raised when remote inspection service is unreachable (fail-closed requirement)."""
    pass


class BaseInspectionClient(ABC):
    """Abstract interface contract for DLP, PII, and prompt-injection inspection."""

    @abstractmethod
    async def inspect_incoming_email(self, email: EmailMessage) -> InspectionResult:
        """Inspect inbound email for indirect prompt injections, phishing, and malware links."""
        pass

    @abstractmethod
    async def inspect_outgoing_email(
        self, draft: Union[EmailDraftRequest, EmailSendRequest]
    ) -> InspectionResult:
        """Inspect outbound email body and subject for confidential data leakage (DLP/PII)."""
        pass

    @abstractmethod
    async def inspect_attachment(
        self, filename: str, content_type: str, data: bytes
    ) -> InspectionResult:
        """Inspect attachment content for embedded malicious scripts or leaked secrets."""
        pass


class HttpInspectionClient(BaseInspectionClient):
    """Production HTTP client for the AgentShield Central Inspection / DLP engine."""

    def __init__(self, service_url: Optional[str] = None, timeout: float = 8.0):
        settings = get_settings()
        self.service_url = service_url or settings.INSPECTION_SERVICE_URL
        self.timeout = timeout
        self.internal_token = settings.INTERNAL_SERVICE_TOKEN

    async def _post_inspect(self, endpoint: str, payload: dict) -> InspectionResult:
        if not self.service_url:
            logger.error("Inspection service URL not configured; failing closed")
            raise InspectionServiceUnavailableError("Inspection service is not configured (fail closed)")

        url = f"{self.service_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {self.internal_token}",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code >= 500:
                    logger.error(f"Inspection service 5xx error: {resp.text}")
                    raise InspectionServiceUnavailableError("Inspection service returned server error")
                if resp.status_code != 200:
                    logger.warning(f"Inspection service returned status {resp.status_code}")
                    return InspectionResult(
                        safe=False,
                        flags=[f"INSPECTION_HTTP_{resp.status_code}"],
                        details={"error": resp.text},
                    )
                return InspectionResult(**resp.json())
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            logger.critical(f"Inspection service unreachable: {e}. Failing closed.")
            raise InspectionServiceUnavailableError(f"Inspection service unreachable: {e}") from e

    async def inspect_incoming_email(self, email: EmailMessage) -> InspectionResult:
        payload = {
            "direction": "incoming",
            "message_id": email.id,
            "subject": email.subject,
            "sender": email.sender.email,
            "body_text": email.body_text or "",
            "snippet": email.snippet,
        }
        return await self._post_inspect("email/incoming", payload)

    async def inspect_outgoing_email(
        self, draft: Union[EmailDraftRequest, EmailSendRequest]
    ) -> InspectionResult:
        payload = {
            "direction": "outgoing",
            "subject": draft.subject,
            "body_text": draft.body_text,
            "body_html": draft.body_html,
            "recipients": [r.email for r in draft.to + draft.cc + draft.bcc],
        }
        return await self._post_inspect("email/outgoing", payload)

    async def inspect_attachment(
        self, filename: str, content_type: str, data: bytes
    ) -> InspectionResult:
        payload = {
            "filename": filename,
            "content_type": content_type,
            "data_base64": base64.b64encode(data).decode("ascii"),
        }
        return await self._post_inspect("attachment", payload)

