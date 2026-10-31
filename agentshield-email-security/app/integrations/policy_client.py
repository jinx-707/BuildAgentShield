"""PolicyClient interface and remote HTTP client for policy decisions."""

import logging
from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID
import httpx
from app.config import get_settings
from app.schemas.email import (
    EmailDraftRequest,
    EmailDraftUpdateRequest,
    EmailForwardRequest,
    EmailSendRequest,
)
from app.schemas.security import PolicyAction, PolicyDecision, PolicyRequest

logger = logging.getLogger("agentshield.email.policy")


class SecurityPolicyError(Exception):
    """Raised when policy authorization fails or blocks the request."""
    pass


class PolicyServiceUnavailableError(SecurityPolicyError):
    """Raised when remote policy service is unreachable (fail-closed requirement)."""
    pass


class BasePolicyClient(ABC):
    """Abstract interface contract for AgentShield policy authorization."""

    @abstractmethod
    async def authorize_read(
        self, tenant_id: str, agent_id: str, account_id: UUID, message_id: str
    ) -> PolicyDecision:
        """Authorize reading a specific email message."""
        pass

    @abstractmethod
    async def authorize_search(
        self, tenant_id: str, agent_id: str, account_id: UUID, query: str
    ) -> PolicyDecision:
        """Authorize searching an email mailbox."""
        pass

    @abstractmethod
    async def authorize_draft(
        self, tenant_id: str, agent_id: str, account_id: UUID, draft_request: EmailDraftRequest
    ) -> PolicyDecision:
        """Authorize composing a new draft message."""
        pass

    @abstractmethod
    async def authorize_draft_update(
        self, tenant_id: str, agent_id: str, account_id: UUID, draft_id: str, update_request: EmailDraftUpdateRequest
    ) -> PolicyDecision:
        """Authorize modifying an existing draft."""
        pass

    @abstractmethod
    async def authorize_send(
        self, tenant_id: str, agent_id: str, account_id: UUID, send_request: EmailSendRequest
    ) -> PolicyDecision:
        """Authorize sending an outbound email message."""
        pass

    @abstractmethod
    async def authorize_forward(
        self, tenant_id: str, agent_id: str, account_id: UUID, forward_request: EmailForwardRequest
    ) -> PolicyDecision:
        """Authorize forwarding an email message to external/internal recipients."""
        pass

    @abstractmethod
    async def authorize_attachment_read(
        self, tenant_id: str, agent_id: str, account_id: UUID, message_id: str, attachment_id: str
    ) -> PolicyDecision:
        """Authorize downloading or inspecting an email attachment."""
        pass


class HttpPolicyClient(BasePolicyClient):
    """Remote production HTTP client invoking the AgentShield central policy service."""

    def __init__(self, service_url: Optional[str] = None, timeout: float = 5.0):
        settings = get_settings()
        self.service_url = service_url or settings.POLICY_SERVICE_URL
        self.timeout = timeout
        self.internal_token = settings.INTERNAL_SERVICE_TOKEN

    async def _post_decision(self, req: PolicyRequest) -> PolicyDecision:
        if not self.service_url:
            logger.error("Policy service URL not configured; failing closed")
            raise PolicyServiceUnavailableError("Policy service is not configured (fail closed)")

        url = f"{self.service_url.rstrip('/')}/authorize"
        headers = {
            "Authorization": f"Bearer {self.internal_token}",
            "X-Tenant-ID": req.tenant_id,
            "X-Agent-ID": req.agent_id,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=req.model_dump(mode="json"), headers=headers)
                if resp.status_code >= 500:
                    logger.error(f"Policy service server error {resp.status_code}: {resp.text}")
                    raise PolicyServiceUnavailableError("Central policy service returned 5xx server error")
                if resp.status_code != 200:
                    logger.warning(f"Policy service rejected request with status {resp.status_code}")
                    return PolicyDecision(
                        allowed=False,
                        reason=f"Policy service returned status {resp.status_code}",
                        policy_id="POLICY_REJECTED",
                    )
                data = resp.json()
                return PolicyDecision(**data)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            logger.critical(f"Central policy service unreachable: {e}. Failing closed.")
            raise PolicyServiceUnavailableError(f"Central policy service unreachable: {e}") from e

    async def authorize_read(
        self, tenant_id: str, agent_id: str, account_id: UUID, message_id: str
    ) -> PolicyDecision:
        req = PolicyRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=PolicyAction.READ,
            account_id=account_id,
            resource_id=message_id,
        )
        return await self._post_decision(req)

    async def authorize_search(
        self, tenant_id: str, agent_id: str, account_id: UUID, query: str
    ) -> PolicyDecision:
        req = PolicyRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=PolicyAction.SEARCH,
            account_id=account_id,
            metadata={"query": query},
        )
        return await self._post_decision(req)

    async def authorize_draft(
        self, tenant_id: str, agent_id: str, account_id: UUID, draft_request: EmailDraftRequest
    ) -> PolicyDecision:
        req = PolicyRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=PolicyAction.DRAFT,
            account_id=account_id,
            recipients=[r.email for r in draft_request.to + draft_request.cc + draft_request.bcc],
            metadata={
                "subject": draft_request.subject,
                "attachment_count": len(draft_request.attachments),
            },
        )
        return await self._post_decision(req)

    async def authorize_draft_update(
        self, tenant_id: str, agent_id: str, account_id: UUID, draft_id: str, update_request: EmailDraftUpdateRequest
    ) -> PolicyDecision:
        recips = []
        if update_request.to:
            recips.extend(r.email for r in update_request.to)
        if update_request.cc:
            recips.extend(r.email for r in update_request.cc)
        if update_request.bcc:
            recips.extend(r.email for r in update_request.bcc)

        req = PolicyRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=PolicyAction.DRAFT_UPDATE,
            account_id=account_id,
            resource_id=draft_id,
            recipients=recips,
            metadata={"subject": update_request.subject},
        )
        return await self._post_decision(req)

    async def authorize_send(
        self, tenant_id: str, agent_id: str, account_id: UUID, send_request: EmailSendRequest
    ) -> PolicyDecision:
        recips = [r.email for r in (send_request.to or []) + send_request.cc + send_request.bcc]
        req = PolicyRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=PolicyAction.SEND,
            account_id=account_id,
            resource_id=send_request.draft_id,
            recipients=recips,
            metadata={
                "subject": send_request.subject,
                "attachment_count": len(send_request.attachments),
                "approval_id": str(send_request.approval_id) if send_request.approval_id else None,
            },
        )
        return await self._post_decision(req)

    async def authorize_forward(
        self, tenant_id: str, agent_id: str, account_id: UUID, forward_request: EmailForwardRequest
    ) -> PolicyDecision:
        req = PolicyRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=PolicyAction.FORWARD,
            account_id=account_id,
            resource_id=forward_request.original_message_id,
            recipients=[r.email for r in forward_request.to + forward_request.cc],
        )
        return await self._post_decision(req)

    async def authorize_attachment_read(
        self, tenant_id: str, agent_id: str, account_id: UUID, message_id: str, attachment_id: str
    ) -> PolicyDecision:
        req = PolicyRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=PolicyAction.ATTACHMENT_READ,
            account_id=account_id,
            resource_id=f"{message_id}:{attachment_id}",
        )
        return await self._post_decision(req)
