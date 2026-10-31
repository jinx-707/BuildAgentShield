"""Development mock implementation of PolicyClient.

WARNING:
This mock is for local development and test suites ONLY.
It DOES NOT provide real security enforcement and must NEVER be used in production.
"""

import logging
from typing import List, Optional, Set
from uuid import UUID
from app.integrations.policy_client import BasePolicyClient
from app.schemas.email import (
    EmailDraftRequest,
    EmailDraftUpdateRequest,
    EmailForwardRequest,
    EmailSendRequest,
)
from app.schemas.security import PolicyDecision

logger = logging.getLogger("agentshield.mocks.policy")


class MockPolicyClient(BasePolicyClient):
    """Development-only mock policy client with configurable rules for unit/integration testing."""

    IS_DEVELOPMENT_MOCK: bool = True

    def __init__(
        self,
        default_allow: bool = True,
        blocked_queries: Optional[List[str]] = None,
        blocked_recipients: Optional[List[str]] = None,
        require_approval_for_send: bool = False,
    ):
        logger.warning(
            "*** SECURITY WARNING: MockPolicyClient ACTIVE. THIS IS A TEST MOCK ONLY. ***"
        )
        self.default_allow = default_allow
        self.blocked_queries: Set[str] = set(blocked_queries or ["blocked_query", "restricted_secret"])
        self.blocked_recipients: Set[str] = set(blocked_recipients or ["blocked@malicious.example.com"])
        self.require_approval_for_send = require_approval_for_send

    async def authorize_read(
        self, tenant_id: str, agent_id: str, account_id: UUID, message_id: str
    ) -> PolicyDecision:
        if message_id == "blocked-message-id":
            return PolicyDecision(
                allowed=False,
                reason="[MOCK] Message ID is on mock restricted list",
                policy_id="MOCK_RESTRICTED_READ",
            )
        return PolicyDecision(
            allowed=self.default_allow,
            reason="[MOCK] Permitted by local mock policy",
            policy_id="MOCK_DEFAULT_ALLOW",
        )

    async def authorize_search(
        self, tenant_id: str, agent_id: str, account_id: UUID, query: str
    ) -> PolicyDecision:
        if any(term in query.lower() for term in self.blocked_queries):
            return PolicyDecision(
                allowed=False,
                reason="[MOCK] Search query contains restricted term",
                policy_id="MOCK_BLOCKED_SEARCH_QUERY",
            )
        return PolicyDecision(
            allowed=self.default_allow,
            reason="[MOCK] Search permitted by mock policy",
            policy_id="MOCK_DEFAULT_ALLOW",
        )

    async def authorize_draft(
        self, tenant_id: str, agent_id: str, account_id: UUID, draft_request: EmailDraftRequest
    ) -> PolicyDecision:
        recipients = [r.email.lower() for r in draft_request.to + draft_request.cc + draft_request.bcc]
        if any(r in self.blocked_recipients for r in recipients):
            return PolicyDecision(
                allowed=False,
                reason="[MOCK] Draft contains blocked recipient address",
                policy_id="MOCK_BLOCKED_RECIPIENT",
            )
        return PolicyDecision(
            allowed=self.default_allow,
            reason="[MOCK] Draft permitted by mock policy",
            policy_id="MOCK_DEFAULT_ALLOW",
        )

    async def authorize_draft_update(
        self, tenant_id: str, agent_id: str, account_id: UUID, draft_id: str, update_request: EmailDraftUpdateRequest
    ) -> PolicyDecision:
        recips = []
        if update_request.to:
            recips.extend(r.email.lower() for r in update_request.to)
        if any(r in self.blocked_recipients for r in recips):
            return PolicyDecision(
                allowed=False,
                reason="[MOCK] Updated draft contains blocked recipient",
                policy_id="MOCK_BLOCKED_RECIPIENT",
            )
        return PolicyDecision(
            allowed=self.default_allow,
            reason="[MOCK] Draft update permitted by mock policy",
            policy_id="MOCK_DEFAULT_ALLOW",
        )

    async def authorize_send(
        self, tenant_id: str, agent_id: str, account_id: UUID, send_request: EmailSendRequest
    ) -> PolicyDecision:
        recipients = [r.email.lower() for r in (send_request.to or []) + send_request.cc + send_request.bcc]
        if any(r in self.blocked_recipients for r in recipients):
            return PolicyDecision(
                allowed=False,
                reason="[MOCK] Send target contains blocked recipient",
                policy_id="MOCK_BLOCKED_RECIPIENT",
            )

        if self.require_approval_for_send:
            return PolicyDecision(
                allowed=False,
                reason="[MOCK] Send requires human approval under mock test rule",
                policy_id="MOCK_APPROVAL_REQUIRED",
                requires_human_approval=True,
            )

        return PolicyDecision(
            allowed=self.default_allow,
            reason="[MOCK] Send permitted by mock policy",
            policy_id="MOCK_DEFAULT_ALLOW",
        )

    async def authorize_forward(
        self, tenant_id: str, agent_id: str, account_id: UUID, forward_request: EmailForwardRequest
    ) -> PolicyDecision:
        recipients = [r.email.lower() for r in forward_request.to + forward_request.cc]
        if any(r in self.blocked_recipients for r in recipients):
            return PolicyDecision(
                allowed=False,
                reason="[MOCK] Forward contains blocked recipient",
                policy_id="MOCK_BLOCKED_RECIPIENT",
            )
        return PolicyDecision(
            allowed=self.default_allow,
            reason="[MOCK] Forward permitted by mock policy",
            policy_id="MOCK_DEFAULT_ALLOW",
        )

    async def authorize_attachment_read(
        self, tenant_id: str, agent_id: str, account_id: UUID, message_id: str, attachment_id: str
    ) -> PolicyDecision:
        if attachment_id == "blocked-attachment-id":
            return PolicyDecision(
                allowed=False,
                reason="[MOCK] Attachment read blocked by policy",
                policy_id="MOCK_BLOCKED_ATTACHMENT_READ",
            )
        return PolicyDecision(
            allowed=self.default_allow,
            reason="[MOCK] Attachment read permitted by mock policy",
            policy_id="MOCK_DEFAULT_ALLOW",
        )
