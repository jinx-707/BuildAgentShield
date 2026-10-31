"""Email search service orchestrating search query policy authorization and provider filtering."""

import logging
from typing import List, Optional
from uuid import UUID
from app.database.repository import OAuthAccountRepository
from app.providers.base import BaseEmailProvider
from app.providers.gmail.client import GmailClient
from app.providers.gmail.message_parser import GmailMessageParser
from app.schemas.email import EmailMessage, EmailSearchRequest, EmailSearchResponse
from app.schemas.security import SecurityContext
from app.security.message_policy import MessagePolicyCoordinator, SecurityPolicyEnforcementError

logger = logging.getLogger("agentshield.services.search")


def build_gmail_query(request: EmailSearchRequest) -> str:
    """Build composite Gmail query from structured filter parameters."""
    query_parts: List[str] = []

    if request.query:
        query_parts.append(request.query.strip())
    if request.from_sender:
        query_parts.append(f"from:{request.from_sender.strip()}")
    if request.to_recipient:
        query_parts.append(f"to:{request.to_recipient.strip()}")
    if request.subject:
        query_parts.append(f"subject:{request.subject.strip()}")
    if request.after_date:
        query_parts.append(f"after:{request.after_date.strip()}")
    if request.before_date:
        query_parts.append(f"before:{request.before_date.strip()}")

    combined = " ".join(query_parts).strip()
    return combined if combined else "label:INBOX"


class EmailSearchService:
    """Manages secure email search queries with authorization and content inspection."""

    def __init__(
        self,
        account_repo: OAuthAccountRepository,
        policy_coordinator: MessagePolicyCoordinator,
    ):
        self.account_repo = account_repo
        self.policy_coordinator = policy_coordinator

    async def _resolve_provider(
        self, context: SecurityContext, account_id: UUID
    ) -> BaseEmailProvider:
        account = await self.account_repo.get_account(
            account_id, context.tenant_id, context.agent_id
        )
        if not account or account.status != "active":
            raise ValueError(f"Account {account_id} not found or inactive for caller")

        # Scope enforcement (requires at least readonly)
        allowed_read_scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://mail.google.com/",
        ]
        self.policy_coordinator.enforce_scope(account.granted_scopes, allowed_read_scopes, "search")

        access_token, refresh_token = self.account_repo.get_decrypted_tokens(account)
        if account.provider == "google":
            return GmailClient(access_token=access_token, refresh_token=refresh_token)
        else:
            from app.providers.microsoft.client import MicrosoftGraphClient
            return MicrosoftGraphClient(access_token=access_token, refresh_token=refresh_token)

    async def search_messages(
        self, context: SecurityContext, search_req: EmailSearchRequest
    ) -> EmailSearchResponse:
        """Execute email search after query policy evaluation and inbound inspection."""
        effective_query = build_gmail_query(search_req)

        # 1. Authorize search query
        decision = await self.policy_coordinator.policy_client.authorize_search(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            account_id=search_req.account_id,
            query=effective_query,
        )
        if not decision.allowed:
            await self.policy_coordinator.audit_client.record_event(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                event_type="EMAIL_SEARCH_BLOCKED",
                status="BLOCKED",
                metadata={"query": effective_query, "reason": decision.reason},
                account_id=search_req.account_id,
                policy_decision_id=decision.policy_id,
            )
            raise SecurityPolicyEnforcementError(
                decision.reason or "Search query blocked by policy",
                policy_id=decision.policy_id or "SEARCH_BLOCKED",
            )

        provider = await self._resolve_provider(context, search_req.account_id)
        raw_messages, next_page = await provider.list_messages(
            query=effective_query,
            max_results=search_req.max_results,
            page_token=search_req.page_token,
            include_spam_trash=search_req.include_spam_trash,
        )

        messages: List[EmailMessage] = []
        for raw in raw_messages:
            parsed = GmailMessageParser.to_email_message(raw)
            inspected = await self.policy_coordinator.inspect_inbound_message(
                context=context, email=parsed, account_id=search_req.account_id
            )
            messages.append(inspected)

        await self.policy_coordinator.audit_client.record_event(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            event_type="EMAIL_SEARCH",
            status="ALLOWED",
            metadata={"query": effective_query, "results_count": len(messages)},
            account_id=search_req.account_id,
            policy_decision_id=decision.policy_id,
        )

        return EmailSearchResponse(
            messages=messages,
            next_page_token=next_page,
            total_estimated=len(messages),
        )
