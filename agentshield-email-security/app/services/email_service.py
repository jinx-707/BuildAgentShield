"""Unified EmailService orchestrator composing sub-services, repositories, and security coordinators."""

import logging
from typing import List, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import get_settings
from app.database.repository import (
    ApprovalRepository,
    AttachmentQuarantineRepository,
    OAuthAccountRepository,
)
from app.integrations.approval_client import BaseApprovalClient, LocalDatabaseApprovalClient
from app.integrations.audit_client import HttpAuditClient
from app.integrations.inspection_client import HttpInspectionClient
from app.integrations.policy_client import HttpPolicyClient
from mocks.mock_approval import MockApprovalClient
from mocks.mock_attachment_scanner import MockAttachmentScanner
from mocks.mock_audit import MockAuditClient
from mocks.mock_inspector import MockInspectionClient
from mocks.mock_policy import MockPolicyClient
from app.schemas.approval import ApprovalResponse
from app.schemas.email import EmailAccountResponse
from app.schemas.security import SecurityContext
from app.security.attachment_scanner import BaseAttachmentScanner, LocalAttachmentScanner
from app.security.message_policy import MessagePolicyCoordinator
from app.services.email_draft import EmailDraftService
from app.services.email_forwarder import EmailForwarderService
from app.services.email_reader import EmailReaderService
from app.services.email_search import EmailSearchService
from app.services.email_sender import EmailSenderService

logger = logging.getLogger("agentshield.services.unified")

# Sentinel attribute present on every development mock class.
_MOCK_SENTINEL = "IS_DEVELOPMENT_MOCK"


def _is_mock(obj) -> bool:
    """Return True if obj carries the IS_DEVELOPMENT_MOCK sentinel."""
    return bool(getattr(obj, _MOCK_SENTINEL, False))


def _assert_no_mocks_in_production(
    policy_client,
    inspection_client,
    audit_client,
    appr_client,
    att_scanner,
) -> None:
    """Raise RuntimeError if any mock implementation is present in a production context.

    This guard runs after client selection so that explicitly injected mocks are
    also caught — dependency injection cannot bypass it.
    """
    checks = {
        "policy_client": policy_client,
        "inspection_client": inspection_client,
        "audit_client": audit_client,
        "approval_client": appr_client,
        "attachment_scanner": att_scanner,
    }
    for name, client in checks.items():
        if _is_mock(client):
            raise RuntimeError(
                f"SECURITY CONFIGURATION ERROR: Mock implementation detected for '{name}' "
                f"({type(client).__name__}) in production environment. "
                "Mock integrations are forbidden in production."
            )


def build_policy_coordinator(
    session: Optional[AsyncSession] = None,
    approval_client: Optional[BaseApprovalClient] = None,
    attachment_scanner: Optional[BaseAttachmentScanner] = None,
) -> MessagePolicyCoordinator:
    """Instantiate policy coordinator with appropriate clients.

    Environment selection:
      production              — real HTTP clients only; raises if USE_MOCK_INTEGRATIONS=True
                                or if any injected client carries IS_DEVELOPMENT_MOCK
      USE_MOCK_INTEGRATIONS   — development/test mocks (forbidden in production)
      APP_ENV == 'test'       — development/test mocks
      default (development)   — real clients if URLs configured, mocks otherwise
    """
    settings = get_settings()

    if settings.APP_ENV == "production":
        if settings.USE_MOCK_INTEGRATIONS:
            raise RuntimeError(
                "SECURITY CONFIGURATION ERROR: USE_MOCK_INTEGRATIONS=True is forbidden "
                "in production. Set USE_MOCK_INTEGRATIONS=False."
            )
        logger.info("[PRODUCTION] Initializing MessagePolicyCoordinator with real integration clients")
        policy_client = HttpPolicyClient()
        inspection_client = HttpInspectionClient()
        audit_client = HttpAuditClient()
        appr_client = approval_client or (LocalDatabaseApprovalClient(session) if session else None)
        if appr_client is None:
            raise RuntimeError(
                "SECURITY CONFIGURATION ERROR: No database session available for "
                "LocalDatabaseApprovalClient in production."
            )
        att_scanner = attachment_scanner or LocalAttachmentScanner()
        # Final guard: reject any injected mock even if the above logic selected real clients
        _assert_no_mocks_in_production(policy_client, inspection_client, audit_client, appr_client, att_scanner)
    elif settings.USE_MOCK_INTEGRATIONS or settings.APP_ENV == "test":
        logger.info("[DEV/TEST] Initializing MessagePolicyCoordinator with development mocks")
        policy_client = MockPolicyClient()
        inspection_client = MockInspectionClient()
        audit_client = MockAuditClient()
        appr_client = approval_client or (LocalDatabaseApprovalClient(session) if session else MockApprovalClient())
        att_scanner = attachment_scanner or MockAttachmentScanner()
    else:
        logger.info("[DEVELOPMENT] Initializing MessagePolicyCoordinator with real integration clients")
        policy_client = HttpPolicyClient()
        inspection_client = HttpInspectionClient()
        audit_client = HttpAuditClient()
        appr_client = approval_client or (LocalDatabaseApprovalClient(session) if session else MockApprovalClient())
        att_scanner = attachment_scanner or LocalAttachmentScanner()

    return MessagePolicyCoordinator(
        policy_client=policy_client,
        inspection_client=inspection_client,
        audit_client=audit_client,
        approval_client=appr_client,
        attachment_scanner=att_scanner,
    )


class EmailService:
    """Primary service façade coordinating email operations."""

    def __init__(
        self,
        session: AsyncSession,
        policy_coordinator: MessagePolicyCoordinator = None,
    ):
        self.session = session
        self.account_repo = OAuthAccountRepository(session)
        self.approval_repo = ApprovalRepository(session)
        self.quarantine_repo = AttachmentQuarantineRepository(session)
        self.approval_client = LocalDatabaseApprovalClient(session)

        self.policy_coordinator = policy_coordinator or build_policy_coordinator(
            session=session, approval_client=self.approval_client
        )

        self.reader = EmailReaderService(
            self.account_repo, self.policy_coordinator, self.quarantine_repo
        )
        self.search = EmailSearchService(self.account_repo, self.policy_coordinator)
        self.draft = EmailDraftService(self.account_repo, self.policy_coordinator)
        self.sender = EmailSenderService(
            self.account_repo, self.policy_coordinator, self.approval_client
        )
        self.forwarder = EmailForwarderService(
            self.account_repo, self.policy_coordinator, self.approval_client
        )

    async def list_accounts(self, context: SecurityContext) -> List[EmailAccountResponse]:
        """List accounts owned by caller, ensuring tokens are omitted."""
        accounts = await self.account_repo.list_accounts(
            tenant_id=context.tenant_id, agent_id=context.agent_id
        )
        return [EmailAccountResponse.model_validate(a) for a in accounts]

    async def get_approval(
        self, context: SecurityContext, approval_id: UUID
    ) -> Optional[ApprovalResponse]:
        """Fetch human approval status within security boundary."""
        return await self.approval_client.get_approval(approval_id, context.tenant_id, context.agent_id)

    async def disconnect_account(self, context: SecurityContext, account_id: UUID) -> bool:
        """Revoke account connection with provider and update database status."""
        account = await self.account_repo.get_account(
            account_id, context.tenant_id, context.agent_id
        )
        if not account:
            return False

        # Attempt provider token revocation
        access_token, _ = self.account_repo.get_decrypted_tokens(account)
        if account.provider == "google":
            from app.providers.gmail.oauth import GoogleOAuthHandler
            await GoogleOAuthHandler().revoke_token(access_token)

        success = await self.account_repo.revoke_account(
            account_id, context.tenant_id, context.agent_id
        )

        await self.policy_coordinator.audit_client.record_event(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            event_type="EMAIL_OAUTH_DISCONNECTED",
            status="ALLOWED",
            metadata={"account_id": str(account_id), "provider": account.provider},
            account_id=account_id,
        )

        return success
