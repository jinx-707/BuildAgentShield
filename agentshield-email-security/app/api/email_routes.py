
"""FastAPI routes exposing secured email integration capabilities to authorized AI agents."""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.integrations.inspection_client import InspectionServiceUnavailableError
from app.integrations.policy_client import PolicyServiceUnavailableError
from app.middleware.authentication import get_security_context
from app.providers.base import (
    ProviderAuthenticationError,
    ProviderNotFoundError,
    ProviderRateLimitError,
)
from app.schemas.approval import ApprovalResponse
from app.schemas.email import (
    AttachmentMetadataResponse,
    EmailAccountResponse,
    EmailDraftRequest,
    EmailDraftResponse,
    EmailDraftUpdateRequest,
    EmailForwardRequest,
    EmailForwardResponse,
    EmailMessage,
    EmailSearchRequest,
    EmailSearchResponse,
    EmailSendRequest,
    EmailSendResponse,
)
from app.schemas.security import SecurityContext
from app.security.message_policy import (
    HumanApprovalRequiredError,
    SecurityPolicyEnforcementError,
)
from app.services.email_service import EmailService


logger = logging.getLogger("agentshield.api.email")

router = APIRouter(prefix="/online/email", tags=["Email Operations"])


def get_email_service(db: AsyncSession = Depends(get_db)) -> EmailService:
    """Dependency provider for EmailService."""
    return EmailService(session=db)


@router.get(
    "/accounts",
    response_model=List[EmailAccountResponse],
    status_code=status.HTTP_200_OK,
    summary="List Connected Email Accounts",
    description="Returns authorized mailboxes for the authenticated tenant and agent. No credentials returned.",
)
async def list_accounts(
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    return await service.list_accounts(context)


@router.post(
    "/accounts/{account_id}/disconnect",
    status_code=status.HTTP_200_OK,
    summary="Disconnect Email Account",
    description="Disconnects account and revokes OAuth tokens with provider.",
)
async def disconnect_account(
    account_id: UUID,
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    success = await service.disconnect_account(context, account_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found or inaccessible",
        )

    return {"status": "disconnected", "account_id": account_id}


@router.get(
    "/messages",
    response_model=EmailSearchResponse,
    status_code=status.HTTP_200_OK,
    summary="List or Preview Mailbox Messages",
    description=(
        "Retrieves a page of messages from the authorized mailbox, "
        "with inbound security inspection and pagination support."
    ),
)
async def list_messages(
    account_id: UUID = Query(..., description="Target email account identifier"),
    q: Optional[str] = Query(default=None, description="Optional search filter query"),
    max_results: int = Query(
        default=10,
        ge=1,
        le=50,
        description="Maximum messages to return",
    ),
    page_token: Optional[str] = Query(
        default=None,
        description="Pagination token from the previous response",
    ),
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    try:
        messages, next_page = await service.reader.list_messages(
            context=context,
            account_id=account_id,
            query=q,
            max_results=max_results,
            page_token=page_token,
        )

        return EmailSearchResponse(
            messages=messages,
            next_page_token=next_page,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except SecurityPolicyEnforcementError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "code": e.policy_id,
            },
        )

    except (
        PolicyServiceUnavailableError,
        InspectionServiceUnavailableError,
    ) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Required security service is unavailable (fail-closed)",
                "details": str(e),
            },
        )

    except ProviderRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    except ProviderAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


@router.get(
    "/messages/{message_id}",
    response_model=EmailMessage,
    status_code=status.HTTP_200_OK,
    summary="Read Specific Email Message",
    description="Retrieves normalized message details, decoded body, and attachment metadata after policy evaluation.",
)
async def get_message(
    message_id: str,
    account_id: UUID = Query(..., description="Target email account identifier"),
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    try:
        return await service.reader.get_message(
            context=context,
            account_id=account_id,
            message_id=message_id,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except ProviderNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email message not found",
        )

    except SecurityPolicyEnforcementError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "code": e.policy_id,
            },
        )

    except (
        PolicyServiceUnavailableError,
        InspectionServiceUnavailableError,
    ) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Required security service is unavailable (fail-closed)",
                "details": str(e),
            },
        )

    except ProviderRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    except ProviderAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


@router.post(
    "/search",
    response_model=EmailSearchResponse,
    status_code=status.HTTP_200_OK,
    summary="Search Messages",
    description="Searches email messages with policy-governed query inspection and inbound sanitization.",
)
async def search_messages(
    request: EmailSearchRequest,
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    try:
        return await service.search.search_messages(
            context=context,
            search_req=request,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except SecurityPolicyEnforcementError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "code": e.policy_id,
            },
        )

    except (
        PolicyServiceUnavailableError,
        InspectionServiceUnavailableError,
    ) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Required security service is unavailable (fail-closed)",
                "details": str(e),
            },
        )

    except ProviderRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    except ProviderAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


@router.post(
    "/draft",
    response_model=EmailDraftResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Email Draft",
    description="Validates recipients, scans draft body for DLP/PII leakage, and persists draft.",
)
async def create_draft(
    request: EmailDraftRequest,
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    try:
        return await service.draft.create_draft(
            context=context,
            draft_req=request,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except SecurityPolicyEnforcementError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "code": e.policy_id,
            },
        )

    except (
        PolicyServiceUnavailableError,
        InspectionServiceUnavailableError,
    ) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Required security service is unavailable (fail-closed)",
                "details": str(e),
            },
        )

    except ProviderRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    except ProviderAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


@router.get(
    "/drafts/{draft_id}",
    response_model=EmailDraftResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Draft by ID",
    description="Retrieves draft details from provider.",
)
async def get_draft(
    draft_id: str,
    account_id: UUID = Query(..., description="Target email account identifier"),
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    try:
        return await service.draft.get_draft(
            context=context,
            account_id=account_id,
            draft_id=draft_id,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except ProviderNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Draft not found",
        )

    except SecurityPolicyEnforcementError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "code": e.policy_id,
            },
        )


@router.patch(
    "/drafts/{draft_id}",
    response_model=EmailDraftResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Draft by ID",
    description="Updates existing draft with recipient and DLP checks.",
)
async def update_draft(
    draft_id: str,
    request: EmailDraftUpdateRequest,
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    try:
        return await service.draft.update_draft(
            context=context,
            draft_id=draft_id,
            update_req=request,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except SecurityPolicyEnforcementError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "code": e.policy_id,
            },
        )


@router.post(
    "/send",
    response_model=EmailSendResponse,
    status_code=status.HTTP_200_OK,
    summary="Send Email Message",
    description="Performs strict egress validation: recipient hygiene, attachment filtering, DLP checks, and policy authorization.",
)
async def send_email(
    request: EmailSendRequest,
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    try:
        return await service.sender.send_email(
            context=context,
            send_req=request,
        )

    except HumanApprovalRequiredError as e:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail={
                "message": e.message,
                "status": "PENDING_APPROVAL",
                "approval_id": e.approval_id,
            },
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except SecurityPolicyEnforcementError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "code": e.policy_id,
            },
        )

    except (
        PolicyServiceUnavailableError,
        InspectionServiceUnavailableError,
    ) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Required security service is unavailable (fail-closed)",
                "details": str(e),
            },
        )

    except ProviderRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    except ProviderAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


@router.post(
    "/forward",
    response_model=EmailForwardResponse,
    status_code=status.HTTP_200_OK,
    summary="Forward Email Message",
    description="Validates forwarding recipients, checks policy authorization, and forwards the message.",
)
async def forward_email(
    request: EmailForwardRequest,
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    try:
        return await service.forwarder.forward_email(
            context=context,
            forward_req=request,
        )

    except HumanApprovalRequiredError as e:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail={
                "message": e.message,
                "status": "PENDING_APPROVAL",
                "approval_id": e.approval_id,
            },
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except SecurityPolicyEnforcementError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "code": e.policy_id,
            },
        )

    except (
        PolicyServiceUnavailableError,
        InspectionServiceUnavailableError,
    ) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Required security service is unavailable (fail-closed)",
                "details": str(e),
            },
        )

    except ProviderRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    except ProviderAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


@router.get(
    "/attachments/{attachment_id}/metadata",
    response_model=AttachmentMetadataResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Attachment Metadata & Security Findings",
    description="Retrieves attachment cryptographic SHA-256 hash, size, and quarantine status.",
)
async def get_attachment_metadata(
    attachment_id: str,
    account_id: UUID = Query(..., description="Target email account identifier"),
    message_id: str = Query(..., description="Parent email message identifier"),
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    try:
        return await service.reader.get_attachment_metadata(
            context=context,
            account_id=account_id,
            message_id=message_id,
            attachment_id=attachment_id,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except SecurityPolicyEnforcementError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "code": e.policy_id,
            },
        )

    except ProviderNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attachment or message not found",
        )


@router.get(
    "/approvals/{approval_id}",
    response_model=ApprovalResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Human Approval Status",
    description="Checks lifecycle status of an approval request (PENDING, APPROVED, REJECTED, USED).",
)
async def get_approval_status(
    approval_id: UUID,
    context: SecurityContext = Depends(get_security_context),
    service: EmailService = Depends(get_email_service),
):
    approval = await service.get_approval(context, approval_id)

    if not approval:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Approval request not found",
        )

    return approval
