"""Email API routes."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.dependencies import AuthContext
from app.capabilities.online.email.email_gateway import EmailGateway
from app.capabilities.online.email.email_policy import EmailPolicy
from app.capabilities.online.email.gmail_client import GmailClient
from app.capabilities.online.email.oauth_manager import GmailOAuthManager, OutlookOAuthManager
from app.capabilities.online.email.outlook_client import OutlookClient
from app.core.configuration import get_settings
from app.core.contracts import GatewayResponse
from app.core.runtime import runtime
from app.core.security_context import build_security_context

router = APIRouter(prefix="/email", tags=["email"])


def _get_gateway() -> EmailGateway:
    settings = get_settings()
    email_policy = EmailPolicy()

    gmail_oauth = GmailOAuthManager(
        client_id=settings.gmail_client_id,
        client_secret=settings.gmail_client_secret,
        redirect_uri=settings.gmail_redirect_uri,
        token_path=settings.gmail_token_path,
    )
    outlook_oauth = OutlookOAuthManager(
        client_id=settings.msgraph_client_id,
        client_secret=settings.msgraph_client_secret,
        tenant_id=settings.msgraph_tenant_id,
        redirect_uri=settings.msgraph_redirect_uri,
    )

    return EmailGateway(
        policy=runtime.policy,
        email_policy=email_policy,
        content_inspector=runtime.content_inspector,
        data_inspector=runtime.data_inspector,
        approval=runtime.approval,
        audit=runtime.audit,
        gmail_client=GmailClient(gmail_oauth),
        outlook_client=OutlookClient(outlook_oauth),
    )


class EmailSearchRequest(BaseModel):
    query: str = Field(default="", max_length=500)
    provider: str = Field(default="gmail")
    max_results: int = Field(default=10, ge=1, le=50)


class EmailReadRequest(BaseModel):
    message_id: str
    provider: str = Field(default="gmail")


class EmailDraftRequest(BaseModel):
    to: list[str]
    subject: str = Field(..., max_length=256)
    body: str = Field(..., max_length=50000)
    provider: str = Field(default="gmail")
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)
    sender: str = Field(default="agent@example.com")


class EmailSendRequestApproval(BaseModel):
    to: list[str]
    subject: str = Field(..., max_length=256)
    body: str = Field(..., max_length=50000)
    sender: str = Field(default="agent@example.com")
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)
    attachment_hashes: list[str] = Field(default_factory=list)
    provider: str = Field(default="gmail")


class EmailSendExecuteRequest(BaseModel):
    approval_id: str
    to: list[str]
    subject: str
    body: str
    sender: str = "agent@example.com"
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)
    attachment_hashes: list[str] = Field(default_factory=list)
    provider: str = Field(default="gmail")


@router.post("/search", response_model=GatewayResponse)
async def search_emails(body: EmailSearchRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="email", operation="search",
    )
    return await _get_gateway().search(
        ctx=ctx, query=body.query, provider=body.provider,
        max_results=body.max_results,
    )


@router.post("/read", response_model=GatewayResponse)
async def read_email(body: EmailReadRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="email", operation="read", resource=body.message_id,
    )
    return await _get_gateway().read(ctx=ctx, message_id=body.message_id, provider=body.provider)


@router.post("/draft", response_model=GatewayResponse)
async def draft_email(body: EmailDraftRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="email", operation="draft",
    )
    return await _get_gateway().draft(
        ctx=ctx, to=body.to, subject=body.subject, body=body.body,
        provider=body.provider, cc=body.cc, bcc=body.bcc, sender=body.sender,
    )


@router.post("/send/request-approval", response_model=GatewayResponse)
async def request_send_approval(body: EmailSendRequestApproval, auth: AuthContext):
    """Step 1: validate and request approval. Returns approval_request_id."""
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="email", operation="send",
    )
    return await _get_gateway().request_send_approval(
        ctx=ctx, to=body.to, subject=body.subject, body=body.body,
        sender=body.sender, cc=body.cc, bcc=body.bcc,
        attachment_hashes=body.attachment_hashes,
    )


@router.post("/send", response_model=GatewayResponse)
async def execute_send(body: EmailSendExecuteRequest, auth: AuthContext):
    """Step 2: verify approval and send. Requires approval_id from step 1."""
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="email", operation="send",
    )
    return await _get_gateway().execute_send(
        ctx=ctx, approval_id=body.approval_id,
        to=body.to, subject=body.subject, body=body.body,
        sender=body.sender, cc=body.cc, bcc=body.bcc,
        attachment_hashes=body.attachment_hashes, provider=body.provider,
    )
