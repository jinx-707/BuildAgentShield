"""
Browser API routes.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.dependencies import AuthContext
from app.capabilities.online.browser.browser_gateway import BrowserGateway
from app.capabilities.online.browser.network_policy import BrowserNetworkPolicy
from app.capabilities.online.browser.puppeteer_manager import PuppeteerManager
from app.capabilities.online.browser.search_service import create_search_provider
from app.capabilities.online.browser.session_manager import SessionManager
from app.core.configuration import get_settings
from app.core.contracts import GatewayResponse, SecurityContext
from app.core.security_context import build_security_context
from app.core.runtime import runtime

router = APIRouter(prefix="/browser", tags=["browser"])


def _get_gateway() -> BrowserGateway:
    settings = get_settings()
    search_provider = create_search_provider(
        provider_name=settings.search_provider,
        api_key=settings.serper_api_key or settings.brave_search_api_key,
    )
    return BrowserGateway(
        policy=runtime.policy,
        content_inspector=runtime.content_inspector,
        audit=runtime.audit,
        search_provider=search_provider,
        puppeteer=PuppeteerManager(),
        session_manager=SessionManager(),
        network_policy=BrowserNetworkPolicy(),
    )


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=500)
    num_results: int = Field(default=10, ge=1, le=20)


class NavigateRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    session_id: str | None = None


class ExtractRequest(BaseModel):
    session_id: str
    url: str
    selector: str | None = None


class BrowserActionRequest(BaseModel):
    action_type: str
    session_id: str
    params: dict[str, Any] = Field(default_factory=dict)


@router.post("/search", response_model=GatewayResponse)
async def search(body: SearchRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id,
        tenant_id=auth.tenant_id,
        capability="browser",
        operation="search",
    )
    gw = _get_gateway()
    return await gw.search(ctx=ctx, query=body.query, num_results=body.num_results)


@router.post("/navigate", response_model=GatewayResponse)
async def navigate(body: NavigateRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id,
        tenant_id=auth.tenant_id,
        capability="browser",
        operation="navigate",
        resource=body.url,
    )
    gw = _get_gateway()
    return await gw.navigate(ctx=ctx, url=body.url, session_id=body.session_id)


@router.post("/extract", response_model=GatewayResponse)
async def extract(body: ExtractRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id,
        tenant_id=auth.tenant_id,
        capability="browser",
        operation="extract",
        resource=body.session_id,
    )
    gw = _get_gateway()
    return await gw.extract(
        ctx=ctx,
        session_id=body.session_id,
        url=body.url,
        selector=body.selector,
    )


@router.post("/action", response_model=GatewayResponse)
async def browser_action(body: BrowserActionRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id,
        tenant_id=auth.tenant_id,
        capability="browser",
        operation=body.action_type,
        resource=body.session_id,
    )
    gw = _get_gateway()
    return await gw.browser_action(
        ctx=ctx,
        action_type=body.action_type,
        session_id=body.session_id,
        params=body.params,
    )
