"""MCP routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.api.dependencies import AuthContext
from app.capabilities.online.mcp.mcp_gateway import MCPGateway
from app.capabilities.online.mcp.server_registry import MCPServerRegistry
from app.capabilities.online.mcp.tool_registry import ToolRegistry
from app.core.configuration import get_settings
from app.core.contracts import GatewayResponse
from app.core.runtime import runtime
from app.core.security_context import build_security_context
from app.integrations.secret_provider import LocalEnvSecretProvider

router = APIRouter(prefix="/mcp", tags=["mcp"])


def _get_gateway() -> MCPGateway:
    settings = get_settings()
    return MCPGateway(
        policy=runtime.policy,
        audit=runtime.audit,
        content_inspector=runtime.content_inspector,
        data_inspector=runtime.data_inspector,
        approval=runtime.approval,
        server_registry=MCPServerRegistry(),
        tool_registry=ToolRegistry(),
        secret_provider=runtime.secret_provider or LocalEnvSecretProvider(),
        use_mock=settings.app_env == "development",
    )


class MCPInvokeRequest(BaseModel):
    server_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


@router.get("/servers", response_model=GatewayResponse)
async def list_servers(auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="mcp", operation="list_servers",
    )
    return await _get_gateway().list_servers(ctx=ctx)


@router.get("/tools", response_model=GatewayResponse)
async def list_tools(
    auth: AuthContext,
    server_id: str | None = Query(default=None),
):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="mcp", operation="list_tools",
    )
    return await _get_gateway().list_tools(ctx=ctx, server_id=server_id)


@router.post("/invoke", response_model=GatewayResponse)
async def invoke_tool(body: MCPInvokeRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="mcp", operation="invoke",
        resource=f"{body.server_id}/{body.tool_name}",
    )
    try:
        return await _get_gateway().invoke(
            ctx=ctx,
            server_id=body.server_id,
            tool_name=body.tool_name,
            arguments=body.arguments,
        )
    except Exception as e:
        from app.core.contracts import GatewayResponse
        from app.core.decisions import OperationStatus, SecurityDecision
        return GatewayResponse(
            request_id=ctx.request_id,
            status=OperationStatus.BLOCKED,
            decision=SecurityDecision.DENY,
            capability="mcp",
            operation="invoke",
            reason=str(e),
        )
