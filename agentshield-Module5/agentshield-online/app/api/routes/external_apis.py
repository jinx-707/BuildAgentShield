"""External APIs route."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.dependencies import AuthContext
from app.capabilities.online.external_apis.api_gateway import APIGateway
from app.capabilities.online.external_apis.connector_registry import ConnectorRegistry
from app.core.contracts import GatewayResponse
from app.core.runtime import runtime
from app.core.security_context import build_security_context
from app.integrations.secret_provider import LocalEnvSecretProvider

router = APIRouter(prefix="/apis", tags=["external_apis"])


def _get_gateway() -> APIGateway:
    return APIGateway(
        policy=runtime.policy,
        audit=runtime.audit,
        data_inspector=runtime.data_inspector,
        registry=ConnectorRegistry(),
        secret_provider=runtime.secret_provider or LocalEnvSecretProvider(),
    )


class APIExecuteRequest(BaseModel):
    connector_id: str
    method: str = Field(default="GET", pattern="^(GET|POST|PUT|PATCH|DELETE)$")
    path: str = Field(..., min_length=1)
    query_params: dict[str, Any] | None = None
    body: dict[str, Any] | None = None


@router.post("/execute", response_model=GatewayResponse)
async def execute_api(body: APIExecuteRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="apis", operation="execute", resource=body.connector_id,
    )
    return await _get_gateway().execute(
        ctx=ctx,
        connector_id=body.connector_id,
        method=body.method,
        path=body.path,
        query_params=body.query_params,
        body=body.body,
    )
