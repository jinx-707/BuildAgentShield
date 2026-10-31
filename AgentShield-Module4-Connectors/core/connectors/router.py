"""
AgentShield FastAPI Connectors Router.
Exposes the required REST API endpoints for external API and MCP connector management:
  - POST   /online/connectors/register
  - GET    /online/connectors
  - POST   /online/connectors/{connector_id}/execute
  - DELETE /online/connectors/{connector_id}
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse

from core.connectors.gateway import SecurityGateway
from core.connectors.models import (
    ConnectorRegistration,
    ConnectorType,
    ExecutionRequest,
    ExecutionResponse,
    ExecutionStatus,
    SecurityDecision,
)

# Global or injectable gateway instance
_default_gateway: SecurityGateway | None = None


def get_gateway() -> SecurityGateway:
    """Dependency provider for SecurityGateway."""
    global _default_gateway
    if _default_gateway is None:
        _default_gateway = SecurityGateway()
    return _default_gateway


def set_gateway(gateway: SecurityGateway) -> None:
    """Sets the active SecurityGateway instance."""
    global _default_gateway
    _default_gateway = gateway


router = APIRouter(prefix="/online/connectors", tags=["External Connectors & MCP Gateway"])


@router.post(
    "/register",
    response_model=ConnectorRegistration,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new external REST API or MCP server",
)
async def register_connector(
    registration: ConnectorRegistration,
    gateway: SecurityGateway = Depends(get_gateway),
) -> ConnectorRegistration:
    """
    Registers an external API or MCP connector in the central registry.
    Validates URL schemes, endpoints, and tool specifications.
    """
    try:
        registered = gateway.registry.register_connector(registration)
        return registered
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid connector registration: {ve}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {exc}",
        )


@router.get(
    "",
    response_model=list[ConnectorRegistration],
    summary="List all registered external connectors",
)
async def list_connectors(
    connector_type: ConnectorType | None = Query(default=None, description="Filter by REST_API or MCP"),
    enabled_only: bool = Query(default=False, description="Filter only enabled connectors"),
    gateway: SecurityGateway = Depends(get_gateway),
) -> list[ConnectorRegistration]:
    """Retrieves all registered connectors with auth credentials securely masked."""
    connectors = gateway.registry.list_connectors(
        connector_type=connector_type,
        enabled_only=enabled_only,
    )
    # Mask any secret_id references in returned listing for safety
    safe_list: list[ConnectorRegistration] = []
    for c in connectors:
        safe_auth = c.auth_config.model_copy(
            update={"secret_id": "***" if c.auth_config.secret_id else None}
        )
        safe_list.append(c.model_copy(update={"auth_config": safe_auth}))
    return safe_list


@router.post(
    "/{connector_id}/execute",
    response_model=ExecutionResponse,
    summary="Execute an external tool or REST API call through the security gateway",
)
async def execute_connector(
    connector_id: str,
    request: ExecutionRequest,
    gateway: SecurityGateway = Depends(get_gateway),
) -> ExecutionResponse:
    """
    Executes an external call through the central 13-stage security gateway.
    Enforces authentication, permissions, SSRF blocking, rate limits,
    secret scrubbing, and inbound/outbound prompt injection/leak scans.
    """
    # Enforce connector_id matching path
    if request.connector_id != connector_id:
        request = request.model_copy(update={"connector_id": connector_id})

    response = await gateway.execute(request)

    # Return response directly; if blocked, status code can be 403 or 200 with blocked status
    return response


@router.delete(
    "/{connector_id}",
    summary="Delete a registered connector",
)
async def delete_connector(
    connector_id: str,
    gateway: SecurityGateway = Depends(get_gateway),
) -> dict[str, Any]:
    """Removes a registered connector and its associated endpoints and tools."""
    deleted = gateway.registry.delete_connector(connector_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector '{connector_id}' not found",
        )
    return {"deleted": True, "connector_id": connector_id}


def create_connectors_app(gateway: SecurityGateway | None = None) -> Any:
    """Helper to instantiate a FastAPI application with the connectors router mounted."""
    from fastapi import FastAPI
    app = FastAPI(
        title="AgentShield External APIs & MCP Security Gateway",
        description="Unified Runtime Security Gateway for External APIs and Model Context Protocol (MCP)",
        version="1.0.0",
    )
    if gateway:
        set_gateway(gateway)
    app.include_router(router)
    return app
