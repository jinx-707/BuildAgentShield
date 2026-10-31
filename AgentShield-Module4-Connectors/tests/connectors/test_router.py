"""
API Endpoint Tests for AgentShield FastAPI Connectors Router.
Tests:
  - POST   /online/connectors/register
  - GET    /online/connectors
  - POST   /online/connectors/{connector_id}/execute
  - DELETE /online/connectors/{connector_id}
"""

import httpx
import pytest

from core.connectors.gateway import SecurityGateway
from core.connectors.models import (
    AgentPermissionRule,
    AuthenticationConfig,
    AuthType,
    ConnectorRegistration,
    ConnectorType,
    EndpointDefinition,
    HttpMethod,
    PermissionAction,
)
from core.connectors.registry import ConnectorRegistry
from core.connectors.router import create_connectors_app


@pytest.fixture
def app_client():
    """Instantiates a FastAPI test client with configured SecurityGateway."""
    registry = ConnectorRegistry()
    gw = SecurityGateway(registry=registry, allow_private_network=True)
    app = create_connectors_app(gateway=gw)
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    return client, gw


@pytest.mark.anyio
async def test_api_register_connector(app_client):
    """POST /online/connectors/register registers a new connector."""
    client, gw = app_client
    payload = {
        "connector_id": "fastapi_test_conn",
        "name": "FastAPI Connector",
        "connector_type": "rest_api",
        "base_url": "https://api.fastapi.test",
        "allowed_endpoints": [
            {"path": "/health", "methods": ["GET"]}
        ],
        "auth_config": {
            "auth_type": "bearer_token",
            "secret_id": "secret_key_123",
        },
    }
    resp = await client.post("/online/connectors/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["connector_id"] == "fastapi_test_conn"
    assert gw.registry.get_connector("fastapi_test_conn") is not None


@pytest.mark.anyio
async def test_api_list_connectors_masks_secrets(app_client):
    """GET /online/connectors returns connectors with masked credentials."""
    client, gw = app_client
    reg = ConnectorRegistration(
        connector_id="conn_mask_test",
        name="Mask Test",
        connector_type=ConnectorType.REST_API,
        base_url="https://mask.test",
        auth_config=AuthenticationConfig(
            auth_type=AuthType.API_KEY,
            secret_id="super_sensitive_secret_id",
        ),
    )
    gw.registry.register_connector(reg)

    resp = await client.get("/online/connectors")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 1
    target = next(i for i in items if i["connector_id"] == "conn_mask_test")
    # Secret reference must be masked in listing!
    assert target["auth_config"]["secret_id"] == "***"


@pytest.mark.anyio
async def test_api_execute_connector(app_client):
    """POST /online/connectors/{connector_id}/execute routes through gateway."""
    client, gw = app_client
    # Register mock connector
    reg = ConnectorRegistration(
        connector_id="exec_test_conn",
        name="Exec Test",
        connector_type=ConnectorType.REST_API,
        base_url="https://exec.test",
        allowed_endpoints=[
            EndpointDefinition(path="/data", methods=[HttpMethod.GET]),
        ],
    )
    gw.registry.register_connector(reg)

    # Permission
    gw.permission_manager.grant_permission(
        AgentPermissionRule(agent_id="api_agent", connector_id="exec_test_conn", action=PermissionAction.ALLOW)
    )

    exec_payload = {
        "agent_id": "api_agent",
        "connector_id": "exec_test_conn",
        "endpoint": "/data",
        "method": "GET",
    }
    resp = await client.post("/online/connectors/exec_test_conn/execute", json=exec_payload)
    assert resp.status_code == 200
    data = resp.json()
    # Response model contains status, security_decision, audit_record
    assert "status" in data
    assert "security_decision" in data
    assert "audit_record" in data


@pytest.mark.anyio
async def test_api_delete_connector(app_client):
    """DELETE /online/connectors/{connector_id} deletes or returns 404."""
    client, gw = app_client
    reg = ConnectorRegistration(
        connector_id="to_delete",
        name="To Delete",
        connector_type=ConnectorType.REST_API,
        base_url="https://del.test",
    )
    gw.registry.register_connector(reg)

    # Delete existing
    del_resp = await client.delete("/online/connectors/to_delete")
    assert del_resp.status_code == 200
    assert del_resp.json() == {"deleted": True, "connector_id": "to_delete"}

    # Delete non-existent
    not_found = await client.delete("/online/connectors/does_not_exist")
    assert not_found.status_code == 404
