"""
Unit Tests for AgentShield Connector Models & Central Registry.
Tests:
  - Model serialization and validations
  - Central connector registration
  - Listing with filters
  - Connector deletion & status toggling
  - MCP tool registration & approval workflows
  - Exact and parameterized endpoint path matching
"""

import pytest

from core.connectors.models import (
    ConnectorRegistration,
    ConnectorType,
    EndpointDefinition,
    HttpMethod,
    McpToolDefinition,
    UnregisteredConnectorError,
)
from core.connectors.registry import ConnectorRegistry


@pytest.fixture
def registry():
    return ConnectorRegistry()


def test_register_and_get_connector(registry):
    """Registers and retrieves connector from the catalog."""
    reg = ConnectorRegistration(
        connector_id="stock_api",
        name="Stock Market API",
        connector_type=ConnectorType.REST_API,
        base_url="https://api.stocks.com",
        allowed_endpoints=[
            EndpointDefinition(path="/quote", methods=[HttpMethod.GET]),
        ],
    )
    registry.register_connector(reg)

    fetched = registry.get_connector("stock_api")
    assert fetched is not None
    assert fetched.name == "Stock Market API"
    assert len(fetched.allowed_endpoints) == 1


def test_list_and_filter_connectors(registry):
    """Filters registered connectors by type and enabled status."""
    c1 = ConnectorRegistration(
        connector_id="rest_1",
        name="REST 1",
        connector_type=ConnectorType.REST_API,
        base_url="https://api1.com",
        enabled=True,
    )
    c2 = ConnectorRegistration(
        connector_id="mcp_1",
        name="MCP 1",
        connector_type=ConnectorType.MCP,
        mcp_server_url="https://mcp1.com",
        enabled=False,
    )
    registry.register_connector(c1)
    registry.register_connector(c2)

    # Filter by type
    rest_only = registry.list_connectors(connector_type=ConnectorType.REST_API)
    assert len(rest_only) == 1
    assert rest_only[0].connector_id == "rest_1"

    # Filter enabled only
    enabled_only = registry.list_connectors(enabled_only=True)
    assert len(enabled_only) == 1
    assert enabled_only[0].connector_id == "rest_1"


def test_delete_connector(registry):
    """Deletes connector and ensures subsequent lookups return None."""
    reg = ConnectorRegistration(
        connector_id="del_me",
        name="To Delete",
        connector_type=ConnectorType.REST_API,
        base_url="https://del.com",
    )
    registry.register_connector(reg)
    assert registry.delete_connector("del_me") is True
    assert registry.get_connector("del_me") is None
    assert registry.delete_connector("non_existent") is False


def test_mcp_tool_registration_and_approval(registry):
    """Registers tools under an MCP connector and manages approval state."""
    mcp = ConnectorRegistration(
        connector_id="mcp_conn",
        name="MCP Server",
        connector_type=ConnectorType.MCP,
        mcp_server_url="https://mcp.com",
    )
    registry.register_connector(mcp)

    tool = McpToolDefinition(name="summarize", description="Summarize text", is_approved=False)
    registry.register_tool("mcp_conn", tool)

    # Initially unapproved
    t = registry.get_tool("mcp_conn", "summarize")
    assert t is not None
    assert t.is_approved is False

    # Explicitly approve
    assert registry.approve_tool("mcp_conn", "summarize") is True
    t_approved = registry.get_tool("mcp_conn", "summarize")
    assert t_approved.is_approved is True


def test_endpoint_path_matching(registry):
    """Validates exact and parameterized endpoint path matching."""
    conn = ConnectorRegistration(
        connector_id="user_service",
        name="User Service",
        connector_type=ConnectorType.REST_API,
        base_url="https://users.com",
        allowed_endpoints=[
            EndpointDefinition(path="/v1/users", methods=[HttpMethod.GET, HttpMethod.POST]),
            EndpointDefinition(path="/v1/users/{user_id}", methods=[HttpMethod.GET, HttpMethod.PUT]),
        ],
    )
    registry.register_connector(conn)

    # Exact match
    ep_exact = registry.match_endpoint(conn, "/v1/users", HttpMethod.GET)
    assert ep_exact is not None
    assert ep_exact.path == "/v1/users"

    # Parameterized match
    ep_param = registry.match_endpoint(conn, "/v1/users/usr_9988", HttpMethod.GET)
    assert ep_param is not None
    assert ep_param.path == "/v1/users/{user_id}"

    # Unregistered path
    ep_unreg = registry.match_endpoint(conn, "/v1/admin/debug", HttpMethod.GET)
    assert ep_unreg is None

    # Registered path with wrong method
    ep_wrong_method = registry.match_endpoint(conn, "/v1/users", HttpMethod.DELETE)
    assert ep_wrong_method is None
