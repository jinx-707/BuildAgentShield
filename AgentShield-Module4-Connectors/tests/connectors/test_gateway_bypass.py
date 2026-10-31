"""
Security Tests: Gateway Bypass Prevention.
Verifies that:
  - Every external tool and API execution MUST traverse the central SecurityGateway.
  - No direct or uninspected execution path exists.
  - Direct calls to internal connectors with unregistered endpoints or unapproved tools fail.
  - Forged permissions or client-supplied credentials cannot bypass gateway inspection.
"""

import httpx
import pytest

from core.connectors.api_connector import RestApiConnector
from core.connectors.gateway import SecurityGateway
from core.connectors.mcp_connector import McpConnector
from core.connectors.models import (
    AgentPermissionRule,
    ConnectorRegistration,
    ConnectorType,
    EndpointDefinition,
    ExecutionRequest,
    ExecutionStatus,
    HttpMethod,
    McpToolDefinition,
    PermissionAction,
    SSRFSecurityError,
    UnregisteredToolError,
)
from core.connectors.permissions import PermissionManager
from core.connectors.registry import ConnectorRegistry


@pytest.fixture
def isolated_gateway():
    registry = ConnectorRegistry()
    permissions = PermissionManager()
    gw = SecurityGateway(registry=registry, permission_manager=permissions)
    return gw, registry, permissions


@pytest.mark.anyio
async def test_bypass_unregistered_connector_rejected(isolated_gateway):
    """An agent cannot execute against any connector that has not been formally registered."""
    gw, _, _ = isolated_gateway
    req = ExecutionRequest(
        agent_id="attacker_agent",
        connector_id="unregistered_stealth_connector",
        endpoint="/data",
        method=HttpMethod.GET,
    )
    resp = await gw.execute(req)

    assert resp.allowed is False
    assert resp.status == ExecutionStatus.REJECTED
    assert "not registered in AgentShield registry" in resp.rejection_reason
    assert resp.audit_record is not None


@pytest.mark.anyio
async def test_bypass_client_permission_spoofing_prevented(isolated_gateway):
    """Client-supplied metadata or headers claiming admin rights are ignored; server-side rule dictates."""
    gw, registry, permissions = isolated_gateway

    reg = ConnectorRegistration(
        connector_id="secure_finance",
        name="Finance",
        connector_type=ConnectorType.REST_API,
        base_url="https://finance.internal.test",
        allowed_endpoints=[EndpointDefinition(path="/transfer", methods=[HttpMethod.POST])],
    )
    registry.register_connector(reg)

    # Server denies the agent
    permissions.grant_permission(
        AgentPermissionRule(
            agent_id="unprivileged_agent",
            connector_id="secure_finance",
            action=PermissionAction.DENY,
        )
    )

    # Client tries to spoof headers/metadata claiming it is an admin
    spoofed_req = ExecutionRequest(
        agent_id="unprivileged_agent",
        connector_id="secure_finance",
        endpoint="/transfer",
        method=HttpMethod.POST,
        headers={"X-User-Role": "admin", "X-Bypass-Security": "true"},
        metadata={"is_admin": True, "permission_override": "allow"},
    )
    resp = await gw.execute(spoofed_req)

    assert resp.allowed is False
    assert resp.status == ExecutionStatus.REJECTED
    assert "Policy explicitly denies" in resp.rejection_reason


@pytest.mark.anyio
async def test_mcp_unapproved_tool_direct_call_fails():
    """Directly calling call_tool on McpConnector without approval fails with UnregisteredToolError."""
    connector = McpConnector()
    reg = ConnectorRegistration(
        connector_id="mcp_test",
        name="MCP Test",
        connector_type=ConnectorType.MCP,
        mcp_server_url="https://mcp.test/rpc",
    )
    unapproved = McpToolDefinition(name="unapproved_exec", is_approved=False)

    with pytest.raises(UnregisteredToolError, match="has not been approved"):
        await connector.call_tool(reg, unapproved, arguments={})


def test_api_connector_direct_ssrf_fails():
    """Direct call to validate_destination_safety on REST API connector fails on loopback/private destinations."""
    with pytest.raises(SSRFSecurityError, match="forbidden local or cloud metadata host"):
        RestApiConnector.validate_destination_safety("http://localhost:8000/keys", allow_private=False)

    with pytest.raises(SSRFSecurityError, match="metadata"):
        RestApiConnector.validate_destination_safety("http://169.254.169.254/secret", allow_private=False)
