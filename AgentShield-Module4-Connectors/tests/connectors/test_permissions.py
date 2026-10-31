"""
Unit & Integration Tests for AgentShield Per-Agent Tool Permissions.
Tests:
  - Default-deny behavior
  - Explicit DENY
  - READ_ONLY, READ_WRITE, ADMIN, and CUSTOM scopes
  - Method constraints (GET, POST, PUT, DELETE)
  - Tool restrictions (allowed_tools, denied_tools)
  - Privilege escalation & argument tampering detection
  - Wildcard agent support
"""

import pytest

from core.connectors.models import (
    AgentPermissionRule,
    HttpMethod,
    PermissionAction,
    PermissionScope,
)
from core.connectors.permissions import PermissionManager


@pytest.fixture
def manager():
    return PermissionManager()


def test_default_deny(manager):
    """An agent with no registered rule must be denied by default."""
    allowed, reason = manager.check_permission(
        agent_id="unknown_agent",
        connector_id="some_api",
        method=HttpMethod.GET,
    )
    assert allowed is False
    assert "No permission rule granted" in reason


def test_explicit_deny(manager):
    """An explicit DENY rule must override and block access."""
    rule = AgentPermissionRule(
        agent_id="agent_1",
        connector_id="finance_api",
        action=PermissionAction.DENY,
    )
    manager.grant_permission(rule)

    allowed, reason = manager.check_permission("agent_1", "finance_api", method=HttpMethod.GET)
    assert allowed is False
    assert "explicitly denies" in reason


def test_read_only_scope(manager):
    """READ_ONLY scope allows GET/HEAD and strictly blocks mutating methods."""
    rule = AgentPermissionRule(
        agent_id="researcher",
        connector_id="docs_api",
        action=PermissionAction.ALLOW,
        scope=PermissionScope.READ_ONLY,
    )
    manager.grant_permission(rule)

    # Allowed safe methods
    ok_get, _ = manager.check_permission("researcher", "docs_api", method=HttpMethod.GET)
    assert ok_get is True

    ok_head, _ = manager.check_permission("researcher", "docs_api", method=HttpMethod.HEAD)
    assert ok_head is True

    # Blocked mutating methods
    ok_post, r_post = manager.check_permission("researcher", "docs_api", method=HttpMethod.POST)
    assert ok_post is False
    assert "READ_ONLY scope prohibits mutating method 'POST'" in r_post

    ok_del, r_del = manager.check_permission("researcher", "docs_api", method=HttpMethod.DELETE)
    assert ok_del is False
    assert "READ_ONLY scope prohibits mutating method 'DELETE'" in r_del


def test_read_write_scope(manager):
    """READ_WRITE scope allows GET, POST, PUT, PATCH but forbids DELETE."""
    rule = AgentPermissionRule(
        agent_id="editor",
        connector_id="cms_api",
        action=PermissionAction.ALLOW,
        scope=PermissionScope.READ_WRITE,
    )
    manager.grant_permission(rule)

    assert manager.check_permission("editor", "cms_api", method=HttpMethod.GET)[0] is True
    assert manager.check_permission("editor", "cms_api", method=HttpMethod.POST)[0] is True
    assert manager.check_permission("editor", "cms_api", method=HttpMethod.PUT)[0] is True

    ok_del, r_del = manager.check_permission("editor", "cms_api", method=HttpMethod.DELETE)
    assert ok_del is False
    assert "READ_WRITE scope does not permit destructive DELETE" in r_del


def test_admin_scope(manager):
    """ADMIN scope permits all methods including DELETE."""
    rule = AgentPermissionRule(
        agent_id="super_admin",
        connector_id="admin_service",
        action=PermissionAction.ALLOW,
        scope=PermissionScope.ADMIN,
    )
    manager.grant_permission(rule)

    assert manager.check_permission("super_admin", "admin_service", method=HttpMethod.DELETE)[0] is True
    assert manager.check_permission("super_admin", "admin_service", method=HttpMethod.POST)[0] is True


def test_tool_name_restrictions(manager):
    """Validates allowed_tools and denied_tools enforcement for MCP/tool calls."""
    rule = AgentPermissionRule(
        agent_id="agent_mcp",
        connector_id="mcp_server",
        action=PermissionAction.ALLOW,
        allowed_tools=["calculator", "web_search"],
        denied_tools=["file_delete"],
    )
    manager.grant_permission(rule)

    # Allowed
    assert manager.check_permission("agent_mcp", "mcp_server", tool_name="calculator")[0] is True
    assert manager.check_permission("agent_mcp", "mcp_server", tool_name="web_search")[0] is True

    # Not in allowed list
    ok_bash, r_bash = manager.check_permission("agent_mcp", "mcp_server", tool_name="bash_exec")
    assert ok_bash is False
    assert "not in permitted tool list" in r_bash

    # Explicitly denied
    ok_del, r_del = manager.check_permission("agent_mcp", "mcp_server", tool_name="file_delete")
    assert ok_del is False
    assert "explicitly denied" in r_del


def test_privilege_escalation_detection(manager):
    """Detects and blocks parameter tampering aiming to escalate permissions."""
    rule = AgentPermissionRule(
        agent_id="user_agent",
        connector_id="crm_api",
        action=PermissionAction.ALLOW,
        scope=PermissionScope.READ_WRITE,
        argument_constraints={"account_id": "acc_1001"},
    )
    manager.grant_permission(rule)

    # Valid arguments
    ok, _ = manager.check_permission(
        "user_agent", "crm_api", method=HttpMethod.POST,
        arguments={"account_id": "acc_1001", "name": "Jane"}
    )
    assert ok is True

    # Escalation: tampering with account_id
    ok_tamper, r_tamper = manager.check_permission(
        "user_agent", "crm_api", method=HttpMethod.POST,
        arguments={"account_id": "acc_9999", "name": "Jane"}
    )
    assert ok_tamper is False
    assert "Privilege escalation blocked" in r_tamper

    # Escalation: injecting forbidden key 'role'
    ok_role, r_role = manager.check_permission(
        "user_agent", "crm_api", method=HttpMethod.POST,
        arguments={"account_id": "acc_1001", "role": "admin"}
    )
    assert ok_role is False
    assert "unauthorized parameter 'role'" in r_role

    # Escalation: nested sudo/privilege parameter
    ok_nested, r_nested = manager.check_permission(
        "user_agent", "crm_api", method=HttpMethod.POST,
        arguments={"options": {"sudo": True}}
    )
    assert ok_nested is False
    assert "unauthorized parameter 'sudo'" in r_nested


def test_permission_revocation(manager):
    """Revoking a permission returns the agent to default-deny."""
    rule = AgentPermissionRule(
        agent_id="temp_agent",
        connector_id="temp_api",
        action=PermissionAction.ALLOW,
    )
    manager.grant_permission(rule)
    assert manager.check_permission("temp_agent", "temp_api", method=HttpMethod.GET)[0] is True

    manager.revoke_permission("temp_agent", "temp_api")
    assert manager.check_permission("temp_agent", "temp_api", method=HttpMethod.GET)[0] is False
