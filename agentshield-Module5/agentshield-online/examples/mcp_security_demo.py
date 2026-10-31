"""
MCP Security Demo.
Run: python -m examples.mcp_security_demo
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("PAYMENT_MODE", "test")

from app.capabilities.online.mcp.server_registry import MCPServerRegistry, MCPServerConfig
from app.capabilities.online.mcp.tool_registry import ToolRegistry
from app.capabilities.online.mcp.mcp_gateway import MCPGateway
from app.integrations.local_security_adapter import LocalContentInspectionAdapter, LocalDataInspectionAdapter
from app.integrations.local_policy_adapter import LocalPolicyAdapter
from app.integrations.local_approval_adapter import LocalApprovalAdapter
from app.integrations.local_audit_adapter import LocalAuditAdapter
from app.integrations.secret_provider import LocalEnvSecretProvider
from app.core.security_context import build_security_context
from app.core.exceptions import MCPServerUnregisteredError, MCPToolUnauthorizedError
from app.core.decisions import SecurityDecision


async def demo():
    print("=" * 60)
    print("AgentShield MCP Security Demo")
    print("=" * 60)

    # Setup registry
    registry = MCPServerRegistry.__new__(MCPServerRegistry)
    registry._servers = {}
    registry._defaults = {}
    registry.register(MCPServerConfig(
        id="test_server",
        name="AgentShield Test Server",
        url="http://localhost:8001",
        allowed_tools=["echo", "get_weather", "search_documents"],
        blocked_tools=["execute_code", "run_shell", "delete_files"],
        approval_required_tools=["send_notification"],
    ))

    gateway = MCPGateway(
        policy=LocalPolicyAdapter(),
        audit=LocalAuditAdapter(),
        content_inspector=LocalContentInspectionAdapter(),
        data_inspector=LocalDataInspectionAdapter(),
        approval=LocalApprovalAdapter(),
        server_registry=registry,
        tool_registry=ToolRegistry(),
        secret_provider=LocalEnvSecretProvider(),
        use_mock=True,
    )

    ctx = build_security_context(
        agent_id="agent_demo", tenant_id="tenant_demo",
        capability="mcp", operation="invoke"
    )

    # ── 1. Unregistered Server ─────────────────────────────────────────────
    print("\n[1] Unregistered Server Access")
    try:
        await gateway.invoke(ctx, "unknown_server", "echo", {"message": "hi"})
        print("  ✗ FAILED to block unregistered server")
    except MCPServerUnregisteredError as e:
        print(f"  ✓ BLOCKED: {str(e)[:70]}")

    # ── 2. Blocked Tools ──────────────────────────────────────────────────
    print("\n[2] Blocked Tool Invocations")
    blocked_tools = ["execute_code", "run_shell", "delete_files"]
    for tool in blocked_tools:
        try:
            await gateway.invoke(ctx, "test_server", tool, {"arg": "value"})
            print(f"  ✗ FAILED to block tool: {tool}")
        except MCPToolUnauthorizedError as e:
            print(f"  ✓ BLOCKED: {tool}")

    # ── 3. Allowed Tool ───────────────────────────────────────────────────
    print("\n[3] Allowed Tool Execution")
    response = await gateway.invoke(ctx, "test_server", "echo", {"message": "Hello AgentShield"})
    if response.decision == SecurityDecision.ALLOW:
        print(f"  ✓ ALLOWED: echo tool executed")
        print(f"  ✓ Result trust note: {response.result.get('trust_note', 'N/A')[:50]}")
    else:
        print(f"  ✗ Unexpectedly denied")

    # ── 4. Tool Response Content Inspection ───────────────────────────────
    print("\n[4] Tool Response Inspection (Untrusted)")
    # Tool response is always treated as untrusted
    response = await gateway.invoke(ctx, "test_server", "echo", {"message": "test"})
    assert "trust_note" in response.result, "Trust note should be present"
    print(f"  ✓ Tool response marked untrusted: trust_note present")
    print(f"  ✓ Response inspected: {response.result.get('inspected', False)}")

    # ── 5. Tool Not In Allowlist ──────────────────────────────────────────
    print("\n[5] Tool Not in Allowlist")
    try:
        await gateway.invoke(ctx, "test_server", "arbitrary_tool_from_llm", {})
        print("  ✗ FAILED to block unauthorized tool")
    except MCPToolUnauthorizedError as e:
        print(f"  ✓ BLOCKED: unauthorized tool")

    # ── 6. List Tools ─────────────────────────────────────────────────────
    print("\n[6] Tool Discovery")
    list_response = await gateway.list_tools(ctx, server_id="test_server")
    tools = list_response.result.get("tools", [])
    print(f"  ✓ {len(tools)} allowed tools discoverable")
    for t in tools:
        print(f"    - {t['tool_name']}")

    print("\n" + "=" * 60)
    print("MCP security demo complete.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(demo())
