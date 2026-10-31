"""
AgentShield Offline — Environment Protection Demo.

Demonstrates secret isolation, variable access control, and minimal env building.

Usage:
    python examples/environment_protection.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.capabilities.offline.environment.environment_guard import EnvironmentGuard
from app.capabilities.offline.environment.environment_policy import EnvironmentPolicy
from app.capabilities.offline.environment.gateway import EnvironmentGateway
from app.capabilities.offline.environment.secret_broker import SecretBroker
from app.capabilities.offline.environment.secret_provider import MockSecretProvider
from app.core.contracts import EnvironmentInspectRequest, SecretAccessRequest, SecurityDecision


async def demo() -> None:
    print("\n=== AgentShield Environment Protection Demo ===\n")

    # Set up policy with a small allowlist
    policy = EnvironmentPolicy.__new__(EnvironmentPolicy)
    policy._global_allowlist = {"TZ", "LANG", "LC_ALL", "PYTHONPATH"}
    policy._global_denylist = set()
    policy._agent_configs = {}

    guard = EnvironmentGuard(policy)
    provider = MockSecretProvider(secrets={
        "app-db-password": "prod-db-password-example",
        "service-api-key": "svc-key-12345",
    })
    broker = SecretBroker(
        provider=provider,
        permitted_secrets={
            "app-db-password": ["db-agent"],
            "service-api-key": ["api-agent", "db-agent"],
        },
    )
    gw = EnvironmentGateway(policy=policy, guard=guard, secret_broker=broker)

    # --- 1. Check which variables are allowed ---
    print("1. Checking environment variable access:")
    vars_to_check = ["TZ", "LANG", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH"]
    req = EnvironmentInspectRequest(
        agent_id="db-agent",
        tool_name="environment_inspect",
        operation="inspect",
        variable_names=vars_to_check,
    )
    resp = await gw.inspect(req)
    print(f"   Allowed: {resp.result['allowed_variables']}")
    print(f"   Denied:  {list(resp.result['denied_variables'].keys())}")

    # --- 2. Build minimal environment (never passes host secrets) ---
    print("\n2. Building minimal subprocess environment:")
    os.environ["OPENAI_API_KEY"] = "sk-test-should-not-appear"  # Simulate host secret
    minimal = guard.build_minimal_env(
        agent_id="db-agent",
        explicit_additions={"TZ": "UTC", "OPENAI_API_KEY": "attempt-to-inject"},
    )
    print(f"   Environment keys: {sorted(minimal.keys())}")
    print(f"   Contains OPENAI_API_KEY: {'OPENAI_API_KEY' in minimal}")
    assert "OPENAI_API_KEY" not in minimal
    os.environ.pop("OPENAI_API_KEY", None)

    # --- 3. Permitted secret retrieval ---
    print("\n3. Secret retrieval (db-agent, permitted):")
    req2 = SecretAccessRequest(
        agent_id="db-agent",
        tool_name="secret_access",
        operation="retrieve",
        secret_id="app-db-password",
        purpose="database connection",
    )
    resp2 = await gw.access_secret(req2)
    print(f"   Decision:  {resp2.decision.value}")
    print(f"   Retrieved: {resp2.result.get('retrieved')}")
    print(f"   Secret value in response: {'prod-db-password-example' not in str(resp2.result)}")

    # --- 4. Denied secret retrieval ---
    print("\n4. Secret retrieval (wrong agent, denied):")
    req3 = SecretAccessRequest(
        agent_id="untrusted-agent",
        tool_name="secret_access",
        operation="retrieve",
        secret_id="app-db-password",
    )
    resp3 = await gw.access_secret(req3)
    print(f"   Decision: {resp3.decision.value} (expected DENY)")

    print("\n✓ Demo complete\n")


if __name__ == "__main__":
    asyncio.run(demo())
