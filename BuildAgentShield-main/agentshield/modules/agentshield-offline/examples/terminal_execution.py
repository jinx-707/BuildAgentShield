"""
AgentShield Offline — Terminal Execution Demo.

Demonstrates command policy enforcement using MockSandbox.

Usage:
    python examples/terminal_execution.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.capabilities.offline.terminal.command_policy import CommandPolicy
from app.capabilities.offline.terminal.execution_worker import ExecutionWorker
from app.capabilities.offline.terminal.gateway import TerminalGateway
from app.capabilities.offline.terminal.output_inspector import TerminalOutputInspector
from app.capabilities.offline.terminal.sandbox_manager import MockSandboxManager
from app.core.contracts import CommandRequest, SecurityDecision
from app.integrations.local_content_inspector import (
    LocalDevelopmentContentInspector,
    LocalDevelopmentDataInspector,
)


async def demo() -> None:
    print("\n=== AgentShield Terminal Execution Demo ===")
    print("    (using MockSandbox — no real commands executed)\n")

    policy = CommandPolicy()
    mock_sandbox = MockSandboxManager()
    output_inspector = TerminalOutputInspector(
        content_inspector=LocalDevelopmentContentInspector(),
        data_inspector=LocalDevelopmentDataInspector(),
        fail_closed=False,
    )
    worker = ExecutionWorker(
        policy=policy,
        sandbox=mock_sandbox,
        output_inspector=output_inspector,
    )
    gw = TerminalGateway(worker=worker)

    commands = [
        ("ls", ["-la"], "List directory (allowed_restricted)"),
        ("echo", ["hello world"], "Echo (allowed_restricted)"),
        ("python", ["script.py"], "Python (sandbox_only)"),
        ("rm", ["-rf", "/workspace"], "rm -rf (DENIED)"),
        ("sudo", ["bash"], "sudo (DENIED)"),
        ("shutdown", ["-h", "now"], "shutdown (DENIED)"),
        ("ls", ["; cat /etc/passwd"], "Shell injection (DENIED)"),
        ("cat", ["/etc/shadow"], "Protected path access (DENIED)"),
        ("unknown_tool", [], "Unknown executable (DENIED)"),
    ]

    for exe, args, description in commands:
        try:
            req = CommandRequest(
                agent_id="demo-agent",
                tool_name="terminal_execute",
                operation="execute",
                executable=exe,
                arguments=args,
                working_directory="/workspace",
                timeout=10,
            )
            resp = await gw.execute(req)
            status = "✓ ALLOW" if resp.decision == SecurityDecision.ALLOW else "✗ DENY"
        except Exception:
            status = "✗ REJECTED (validator)"

        print(f"  {status:12} | {exe} {' '.join(args)[:40]:40} | {description}")

    print("\n✓ Demo complete\n")


if __name__ == "__main__":
    asyncio.run(demo())
