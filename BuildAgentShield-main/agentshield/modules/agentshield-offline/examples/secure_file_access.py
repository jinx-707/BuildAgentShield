"""
AgentShield Offline — Secure File Access Demo.

Demonstrates workspace-scoped file read, write, and access control.

Usage:
    python examples/secure_file_access.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.capabilities.offline.local_files.directory_scopes import (
    AgentFilesystemConfig,
    DirectoryScopeRegistry,
)
from app.capabilities.offline.local_files.filesystem_gateway import LocalFilesystemGateway
from app.core.contracts import (
    FileCreateRequest,
    FileDeleteRequest,
    FileReadRequest,
    SecurityDecision,
)


async def demo() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "docs").mkdir()
        (tmp / "output").mkdir()
        (tmp / "docs" / "report.txt").write_text(
            "Q3 Financial Report\nRevenue: $1.2M\nGrowth: 15%"
        )

        # Configure registry manually for demo
        registry = DirectoryScopeRegistry.__new__(DirectoryScopeRegistry)
        registry._agents = {
            "analyst-agent": AgentFilesystemConfig(
                agent_id="analyst-agent",
                workspace=str(tmp),
                read_paths=[str(tmp / "docs")],
                write_paths=[str(tmp / "output")],
                delete_paths=[str(tmp / "output")],
            )
        }
        gw = LocalFilesystemGateway(scope_registry=registry)

        print("\n=== AgentShield Secure File Access Demo ===\n")

        # 1. Authorized read
        resp = await gw.read_file(FileReadRequest(
            agent_id="analyst-agent",
            tool_name="file_access",
            operation="read",
            file_path=str(tmp / "docs" / "report.txt"),
        ))
        print(f"[READ authorized file]  → {resp.decision.value}")
        if resp.result:
            print(f"  Content: {resp.result['content'][:50]}...")

        # 2. Unauthorized read (output dir not in read permissions)
        resp2 = await gw.read_file(FileReadRequest(
            agent_id="analyst-agent",
            tool_name="file_access",
            operation="read",
            file_path=str(tmp / "output" / "anything.txt"),
        ))
        print(f"\n[READ unauthorized dir] → {resp2.decision.value} (expected DENY)")

        # 3. Authorized write
        resp3 = await gw.create_file(FileCreateRequest(
            agent_id="analyst-agent",
            tool_name="file_access",
            operation="create",
            file_path=str(tmp / "output" / "analysis.txt"),
            content="Analysis complete. See attached report.",
        ))
        print(f"\n[WRITE authorized dir]  → {resp3.decision.value}")

        # 4. Path traversal attack attempt
        resp4 = await gw.read_file(FileReadRequest(
            agent_id="analyst-agent",
            tool_name="file_access",
            operation="read",
            file_path=str(tmp / "docs" / ".." / ".." / "etc" / "passwd"),
        ))
        print(f"\n[TRAVERSAL attack]      → {resp4.decision.value} (expected DENY)")

        # 5. Delete authorized file
        resp5 = await gw.delete_file(FileDeleteRequest(
            agent_id="analyst-agent",
            tool_name="file_access",
            operation="delete",
            file_path=str(tmp / "output" / "analysis.txt"),
        ))
        print(f"\n[DELETE authorized]     → {resp5.decision.value}")

        print("\n✓ Demo complete\n")


if __name__ == "__main__":
    asyncio.run(demo())
