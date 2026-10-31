from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from agentshield_sdk import AgentShieldClient, SecureAgent


agent_key = os.environ["AGENTSHIELD_AGENT_KEY"]
base_url = os.environ.get("AGENTSHIELD_URL", "http://127.0.0.1:8000")
secure_agent = SecureAgent(AgentShieldClient(base_url, agent_key=agent_key))
server = FastMCP("agentshield-protected-tools")


@server.tool()
def read_workspace_file(path: str) -> dict:
    """Read a workspace file through the AgentShield gateway."""
    return secure_agent.run(
        "read_file",
        {"path": path},
        source="mcp",
        user_intent="Read a workspace file requested by the user",
    )


if __name__ == "__main__":
    server.run()
