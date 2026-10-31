from __future__ import annotations

import os

from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode

from agentshield_sdk import AgentShieldClient, SecureAgent


agent_key = os.environ["AGENTSHIELD_AGENT_KEY"]
base_url = os.environ.get("AGENTSHIELD_URL", "http://127.0.0.1:8000")
secure_agent = SecureAgent(AgentShieldClient(base_url, agent_key=agent_key))


@tool
def read_document(document: str) -> dict:
    """Read a document only after the AgentShield gateway allows it."""
    return secure_agent.run(
        "read_document",
        {"document": document},
        source="langgraph",
        user_intent="Read a document for the current task",
    )


tools = ToolNode([read_document])
