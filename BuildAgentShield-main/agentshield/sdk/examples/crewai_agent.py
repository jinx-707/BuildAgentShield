from __future__ import annotations

import os

from crewai.tools import tool

from agentshield_sdk import AgentShieldClient, SecureAgent


agent_key = os.environ["AGENTSHIELD_AGENT_KEY"]
base_url = os.environ.get("AGENTSHIELD_URL", "http://127.0.0.1:8000")
secure_agent = SecureAgent(AgentShieldClient(base_url, agent_key=agent_key))


@tool("Send an approved email")
def send_email(to: str, subject: str, body: str) -> dict:
    return secure_agent.run(
        "send_email",
        {"to": to, "subject": subject, "body": body},
        source="crewai",
        user_intent="Send an email requested by the user",
    )
