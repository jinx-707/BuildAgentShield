from __future__ import annotations

import json
import os

from agentshield_sdk import AgentShieldClient


base_url = os.environ.get("AGENTSHIELD_URL", "http://127.0.0.1:8000")
agent_key = os.environ.get("AGENTSHIELD_AGENT_KEY")
dashboard_token = os.environ.get("AGENTSHIELD_DASHBOARD_TOKEN")

if not agent_key or not dashboard_token:
    raise SystemExit(
        "Set AGENTSHIELD_AGENT_KEY and AGENTSHIELD_DASHBOARD_TOKEN "
        "to run the approval example."
    )

arguments = {"amount": 120, "currency": "USD", "merchant": "Acme Software"}

with AgentShieldClient(
    base_url, agent_key=agent_key, dashboard_token=dashboard_token
) as client:
    proposal = client.propose(
        "initiate_payment",
        arguments,
        source="shopping-agent",
        trust="trusted",
        user_intent="Buy a team license",
    )
    print("proposal:", json.dumps(proposal, indent=2))
    approval_id = proposal.get("approval_id")
    if proposal.get("decision") != "REQUIRE_APPROVAL" or not approval_id:
        raise SystemExit("The gateway did not request approval for this action.")

    approved = client.approve(approval_id, comment="Approved by SDK reviewer")
    print("approval:", json.dumps(approved, indent=2))

    result = client.execute_once(
        "initiate_payment",
        arguments,
        source="shopping-agent",
        trust="trusted",
        user_intent="Buy a team license",
        approval_token=approved["token"],
    )
    print("result:", json.dumps(result, indent=2))
