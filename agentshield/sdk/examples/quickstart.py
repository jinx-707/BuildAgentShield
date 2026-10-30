from __future__ import annotations

import json
import os

from agentshield_sdk import AgentShieldClient


base_url = os.environ.get("AGENTSHIELD_URL", "http://127.0.0.1:8000")
agent_key = os.environ.get("AGENTSHIELD_AGENT_KEY")

if not agent_key:
    raise SystemExit("Set AGENTSHIELD_AGENT_KEY to an agent key created in the dashboard.")

with AgentShieldClient(base_url, agent_key=agent_key) as client:
    print("readiness:", json.dumps(client.health(), indent=2))
    response = client.execute_once(
        "read_document",
        {"document": "quarterly-report.pdf"},
        source="email-inbox",
        trust="untrusted",
        data_classification="sensitive",
        user_intent="Summarize the quarterly report",
    )
    print("decision:", json.dumps(response, indent=2))
