# AgentShield Prompt 3 — Agent Integration Guide

AgentShield provides SDKs for Python and TypeScript so real AI agents can
execute browser actions through the AgentShield enforcement architecture:

```
AI agent → SDK → AgentShield API → Policy Engine → Browser Worker →
Egress Proxy → Destination
```

## Authentication

Agents authenticate with an `agent_id` and `secret` issued by AgentShield
(organization-scoped, created via `/v1/organizations/{org_id}/agents`). The
secret is validated against a server-side bcrypt hash. It is never returned by
the API and never logged by the SDK.

### Python SDK

```python
from agentshield import AgentShieldClient

client = AgentShieldClient(
    base_url="http://localhost:8000",
    agent_id="agent-abc123",
    secret="<agent-secret-returned-once>",
)
client.authenticate()

result = client.navigate(
    url="https://example.com",
    session_id="session-1",
)
print(result["decision"])   # allow | deny | require_approval
print(result["risk_score"]) # 0-100
print(result["threat"])     # threat detections
print(result["dlp"])        # DLP findings
```

### TypeScript SDK

```ts
import { AgentShieldClient } from "@agentshield/sdk";

const client = new AgentShieldClient({
  baseUrl: "http://localhost:8000",
  agentId: "agent-abc123",
  secret: "<agent-secret-returned-once>",
});
await client.authenticate();

const result = await client.navigate({
  url: "https://example.com",
  sessionId: "session-1",
});
console.log(result.decision);
console.log(result.riskScore);
```

## Agent Actions

| Action | Description | Required permission |
|--------|-------------|---------------------|
| navigate | Browser navigation | browser_navigation |
| click | Page click | page_interaction |
| type | Page text input | page_interaction |
| scroll | Page scroll | page_interaction |
| extract | Data extraction | data_extraction |
| screenshot | Page screenshot | page_interaction |
| tool_call | Agent tool invocation | external_communication |
| file_download | File download | file_downloads |
| form_submit | Form submission | form_submission |
| sensitive_access | Sensitive data access | sensitive_data_access |

Agents use least-privilege defaults. Actions not in the agent's permission set
are denied or require approval. Every tool invocation is checked against the
agent's effective permissions and organization policy.

## Security Responses

Each action result includes:

- `decision`: `allow`, `deny`, or `require_approval`
- `reason`: human-readable enforcement reason
- `severity`: low/medium/high/critical
- `risk_score`: 0-100 explainable risk score
- `threat`: threat detections (category, module, severity)
- `dlp`: DLP findings (rule, action taken)
- `risk`: risk assessment with reasons and factors
- `enforcement`: underlying worker/proxy enforcement detail (for navigate)

## Provider Abstraction

The SDK is LLM-provider agnostic: it mediates whatever browser actions the AI
agent decides to take, regardless of which model provider powers the agent.
Provider credentials live on the server/application side, never in the SDK.

## Security Notes

- The agent must not bypass AgentShield when executing protected browser
  actions. All protected actions go through the SDK → API path.
- Prompt-injection detection is heuristic; we do not claim universal
  prevention. Critical actions are controlled by deterministic policy.
- Raw secrets and sensitive values are never logged.
