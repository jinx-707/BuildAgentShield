# AgentShield Prompt 3 — AI Agent Security Architecture & Threat Model

## Overview

Prompt 3 transforms AgentShield into an enterprise AI Agent Security Platform.
It integrates a real AI agent integration layer with the existing enforcement
architecture:

```
AI agent / caller
        |
        v
AgentShield SDK (Python / TypeScript)
        |
        v  HTTP (authenticated, org-scoped)
FastAI Agent Security API  (/v1/ai-agent/*)
        |
        v  AgentSecurityService
+-------------------------------+
| Threat Detection Engine       |  prompt injection, malicious content,
| DLP Engine                    |  suspicious navigation, data exfiltration
| Permission Governance         |  least-privilege agent capabilities
| Risk Engine                   |  explainable risk scoring
+-------------------------------+
        |
        v
DatabasePolicyEngine (PostgreSQL, org-scoped policies)
        |
        v
BrowserSecurityOrchestrator
        |
        v
Browser Worker (Puppeteer/Chromium)
        |
        v
Egress Proxy
        |
        v
Destination
```

Every AI agent action is mediated through this path. No agent action bypasses
the browser worker or egress proxy.

## Data Flow (Definition of Done)

```
User request → AI agent → AgentShield SDK → API → Policy Engine →
Browser Worker → Egress Proxy → Destination
```

The SDK authenticates with `agent_id` + `secret` (the secret is validated
against a server-side hash; it is never returned or logged). Each action
produces:

1. An `AgentExecution` record (organization-scoped).
2. Threat detections (`ThreatDetection`).
3. DLP findings (`DlpFinding`; raw values never stored).
4. A risk assessment (`RiskAssessment`; explainable).
5. A tool authorization decision (`ToolDecision`).
6. An SSE event published to the enterprise console.

## Security Boundaries

- **Untrusted content labeling**: All browser-extracted content is labeled
  `trust_label: "untrusted"` and scanned before being returned to the agent.
- **Trust boundaries**: System instructions, developer instructions, user
  instructions, retrieved webpage content, tool outputs, and external content
  are treated as distinct trust zones. Webpage content is never trusted to
  override agent policy.
- **Deterministic enforcement**: An LLM classifier is never the only security
  boundary. Critical actions are controlled by deterministic policy and pattern
  detection. Prompt-injection prevention is best-effort; we do not claim
  universal prevention.
- **Multi-tenancy**: Every record is organization-scoped. Cross-tenant access
  is impossible by construction (all queries filter by `organization_id`).
- **No secret logging**: Raw secrets, credentials, and sensitive browser
  content are never logged or persisted.

## Detection Modules

| Module | Threat Category | Method |
|--------|----------------|--------|
| Prompt injection | indirect_prompt_injection | Pattern-based |
| Malicious content | malicious_webpage_instructions | Pattern-based |
| Navigation | suspicious_navigation | Pattern-based (metadata, localhost, private nets) |
| Data exfiltration | data_exfiltration_attempt | Pattern-based |
| DLP | sensitive_information_exposure | Configurable regex rules |

## Risk Scoring

Risk scores (0-100) are computed from detection severity/confidence, agent
permissions, destination sensitivity, and prior violations. Scores are
explainable (each factor is listed) and never override a deterministic deny
decision.

## Persistence

New tables (migration `0002_ai_agent_security`): `agent_executions`,
`threat_detections`, `risk_assessments`, `dlp_findings`, `tool_decisions`,
`attack_simulation_runs`, `scenario_evidence`. All organization-scoped.

## API

`/v1/ai-agent/authenticate`, `/v1/ai-agent/action`,
`/v1/ai-agent/organizations/{org}/executions|threats|dlp|risk|tools`,
`/v1/attack-simulation/scenarios|run|runs|runs/{id}`.

## Limitations

- Detection is heuristic/pattern-based; novel obfuscation may evade detection.
- No LLM classifier is used as a security boundary.
- Attack simulation targets are local loopback mocks, not production systems.
- SSE event delivery is single-process (in-memory broadcaster); Redis pub/sub
  would be needed for multi-replica deployments.
