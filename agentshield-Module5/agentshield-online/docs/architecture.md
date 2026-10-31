# AgentShield Online — Architecture

## Overview

Every external operation an AI agent requests flows through a security gateway before execution. The gateway enforces policy, inspects content, requires approval where needed, and records an audit event.

```
AI Agent Request
      │
      ▼
FastAPI Route
      │
      ▼
Auth Context (local dev / Person 4 in production)
      │
      ▼
Capability Gateway
  ├── Policy check (LocalPolicyAdapter / OPA)
  ├── URL / schema / recipient validation
  ├── Content / DLP inspection (Local / Person 1)
  ├── Approval check (Local / Person 4)
  ├── Execute operation
  ├── Response inspection
  └── Audit record (Local / Person 4)
      │
      ▼
GatewayResponse (standardised)
```

## Integration Ports

The module uses dependency-inversion for all shared services:

| Port | Local Adapter | Production Adapter |
|---|---|---|
| `ContentInspectionPort` | `LocalContentInspectionAdapter` | Person 1 |
| `DataInspectionPort` | `LocalDataInspectionAdapter` | Person 1 |
| `PolicyPort` | `LocalPolicyAdapter` (default-deny) | Person 4 / OPA |
| `ApprovalPort` | `LocalApprovalAdapter` (explicit grant) | Person 4 |
| `AuditPort` | `LocalAuditAdapter` (JSON logs) | Person 4 |
| `SecretProviderPort` | `LocalEnvSecretProvider` | Vault |

## Key Security Principles

1. **Fail closed** — if a required security service is unavailable, the operation is denied
2. **Untrusted external content** — all webpage, email and MCP content is tagged `trust_level: untrusted`
3. **Exact-action binding** — approvals are cryptographically bound to the exact transaction details
4. **No raw credentials to LLM** — credentials are injected server-side only
5. **Test mode only for payments** — runtime guard prevents live payment keys
6. **Atomic spending limits** — database-level locking prevents concurrent bypass
