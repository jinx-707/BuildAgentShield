# Backend and teammate integration

Backend integration is intentionally deferred at the user's request. This file
describes the intended boundary, not an already implemented Python interface.

## Current boundary

`frontend/src/services/demo.ts` owns the seeded records, frontend data types,
local scenario evaluator, and download helper. UI session state currently lives
in `App.tsx`. Replace these with an authenticated API client and server-derived
records; do not treat frontend permission switches as authorization.

## P1: security engine

Implement async input/output/tool-call/data inspection and risk calculation
against the future canonical Pydantic contracts. Findings must include type,
severity, reason, sanitized evidence, and location. Return the most restrictive
applicable decision. External data must retain untrusted provenance.

## P2: offline adapters

Provide side-effect-free prechecks, execute, healthcheck, and registration for
documents, scoped local files, protected system files, secrets, and isolated
terminal workers. Never run arbitrary commands or expose host resources in the
API process.

## P3: online adapters

Provide the same adapter lifecycle for browser, email, downloads, sandbox
payments, external APIs, and MCP. Preserve taint, validate domains/merchants,
and prevent uncontrolled egress. Do not send real email or payments in mock mode.

## Gateway work still required

1. Canonical strict Pydantic models and async engine/adapter interfaces.
2. Credential-derived tenant/agent identity, revocation, JWT and human roles.
3. Tool registry with strict schemas and default-deny RBAC/ABAC.
4. Fail-closed central gateway, OPA integration and policy equivalence tests.
5. PostgreSQL persistence, Redis coordination, transactional idempotency.
6. Exact-action signed approvals, expiry, atomic single-use consumption.
7. Durable append-only sanitized audit logging and hash verification.
8. Real authenticated endpoints, migrations, Docker, monitoring, SDK.
9. Integration/conformance/adversarial testing before replacing demo labels.

The original environment variable names intended for the future loader are
`P1_ENGINE`, `P2_ADAPTERS`, and `P3_ADAPTERS`. No loader consumes them yet.

## Frontend connection checklist

- Replace seeded metrics with `/v1/stats/*` queries and events with `/v1/audit`.
- Derive pending counts directly from the approvals API.
- Implement server-enforced approval permissions and display canonical actions.
- Replace demo keys with one-time real key delivery; never store raw keys.
- Persist permission/policy mutations through authorized endpoints.
- Authenticate exports, apply tenant scoping, and mask sensitive fields.
- Keep mock/real/unavailable/unhealthy status explicit.
- Remove demo sign-in only after real auth and role enforcement are tested.
- Replace local simulations with gateway proposal/execution test flows.
