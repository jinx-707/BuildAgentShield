# Backend and teammate integration

The backend, dashboard client, and SDK are implemented in this repository.
P1, P2, and P3 currently use safe mock implementations behind stable interfaces.
Unavailable integrations deny requests; they never bypass the gateway.

## Integration status model

Every integration reports one of:

- `REAL`: a real teammate implementation is connected and healthy.
- `MOCK`: the built-in deterministic mock is active.
- `UNAVAILABLE`: the integration cannot be reached; the gateway fails closed.
- `UNHEALTHY`: the integration is reachable but not healthy; the gateway fails
  closed where required.

This status is exposed by `/api/v1/integrations/health` and shown in the
dashboard. `/ready` reports overall readiness.

## Frontend boundary

`frontend/src/services/api.ts` is the only network boundary. It owns the API
base URL, bearer token storage (`agentshield.access_token`), session user cache
(`agentshield.session_user`), typed requests, and endpoint helpers.

Backend mode:

1. Restore a stored session or auto-login with
   `VITE_AGENTSHIELD_DEMO_EMAIL` / `VITE_AGENTSHIELD_DEMO_PASSWORD`.
2. Load agents, approvals, audit, policies, quarantine, workspace, stats, tools,
   and integration health from the API.
3. Send mutations through the API and refresh affected state.
4. Keep approval decisions, key rotation, policy activation, audit verification,
   quarantine release, and simulator execution server-side.

If auto-connect or restoration fails, the dashboard resets to the original
in-browser demo. Demo mode is intentionally not a security boundary.

Base URL rules:

- `VITE_AGENTSHIELD_API_URL` includes the full `/api/v1` root.
- Managed preview / `file:` default: `http://127.0.0.1:8000/api/v1`.
- Otherwise default: `${window.location.origin}/api/v1` (nginx proxies `/api/`).
- `VITE_AGENTSHIELD_AUTO_CONNECT=false` disables automatic connection.

## Backend boundary

- Dashboard routes require a bearer JWT and tenant/role checks.
- Agent runtime routes require `X-Agent-Key`; approval execution also requires
  `X-Approval-Token`.
- `Idempotency-Key` makes execution retries safe.
- The gateway validates the tool, validates strict arguments, inspects with P1,
  evaluates policy, checks approval/taint/scope constraints, executes through an
  adapter, and writes a sanitized audit event.
- Dashboard endpoints are tenant scoped; cross-tenant identifiers return 404.
- Audit reads are sanitized; raw arguments and secrets are not exposed.

Canonical response decisions are `ALLOW`, `DENY`, `REQUIRE_APPROVAL`,
`QUARANTINE`, and `REDACT`. `BLOCK` is accepted as a compatibility alias for
`DENY`.

## P1: security engine

Interface: `app/p1.py` and `app/integration.py`.

P1 receives a validated tool request and returns findings with code, severity,
reason, sanitized evidence, and location. Mock P1 detects protected paths,
secrets, prompt injection, suspicious downloads, risky commands, and unsafe
egress. P1 failure or unavailability produces a critical finding, and the
gateway denies the request.

The P1 teammate should implement the same async inspection interface and return
the most restrictive applicable decision. Preserve taint and never echo raw
secrets into findings or audit details.

## P2: offline adapters

Interface: `app/adapters.py` and `app/p2.py`.

Required lifecycle: healthcheck, inspect/precheck, execute, and registration for
documents, scoped local files, protected system files, secrets, and isolated
terminal operations. Mock P2 returns side-effect-free results.

Do not execute arbitrary commands or expose host resources in the API process.
The API is the policy boundary; P2 needs its own OS/container isolation.

## P3: online adapters

Interface: `app/adapters.py` and `app/p3.py`.

Required lifecycle: healthcheck, inspect/precheck, execute, and registration for
browser, email, downloads, sandbox payments, external APIs, and MCP. Mock P3
never sends real email, performs real payments, or downloads real content.

Validate domains, merchants, budgets, and egress policy. Preserve upstream taint.
Downloads should enter quarantine before an agent can consume them.

## Configuration

Backend variables use the `AGENTSHIELD_` prefix. Key values:

- `AGENTSHIELD_DATABASE_URL` (SQLite locally, PostgreSQL in compose)
- `AGENTSHIELD_REDIS_URL` (optional coordination/rate-limit backend)
- `AGENTSHIELD_OPA_URL` (optional; local policy engine otherwise)
- `AGENTSHIELD_P1_ENGINE`, `AGENTSHIELD_P2_ADAPTERS`, `AGENTSHIELD_P3_ADAPTERS`
- `AGENTSHIELD_JWT_SECRET`, `AGENTSHIELD_API_KEY_PEPPER`,
  `AGENTSHIELD_APPROVAL_SIGNING_SECRET`
- `AGENTSHIELD_ADMIN_EMAIL`, `AGENTSHIELD_ADMIN_PASSWORD`
- `AGENTSHIELD_ADMIN_TENANT_SLUG`, `AGENTSHIELD_ADMIN_TENANT_NAME`
- `AGENTSHIELD_ALLOWED_ORIGINS`

Frontend variables:

- `VITE_AGENTSHIELD_API_URL`
- `VITE_AGENTSHIELD_AUTO_CONNECT`
- `VITE_AGENTSHIELD_DEMO_EMAIL`
- `VITE_AGENTSHIELD_DEMO_PASSWORD`

## Policy notes

The local policy engine enforces the seeded baseline policies. Baseline policies
are immutable through the dashboard. Custom policies are persisted as drafts and
are not executable Rego. If `AGENTSHIELD_OPA_URL` is set, the policy engine can
call the configured OPA decision endpoint; the included Rego policy still needs
validation against a real OPA runtime before production use.

## SDK

`sdk/agentshield_sdk/client.py` targets the server root, for example
`http://127.0.0.1:8000`. SDK runtime calls use `/v1/*`, while dashboard browser
calls use `/api/v1/*`. Both route groups are served by the same FastAPI app.

Framework examples wrap `SecureAgent.run()` so every framework tool call passes
through the gateway. Approval examples obtain a signed token from the dashboard
approve endpoint and execute the exact approved action once.

## Before production

- Replace mock P1/P2/P3 with teammate implementations and run conformance tests.
- Validate the Rego policy against a pinned OPA version.
- Exercise the compose stack on a Docker host and PostgreSQL/Redis failure modes.
- Rotate all secrets and use a managed database with restricted roles.
- Add load tests, backup/restore tests, and operational runbooks.
