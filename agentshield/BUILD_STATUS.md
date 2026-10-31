# Build status

## Completed

### Backend

- Strict Pydantic contracts and canonical decisions with the `BLOCK` → `DENY`
  compatibility alias.
- FastAPI application with `/v1` and `/api/v1` route prefixes, CORS, request IDs,
  security headers, rate limiting, health, readiness, and metrics.
- JWT dashboard authentication, role checks, agent API keys, tenant isolation,
  and admin/lookup/developer/viewer capability separation.
- Agent registry, strict per-tool input schemas, RBAC/ABAC permission and scope
  checks, payment/merchant budgets, path/domain allowlists, and taint handling.
- Fail-closed gateway with mock P1 inspection, mock P2/P3 adapters, unavailable
  integration denial, idempotency records, quarantine, and regression tests.
- Local policy engine plus optional OPA client and `policies/execution.rego`.
- Human approval workflow with exact-action hashes, expiry, signed single-use
  tokens, reject/approve review, and replay prevention.
- Tenant-isolated append-only audit records with SHA-256 hash chaining,
  verification, sanitized CSV/JSON export, and SQLite update/delete triggers.
- Dashboard APIs for agents, capabilities/scopes, approvals, audit, policies,
  quarantine, workspace, stats, tools, integration health, and simulator.
- Seeded demo tenant, users, agents, policies, approvals, audit events, and
  simulator scenarios.
- Alembic initial migration and environment.
- Dockerfiles, compose stack (PostgreSQL, Redis, OPA, API, nginx), and reverse
  proxy configuration.

### Frontend

- Existing dark AgentShield dashboard is preserved; no redesign or palette
  change was introduced.
- API client with session storage, restore, login/logout, tenant-scoped data
  loading, and silent offline fallback.
- Live dashboard stats/chart data, agents, key rotation, status changes,
  approvals, audit search/export/integrity, policies, quarantine release,
  workspace settings, integration status, and backend simulator execution.
- Backend-aware copy distinguishes live behavior from the offline demo.
- Original demo mode remains fully functional when the API is unavailable.

### SDK and examples

- Sync/async clients, health, propose/execute, idempotency, approval polling,
  approve/reject, and simulator calls.
- `SecureAgent` for framework integration.
- SDK unit tests and LangGraph, CrewAI, and MCP examples.

## Verification

- Backend: **40 passed, 1 skipped**. The skipped test requires
  `AGENTSHIELD_OPA_URL`.
- SDK: **8 passed**.
- Frontend TypeScript: `npx tsc --noEmit` passed.
- Frontend unit tests: **14 passed**.
- Production build: `npm run build` passed. Vite reports only non-fatal
  config-loader and bundle-size warnings.
- Browser tests without a backend: **4 passed** (overview, simulator, agent
  lifecycle, approvals, audit filtering, demo login, permissions, policies,
  quarantine, settings, search, and mobile layout).
- Live backend browser smoke test: auto-connect, live overview stats, audit,
  baseline-policy immutability, approval/quarantine review surfaces, and all ten
  simulator scenarios passed.
- Alembic `upgrade head` and `downgrade base` both completed successfully
  against a temporary SQLite database.

## Remaining verification

- Docker/Compose could not be run because Docker is not installed in this
  environment.
- A real OPA binary was unavailable, so Rego evaluation remains unverified.
  Backend policy tests use the local engine.
- PostgreSQL and Redis runtime behavior were not exercised locally.
- Load/performance testing and production deployment hardening remain future
  work.
- The production bundle is larger than 500 KB after minification; code splitting
  is a future optimization.
