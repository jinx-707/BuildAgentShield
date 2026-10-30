# AgentShield

AgentShield is a fail-closed runtime security gateway for AI agents with a
tenant-scoped dashboard, human approval workflow, hash-chained audit log, and a
Python SDK. The preserved React dashboard connects to the live API when it is
available and falls back to a safe in-browser demonstration when it is not.

## What is included

- **Gateway**: strict tool schemas, agent API keys, RBAC/ABAC permission checks,
  default-deny policy evaluation, provenance taint checks, idempotency, and
  mock P1/P2/P3 adapters. Unavailable integrations fail closed.
- **Dashboard API**: login/JWT sessions, agents and key rotation, approvals,
  audit search/export/verification, policies, quarantine, workspace settings,
  integration health, overview stats, metrics, and the ten-scenario simulator.
- **Dashboard**: the existing AgentShield UI with live API data in backend mode
  and the original seeded demo data when the backend is offline.
- **SDK**: synchronous and asynchronous clients, `SecureAgent` wrapper,
  proposal/approval polling, single-use approval tokens, simulator support, and
  LangGraph, CrewAI, and MCP examples.
- **Operations**: Alembic migration, Dockerfiles, nginx reverse proxy, compose
  stack with PostgreSQL/Redis/OPA, local Rego policy, health/readiness, and
  Prometheus-style metrics.

## Quick start

### Backend

```powershell
cd agentshield/backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload --port 8000
```

The default local database is SQLite (`agentshield.db`). API docs are at
`http://127.0.0.1:8000/docs`, health at `/health`, and readiness at `/ready`.
Dashboard routes are available under both `/v1` and `/api/v1`.

Default backend administrator:

- Email: `admin@agentshield.local`
- Password: `admin-change-me`

Change these before exposing the API. Production mode rejects default secrets.

### Frontend

From the repository root:

```powershell
npm install
npm run dev
```

If the API runs on a non-default address, set:

```powershell
$env:VITE_AGENTSHIELD_API_URL = "http://127.0.0.1:8000/api/v1"
$env:VITE_AGENTSHIELD_DEMO_EMAIL = "admin@agentshield.local"
$env:VITE_AGENTSHIELD_DEMO_PASSWORD = "admin-change-me"
npm run dev
```

`VITE_AGENTSHIELD_API_URL` is the full API root including `/api/v1`. When it is
unset, the dashboard uses `http://127.0.0.1:8000/api/v1` on the managed preview /
`file:` origin and `${origin}/api/v1` otherwise. Auto-connect is enabled unless
`VITE_AGENTSHIELD_AUTO_CONNECT=false`.

The offline demo fallback uses public, non-production credentials:

- Email: `admin@agentshield.demo`
- Password: `demo-password`

If backend auto-connect fails, the dashboard silently stays in demo mode. No
demo action touches host files, sends email, or makes payments.

### Docker

```powershell
cd agentshield
docker compose up --build
```

Open `http://localhost:8080`. The compose stack runs PostgreSQL, Redis, OPA, the
API, and nginx. Docker was not available in the verification environment, so the
compose stack and real OPA evaluation still need runtime verification before
production use.

## API surface

The primary groups are:

- `/api/v1/auth/*`: login, logout, current session
- `/api/v1/agents`: create, update, rotate keys
- `/api/v1/tools` and `/api/v1/gateway/*`: tool catalog, proposal, execution
- `/api/v1/approvals/*`: review and signed single-use approval tokens
- `/api/v1/audit/*`: search, export, and hash-chain verification
- `/api/v1/policies`, `/api/v1/quarantine`, `/api/v1/workspace`
- `/api/v1/stats/overview`, `/api/v1/integrations/health`
- `/api/v1/simulator/*`, `/api/v1/metrics`

Canonical decisions are `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `QUARANTINE`, and
`REDACT`. The legacy alias `BLOCK` maps to `DENY`.

## SDK

```powershell
cd agentshield/sdk
pip install -e ".[test]"
python -m pytest -q
```

Minimal execution:

```python
from agentshield_sdk import AgentShieldClient

with AgentShieldClient("http://127.0.0.1:8000", agent_key="as_...") as client:
    result = client.execute_once(
        "read_document",
        {"document": "quarterly-report.pdf"},
        source="email-inbox",
        trust="untrusted",
        user_intent="Summarize the attached report",
    )

print(result["decision"])
```

The SDK `base_url` is the server root (`http://127.0.0.1:8000`), not the
`/api/v1` dashboard prefix. See `sdk/examples/` for direct, approval, LangGraph,
CrewAI, and MCP examples.

## Tests

```powershell
cd agentshield/backend
python -m pytest -q

cd ../sdk
python -m pytest -q

cd ../..
npx tsc --noEmit
npx vitest run --config agentshield/frontend/vitest.config.ts
npm run build
npx playwright test --config agentshield/frontend/playwright.config.ts
```

Browser tests expect a preview or development server. Set
`AGENTSHIELD_PREVIEW_URL` to override the default
`http://127.0.0.1:${PORT || 3000}`. The demo browser tests intentionally run
without a backend.

## Structure

```text
agentshield/
  backend/
    app/                 FastAPI app, gateway, auth, policies, audit, adapters
    tests/                backend regression and security tests
    migrations/           Alembic environment and initial migration
  frontend/
    src/                  preserved dashboard and API client
    tests/                Playwright browser workflows
    nginx.conf            SPA fallback and /api reverse proxy
  policies/execution.rego local/OPA policy
  sdk/                    Python client, tests, and framework examples
  docker-compose.yml
  BUILD_STATUS.md
  INTEGRATION.md
```

## Security notes and limitations

- P1/P2/P3 are mock implementations in this repository. Unavailable adapters
  deny requests rather than bypassing checks.
- OPA is optional. Without `AGENTSHIELD_OPA_URL`, the local deterministic policy
  engine is used. The Rego policy has not been evaluated against a real OPA
  binary in this environment.
- Custom policies created in the dashboard are stored as drafts; the server does
  not execute custom Rego, and baseline policies are immutable.
- The offline frontend demo is deliberately self-contained and is not a security
  boundary. Use the connected backend for real authorization and audit records.
- Audit records are hash chained and protected against update/delete in SQLite;
  PostgreSQL deployments should additionally restrict database roles.
- Production requires non-default JWT, API-key pepper, and approval secrets.
