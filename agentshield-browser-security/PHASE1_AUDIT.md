# AgentShield PHASE 1 — Implementation Audit

## Scope
Inspected `agentshield-browser-security/api/` (FastAPI), `agentshield-browser-security/worker/` (Playwright browser worker), `agentshield-browser-security/proxy/` (egress proxy), `agentshield-browser-security/cyber-range/` (simulation controller + 7 targets), and the Figma Make frontend scaffold at repo root.

## P1_ENGINE — Security / policy engine
| Component | File | Status | Notes |
|---|---|---|---|
| MockPolicyEngine | `api/app/mocks/policy.py` | **MOCK** | Docstring: "Development-only policy engine. It is not a security control." Allows http/https, rejects embedded creds, otherwise allow. |
| RealPolicyEngine | `api/app/security/policy_engine.py` | Real | Exists but only used when `POLICY_BACKEND=egress-policy`. |
| DatabasePolicyEngine | `api/app/security/database_policy_engine.py` | Real | Resolves effective policy from PostgreSQL. Used when `DATABASE_URL` configured. |
| Policy backend selection | `api/app/factories.py:49` | Configured | `.env` sets `POLICY_BACKEND=mock` → engine is MockPolicyEngine in dev. |

**Verdict:** P1_ENGINE is **Mock** in the current `.env` (`POLICY_BACKEND=mock`). Not a real enforcement control in development.

## P2_ADAPTERS — Offline adapters (content / data inspection)
| Component | File | Status | Notes |
|---|---|---|---|
| MockContentInspector | `api/app/mocks/inspection.py` | **MOCK** | Used when `INSPECTION_BACKEND=mock`. `.env` sets `INSPECTION_BACKEND=mock`. |
| PromptInjectionInspector | `api/app/security/content_inspector.py` | Real | Used when `INSPECTION_BACKEND=prompt-injection`. |

**Verdict:** P2_ADAPTERS is **Mock** in current `.env`.

## P3_ADAPTERS — Online adapters (egress proxy, browser worker)
| Component | File | Status | Notes |
|---|---|---|---|
| Egress proxy | `proxy/` | Real | Node.js proxy with domain/port policy, health endpoint `/health/ready`. |
| Browser worker | `worker/src/` | Real | Playwright-based, request interception, page hardening, egress enforcement via `assertEgressEnforcement()`. |
| Egress assertion | `worker/src/lib/egress.js` | Real | Requires proxy health check before allowing actions. |

**Verdict:** P3_ADAPTERS is **Real**, but the egress proxy health requires `EGRESS_PROXY_URL` and the proxy to report `mode: "enforcing"`.

## /v1/attack-simulation/* — Attack simulation lab API
| Endpoint | File | Status | Notes |
|---|---|---|---|
| `POST /v1/attack-simulation/run` | `api/app/api/attack_simulation.py:152` | Real (w/ mock targets) | Requires auth + agent lookup. Issues an agent JWT, instantiates `AttackSimulationLab(base_url="http://127.0.0.1:8000", api_token=agent_token)`. |
| `GET /v1/attack-simulation/scenarios` | `api/app/api/attack_simulation.py:142` | Real | Static catalog of 10 scenarios. |
| `GET /v1/attack-simulation/runs` | `api/app/api/attack_simulation.py:224` | Real | Org-scoped run history. |
| `GET /v1/attack-simulation/runs/{run_id}` | `api/app/api/attack_simulation.py:259` | Real | Org-scoped run detail + evidence. |
| AttackSimulationLab | `api/app/services/attack_simulation.py` | Mixed | Spins up a **loopback MockTargetServer** (fake `/metadata`, `/sensitive`, `/malicious`, etc.) and POSTs each scenario through `/v1/ai-agent/action`. Real enforcement path, but targets are local fixtures, not the Docker cyber-range targets. |

**Verdict:** Real enforcement call, but targets are mock loopback fixtures — tests the gateway, not the cyber-range targets.

## /v1/ai-agent/action — AI agent action enforcement
| Endpoint | File | Status | Notes |
|---|---|---|---|
| `POST /v1/ai-agent/action` | `api/app/api/ai_agent.py:231` | Real | Resolves agent from JWT (`principal.agent_id`), runs permission → threat → DLP → risk → policy engine → orchestrator → browser worker → egress proxy. Persists execution, threat, DLP, risk, tool decision. |
| AgentSecurityService | `api/app/services/ai_agent_security.py` | Real | Full enforcement orchestration. |

**Verdict:** Real enforcement path. **BUT:** when `API_AUTH_TOKEN` is set, `ApiAuthMiddleware` requires `Authorization: Bearer <api_auth_token>` on ALL non-health endpoints. The internal simulation-to-enforcement call sends only the agent JWT (`Bearer <agent_token>`), so it receives **401**. This is the broken authentication issue.

## /v1/simulations/* — Cyber range campaign API
| Endpoint | File | Status | Notes |
|---|---|---|---|
| `POST /v1/simulations/campaigns` | `api/app/api/cyber_range.py:252` | Real | Org-scoped, writes to `simulation_campaigns`/`simulations` via raw SQL, triggers `simulation-controller:8090`. |
| `GET /v1/simulations/scenarios` | `api/app/api/cyber_range.py:186` | Real | Health-checks the 7 Docker targets + worker + proxy. |
| SSE event streams | `api/app/api/cyber_range.py:711` | Real | Streams campaign/simulation events. |
| simulation-controller | `cyber-range/simulation-controller/main.py` | Real | Runs 7 scenarios through the browser worker; persists campaigns/simulations/evidence/events to PostgreSQL. |

**Verdict:** Real cyber-range execution with 7 scenarios (7 cyber-range targets grouped into 6 categories: SSRF + DNS rebinding both under Network Security).

## Database models & migrations
- `api/app/db/ai_models.py` — AttackSimulationRun, ScenarioEvidence, AgentExecution, ThreatDetection, DlpFinding, RiskAssessment, ToolDecision. Organization-scoped.
- `cyber-range/simulation-controller/main.py` — Campaign, Simulation, SimulationEvidence, CampaignEvent, SimulationEvent (separate SQLAlchemy metadata, `simulation_*` tables).
- Alembic: `api/app/alembic/`. No migrations yet for `simulation_*` tables (cyber_range.py uses raw SQL `CREATE TABLE` assumptions).
- `.env` `DATABASE_URL` points to local PostgreSQL (`postgresql+psycopg2://admin@127.0.0.1:5432/agentshield`).

## Frontend integration settings & Attack Simulator
- Repo root (`/Users/admin/whack/`) is a Figma Make Vite + React scaffold. `index.html` references `/src/main.tsx` but **`src/` does not exist** — no frontend implementation is present yet.
- `docker-compose.yml` `frontend` service builds from `../BuildAgentShield-main` (a separate Next.js app), not the root Vite app.

## Summary of mocked vs real
- **Mock:** P1_ENGINE policy (`MockPolicyEngine`), P2_ADAPTERS inspection (`MockContentInspector`). Controlled by `POLICY_BACKEND=mock` / `INSPECTION_BACKEND=mock` in `.env`.
- **Real:** Egress proxy, browser worker, `/v1/ai-agent/action` enforcement, `/v1/attack-simulation/run` (mock loopback targets), `/v1/simulations/*` cyber range (7 Docker targets).
- **Broken:** Internal `/v1/ai-agent/action` 401 when `API_AUTH_TOKEN` is set (middleware doesn't exempt agent-JWT endpoints).
- **Missing:** Frontend `src/`, integration health-check endpoint, six-category mapping, external-target authorization, downloadable JSON report, live SSE dashboard.
