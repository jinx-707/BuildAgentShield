# Phase 0 — Baseline Audit Report

## Repository Overview

### Backend: `/Users/admin/whack/agentshield-browser-security/`
- **API Service** (Python/FastAPI): `api/` - PostgreSQL + Redis backed, JWT auth, RBAC, enterprise models
- **Browser Worker** (Node.js): `worker/` - Puppeteer/Chromium browser automation with egress proxy
- **Egress Proxy** (Node.js): `proxy/` - MITM proxy with domain/IP policy enforcement
- **Database**: SQLAlchemy models for organizations, agents, policies, audit events, AI security models
- **Docker Compose**: Single compose file with services: postgres, redis, api, browser-worker, egress-proxy, frontend

### Frontend: `/Users/admin/whack/BuildAgentShield-main/`
- **React 19 + Vite + Tailwind CSS v4** single-page application
- **Pages**: Overview, Agents, Browser Sessions, Capabilities & Permissions, Policy Manager, Approval Queue, Audit Logs, Attack Simulator, Quarantine, Settings
- **Services**: API client (`api.ts`), demo data (`demo.ts`), UI components
- **Attack Simulator**: Currently uses local demo evaluator (`simulate()` function), not real backend

### Additional: `/Users/admin/whack/agentshield-Module5/agentshield-online/`
- Separate Python/FastAPI implementation with different attack scenarios (email, payments, downloads, MCP, browser)

---

## Existing Attack Simulation State

### Backend API (`/api/app/api/attack_simulation.py`)
- **Endpoints**:
  - `GET /v1/attack-simulation/scenarios` — 11 hardcoded scenarios
  - `POST /v1/attack-simulation/run` — runs all scenarios
  - `GET /v1/attack-simulation/runs` — lists runs (org-scoped)
  - `GET /v1/attack-simulation/runs/{run_id}` — gets run with evidence

- **Scenarios** (11): unauthorized-destination, ssrf-metadata, malicious-redirect, indirect-prompt-injection, unauthorized-tool-invocation, excessive-permissions, sensitive-data-exfil, session-ownership-violation, proxy-failure, direct-egress-bypass

### Backend Service (`/api/app/services/attack_simulation.py`)
- **MockTargetServer**: Starlette app on loopback with endpoints: `/safe`, `/malicious`, `/metadata`, `/sensitive`, `/redirect`, `/echo`
- **AttackSimulationLab**: Runs scenarios through API `/v1/ai-agent/action` endpoint
- **Results**: PASS/FAIL/ERROR/INCONCLUSIVE with evidence stored in `AttackSimulationRun` + `ScenarioEvidence` tables
- **Limitation**: Uses in-process mock server, not isolated Docker containers

### Database Models (`/api/app/db/ai_models.py`)
- `AttackSimulationRun`: organization_id, agent_id, session_id, scenario_id, scenario_name, threat_category, attempted_action, policy_decision, enforcement_result, evidence(JSONB)
- `ScenarioEvidence`: run_id, evidence_type, description, content(JSONB)

### Frontend Attack Simulator (`/BuildAgentShield-main/agentshield/frontend/src/App.tsx`)
- **10 demo scenarios** in `demo.ts`: pdf, ssh, traversal, env, terminal, pii, browser, payment, tampering, replay
- **Local simulation only**: `simulate()` function uses string matching, no backend calls
- **Backend mode**: Calls `runSimulatorApi()` → `POST /v1/attack-simulation/run`
- **Results display**: Scenario cards with Passed/Failed badges, "Executed: no" (demo mode)

---

## Docker Architecture

### Current `docker-compose.yml` (agentshield-browser-security/)
```yaml
services:
  postgres, redis, api, browser-worker, egress-proxy, frontend
networks:
  edge, worker-net (internal), egress-net
profiles: none (all services always start)
```

### Security Boundaries
- `worker-net`: internal (browser-worker ↔ egress-proxy)
- `egress-net`: egress-proxy only (outbound)
- `edge`: postgres, redis, api, frontend (management)
- No simulation targets exist yet
- No dedicated simulation networks

---

## Integration Map

```
Frontend (BuildAgentShield-main)
    │
    ├── API Client (api.ts) → POST /v1/attack-simulation/run
    │
    └── Demo Mode → local simulate() function

Backend API (agentshield-browser-security/api)
    │
    ├── AttackSimulationLab → MockTargetServer (in-process)
    │
    ├── API Routes → /v1/ai-agent/action → Browser Worker
    │
    └── Database → AttackSimulationRun + ScenarioEvidence

Browser Worker (agentshield-browser-security/worker)
    │
    ├── Puppeteer/Chromium
    │
    ├── Egress Proxy (via http://egress-proxy:3128)
    │
    └── Policy Enforcement (domain_policy.js, url_guard.js)

Egress Proxy (agentshield-browser-security/proxy)
    │
    ├── Domain/IP allow/deny lists
    │
    ├── Private network blocking
    │
    └── DNS resolution validation
```

---

## Gaps for Cyber-Range Implementation

| Requirement | Current State | Gap |
|-------------|---------------|-----|
| Docker-isolated simulation targets | ❌ None | Need 7 dedicated target containers |
| Dedicated simulation networks | ❌ Only worker-net/egress-net | Need `agentshield_control`, `agentshield_simulation`, `agentshield_egress` |
| Compose profiles | ❌ None | Need `core`, `lab`, `observability` |
| Campaign orchestration | ❌ Only "run all" | Need campaign API, sequential/parallel, cancellation |
| Real browser integration | ⚠️ Worker exists but not used in sim | Need Puppeteer-driven scenarios |
| Live frontend updates | ❌ Polling only | Need SSE/WebSocket for live events |
| Evidence from target side | ❌ Only API-side | Need target logs, proxy logs, worker logs |
| DNS rebinding test | ❌ Not implemented | Need controlled DNS service |
| Resource exhaustion test | ❌ Not implemented | Need bounded container with limits |
| Phishing target | ❌ Not implemented | Need synthetic phishing page |
| Malicious download target | ❌ Not implemented | Need file serving with MIME/type tests |
| Data exfiltration sink | ❌ Not implemented | Need mock receiver with receipt logging |

---

## Files to Modify/Create

### Backend (agentshield-browser-security/)
- `docker-compose.yml` — Add profiles, networks, 7 target services, orchestrator, evidence collector
- `api/app/api/simulation.py` — New campaign/simulation endpoints
- `api/app/services/simulation_engine.py` — Persistent simulation engine
- `api/app/services/campaign_orchestrator.py` — Campaign management
- `api/app/services/scenarios/` — 7 scenario implementations
- `api/app/db/ai_models.py` — Add Campaign, Simulation models
- `api/alembic/versions/` — Migration for new tables
- `worker/` — May need adjustments for simulation mode

### Frontend (BuildAgentShield-main/)
- `agentshield/frontend/src/pages/AttackSimulation.tsx` — New dedicated page
- `agentshield/frontend/src/services/api.ts` — New API methods
- `agentshield/frontend/src/components/` — Scenario cards, live execution, evidence explorer

### Root Level
- `scripts/lab-start.sh`, `lab-stop.sh`, `lab-status.sh`, `lab-logs.sh`, `lab-test.sh`, `lab-reset.sh`
- `.env.example`
- `docs/` — 10 documentation files

---

## Summary

**Working Components to Preserve**:
- API authentication, RBAC, org isolation
- Database models and migrations
- Browser worker with Puppeteer
- Egress proxy with policy enforcement
- Audit event persistence
- Frontend UI framework and navigation

**Components to Extend**:
- Attack simulation API → Campaign/Simulation APIs
- MockTargetServer → 7 isolated Docker targets
- In-process scenarios → Real containerized execution
- Demo frontend → Live backend-driven UI

**New Components Required**:
- Simulation controller/orchestrator service
- 7 attack target containers
- Evidence collector service
- DNS test service
- Campaign state machine
- SSE event streaming