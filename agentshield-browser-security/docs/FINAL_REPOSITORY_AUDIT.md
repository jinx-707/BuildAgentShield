# AgentShield — Final Repository Audit

**Date:** 2026-10-31
**Backend Commit:** (to be filled)
**Frontend Commit:** (to be filled)

---

## 1. Architecture Overview

AgentShield is a multi-component AI Agent Security Platform consisting of:

### Backend (`agentshield-browser-security/`)
- **FastAPI API** (`api/`) — Enterprise control plane, browser security, AI agent security, attack simulation
- **PostgreSQL** — Persistent storage for organizations, users, agents, policies, audit events, security incidents, attack simulation runs
- **Redis** — Rate limiting backend (optional)
- **Browser Worker** (`worker/`) — Puppeteer-based browser execution via Node.js/Express
- **Egress Proxy** (`proxy/`) — MITM proxy enforcing domain/port/IP policies
- **Python SDK** (`sdk/python/`) — Client library for AI agents

### Frontend (`BuildAgentShield-main/agentshield/frontend/`)
- **React 19 + Vite + Tailwind CSS v4** single-page application
- **Pages:** Overview, Agents, Browser Sessions, Capabilities & Permissions, Policy Manager, Approval Queue, Audit Logs, Attack Simulator, Quarantine, Settings
- **Services:** API client (`api.ts`), demo data (`demo.ts`)

### Data Flow
```
AI Agent → AgentShield SDK → FastAPI (Auth + Policy Engine) → Browser Worker → Egress Proxy → Destination
                ↓
           PostgreSQL (Audit, Policies, Agents, Orgs)
                ↓
           SSE → Frontend Dashboard
```

---

## 2. Component Inventory

### Backend Components

| Component | Location | Status |
|-----------|----------|--------|
| FastAPI App | `api/app/main.py` | ✅ Complete |
| Enterprise Auth (JWT, RBAC) | `api/app/enterprise/auth.py`, `deps.py`, `rbac.py` | ✅ Complete |
| Organizations CRUD | `api/app/api/enterprise.py` | ✅ Complete |
| Users & Memberships | `api/app/api/enterprise.py` | ✅ Complete |
| Agents (Register, Revoke) | `api/app/api/enterprise.py` | ✅ Complete |
| Policies (CRUD, Versioning, Rollback) | `api/app/api/enterprise.py` | ✅ Complete |
| Browser Sessions | `api/app/api/browser.py` | ✅ Complete |
| Browser Navigation | `api/app/api/browser.py` | ✅ Complete |
| Actions/Screenshots/Extract | `api/app/api/browser.py` | ✅ Complete |
| Search | `api/app/api/browser.py` | ✅ Complete |
| Audit Events (REST + SSE) | `api/app/api/audit.py` | ✅ Complete |
| Security Incidents | `api/app/api/enterprise.py` | ✅ Complete |
| Dashboard Metrics | `api/app/api/enterprise.py` | ✅ Complete |
| Deployments | `api/app/api/enterprise.py` | ✅ Complete |
| AI Agent Auth | `api/app/api/ai_agent.py` | ✅ Complete |
| AI Agent Action Execution | `api/app/api/ai_agent.py` | ✅ Complete |
| AI Threat/DLP/Risk/Tools Listings | `api/app/api/ai_agent.py` | ✅ Complete |
| Attack Simulation Orchestrator | `api/app/services/attack_simulation.py` | ✅ Complete |
| Attack Scenarios (10 implemented) | `api/app/services/attack_simulation.py` | ✅ Complete |
| Attack Simulation API | `api/app/api/attack_simulation.py` | ✅ Complete |
| Database Models (Core) | `api/app/db/models.py` | ✅ Complete |
| Database Models (AI) | `api/app/db/ai_models.py` | ✅ Complete |
| Alembic Migrations | `api/app/alembic/versions/` | ✅ 3 migrations |
| Policy Engine (DB-backed) | `api/app/security/database_policy_engine.py` | ✅ Complete |
| Network Preflight | `api/app/security/preflight.py` | ✅ Complete |
| Content Inspector | `api/app/security/content_inspector.py` | ✅ Complete |
| Browser Orchestrator | `api/app/services/orchestrator.py` | ✅ Complete |
| Session/Action/Screenshot Services | `api/app/services/` | ✅ Complete |
| AI Security Service | `api/app/services/ai_agent_security.py` | ✅ Complete |
| Threat Detection | `api/app/security/ai/detection.py` | ✅ Complete |
| DLP Engine | `api/app/security/ai/dlp.py` | ✅ Complete |
| Risk Engine | `api/app/security/ai/risk.py` | ✅ Complete |
| Browser Worker (Puppeteer) | `worker/src/` | ✅ Complete |
| Egress Proxy (Policy enforcement) | `proxy/src/` | ✅ Complete |
| Worker↔Proxy Policy Sync | `worker/src/lib/domain_policy.js`, `proxy/src/lib/policy.js` | ✅ Complete |

### Frontend Components

| Component | Location | Status |
|-----------|----------|--------|
| React App Shell | `src/App.tsx` | ✅ Complete |
| Overview Dashboard | `src/pages/Overview.tsx` | ✅ Complete |
| Agents Management | `src/pages/Agents` (in App.tsx) | ✅ Complete |
| Browser Sessions | `src/pages/BrowserSessions.tsx` | ✅ Complete |
| Capabilities & Permissions | `src/pages/Capabilities` (in App.tsx) | ✅ Complete |
| Policy Manager | `src/pages/Policy Manager` (in App.tsx) | ✅ Complete |
| Approval Queue | `src/pages/Approval Queue` (in App.tsx) | ⚠️ Partial (backend not implemented) |
| Audit Logs | `src/pages/Audit Logs` (in App.tsx) | ✅ Complete |
| Attack Simulator | `src/pages/Attack Simulator` (in App.tsx) | ✅ Complete |
| Quarantine | `src/pages/Quarantine` (in App.tsx) | ⚠️ Partial (backend not implemented) |
| Settings | `src/pages/Settings` (in App.tsx) | ✅ Complete |
| API Client | `src/services/api.ts` | ✅ Complete |
| Demo Data (Mock) | `src/services/demo.ts` | ✅ Complete |
| UI Components | `src/components/ui.tsx` | ✅ Complete |

---

## 3. Implemented Capabilities

### ✅ Fully Implemented

1. **Enterprise Identity & Access**
   - User registration, login, JWT authentication
   - Organization creation and membership
   - Role-based access control (owner, admin, viewer)
   - Cross-tenant isolation enforced at API and DB layer

2. **Agent Management**
   - Agent registration with credential issuance (secret returned once)
   - Agent revocation (status = "revoked")
   - Agent listing scoped to organization

3. **Policy Management**
   - Policy CRUD with versioning
   - Policy activation/deactivation
   - Policy rollback to previous versions
   - Default-deny domain policy
   - Allowed/blocked domains, allowed ports, private network blocking

4. **Browser Security**
   - Session create/get/close
   - Navigation with policy enforcement
   - Redirect revalidation
   - Actions (click, type, scroll, etc.)
   - Screenshots and content extraction
   - Search with policy enforcement

5. **Audit & Monitoring**
   - Persistent audit events in PostgreSQL
   - SSE stream for real-time events (org-scoped)
   - Dashboard metrics (agents, sessions, requests, violations)

6. **AI Agent Security**
   - Agent authentication (agent_id + secret → JWT)
   - Action execution through enforcement pipeline
   - Threat detection (prompt injection, suspicious nav, exfiltration)
   - DLP (API keys, tokens, passwords, PII patterns)
   - Risk scoring with explainable factors
   - Tool governance (permission checks)

7. **Attack Simulation Lab**
   - 10 scenarios implemented (7 core + 3 additional)
   - Mock targets on loopback only
   - Evidence persistence to PostgreSQL
   - Run history and evidence viewer API

8. **Deployment Infrastructure**
   - Docker Compose with 7 services
   - Health checks, resource limits, security hardening
   - Network isolation (internal worker-net, egress-net)
   - Persistent volumes for PostgreSQL and Redis

---

## 4. Partially Implemented Capabilities

| Capability | Gap |
|------------|-----|
| **Approval Queue** | Frontend UI exists but backend endpoints return 501 (not implemented). No approval workflow in backend. |
| **Quarantine** | Frontend UI exists but backend endpoints return 501. No quarantine queue in backend. |
| **Agent Key Rotation** | Frontend has UI but backend returns 501. Not implemented. |
| **Workspace Renaming** | Frontend has UI but backend returns 501. Not implemented. |
| **Audit Hash-Chain Verification** | Frontend has button but backend returns 501. Not implemented. |
| **Tool Gateway Execution** | Frontend has UI for tool calls but backend returns 501. Not part of browser-security API. |
| **Capabilities & Permissions Persistence** | Frontend toggles call `updateAgentApi` but backend throws 501 for permissions/scopes. |
| **Attack Simulator Dashboard** | Frontend calls `runSimulatorApi` but uses `/attack-simulation/run` which expects different payload. Some scenarios missing (DNS rebinding, resource exhaustion, fork bomb). |
| **SSE Audit Stream** | Backend implements SSE but frontend doesn't consume it (uses polling via `refreshAudit`). |

---

## 5. Missing Capabilities

| Capability | Description |
|------------|-------------|
| **DNS Rebinding Attack Scenario** | Not implemented in attack simulation lab |
| **Resource Exhaustion / Fork Bomb Scenario** | Not implemented (requires container limits testing) |
| **Phishing/Social Engineering Scenario** | Not implemented (local fake login page) |
| **Malicious File Download Scenario** | Not implemented |
| **Real Browser E2E Tests** | Playwright tests exist but only test demo mode, not real backend |
| **Integration Health API** | Backend returns static health, no real worker/proxy health checks |
| **Agent Credential Rotation** | Not implemented |
| **Approval Workflow** | Not implemented |
| **Quarantine Workflow** | Not implemented |
| **Audit Hash-Chain** | Not implemented |
| **Deployment Enrollment/Sync** | Models exist but no sync implementation |

---

## 6. Duplicate Code / Inconsistencies

1. **Two Frontend Repositories**
   - Root `BuildAgentShield-main/` (Vite/React app) — PRIMARY
   - `BuildAgentShield-main/agentshield/frontend/` (duplicate with same code)
   - The `agentshield/frontend/` appears to be a copy; root is the actual entry point

2. **Two API Base URLs**
   - Frontend `api.ts` defaults to `http://127.0.0.1:8000/v1`
   - Docker Compose frontend env uses `NEXT_PUBLIC_API_BASE_URL` but frontend is Vite, not Next.js

3. **Mock vs Real Data**
   - Frontend `demo.ts` has extensive mock data (agents, events, approvals, policies, scenarios)
   - `api.ts` has `backendMode` flag; when false, uses mock data
   - Many backend endpoints return 501 for features frontend expects

4. **Attack Simulation Scenarios Mismatch**
   - Backend: 10 scenarios (unauthorized-destination, ssrf-metadata, malicious-redirect, indirect-prompt-injection, unauthorized-tool-invocation, excessive-permissions, sensitive-data-exfil, session-ownership-violation, proxy-failure, direct-egress-bypass)
   - Frontend `demo.ts`: 10 different scenarios (pdf, ssh, traversal, env, terminal, pii, browser, payment, tampering, replay)
   - Frontend `runSimulatorApi` calls `/attack-simulation/run` but maps results differently

5. **Policy Engine Dual Implementation**
   - `DatabasePolicyEngine` (DB-backed, uses Policy model)
   - `PolicyEngine` interface with mock implementation
   - `build_policy_engine` factory chooses based on `policy_backend` setting

---

## 7. Broken Integration Points

| Integration Point | Issue |
|-------------------|-------|
| **Frontend → Backend: Approvals** | `getApprovalsApi` returns `[]`, `approveRequestApi`/`rejectRequestApi` throw 501 |
| **Frontend → Backend: Quarantine** | `getQuarantineApi` returns `[]`, `releaseQuarantineApi` throws 501 |
| **Frontend → Backend: Agent Permissions** | `updateAgentApi` throws 501 for permissions/scopes |
| **Frontend → Backend: Agent Key Rotation** | `rotateAgentKeyApi` throws 501 |
| **Frontend → Backend: Workspace Rename** | `updateWorkspaceApi` throws 501 |
| **Frontend → Backend: Audit Verification** | `verifyAuditApi` throws 501 |
| **Frontend → Backend: Tool Execution** | `executeTool` throws 501 |
| **Frontend Attack Simulator → Backend** | `runSimulatorApi` POSTs to `/attack-simulation/run` with `{organization_id}` but backend expects `{organization_id, agent_id?, session_id?}` — works but scenarios differ |
| **Frontend SSE → Backend** | Backend has `/v1/audit/stream` SSE endpoint but frontend doesn't use it |
| **Worker ↔ Proxy Policy Sync** | Both compute policy fingerprint independently; no runtime sync mechanism |

---

## 8. Security Concerns

| Concern | Severity | Details |
|---------|----------|---------|
| **JWT Secret Default** | High | `JWT_SECRET=INSECURE-dev-default-change-me` in docker-compose.yml |
| **Proxy Auth Token Empty** | Medium | `PROXY_AUTH_TOKEN=${PROXY_AUTH_TOKEN:-}` — no auth by default |
| **Worker Auth Token Empty** | Medium | `WORKER_AUTH_TOKEN=` — no auth between API and worker |
| **Database Password Default** | Medium | `POSTGRES_PASSWORD=agentshield-dev-password` in docker-compose.yml |
| **CORS Origins** | Low | `CORS_ORIGINS` not set in .env; defaults to empty |
| **Rate Limit Fail Open** | Medium | `rate_limit_fail_open` default not visible; should be fail-closed |
| **Secrets in Audit Logs** | Low | DLP engine redacts but raw content inspected before redaction |
| **No TLS in Local Dev** | Low | All services HTTP; production would need TLS termination |

---

## 9. Test Coverage

### Backend Tests (`api/tests/`)
| Test File | Coverage |
|-----------|----------|
| `test_enterprise.py` | ✅ Org isolation, RBAC, agent revocation, policy versioning, persistent audit, policy enforcement |
| `test_ai_agent_api.py` | ✅ AI agent auth, action execution, listings |
| `test_ai_security.py` | ✅ Threat detection, DLP, risk scoring |
| `test_policy_sync.py` | ✅ Hybrid deployment policy sync |
| `test_actions_screenshots.py` | ✅ Browser actions, screenshots |
| `test_phase2_workflow.py` | ✅ Basic browser workflow |
| `test_orchestrator.py` | ✅ Browser orchestrator |
| `test_api_navigate.py` | ✅ Navigation API |
| `test_session_isolation.py` | ✅ Session isolation |
| `test_browser_client.py` | ✅ Worker client |
| `test_api_auth.py` | ✅ API authentication |
| `test_security_hardening.py` | ✅ Security hardening |
| `test_sessions_extract_search.py` | ✅ Sessions, extract, search |
| `test_rate_limit_identity.py` | ✅ Rate limiting |
| `test_health.py` | ✅ Health checks |
| `integration/test_full_request_path.py` | ✅ Full request path |
| `integration/test_worker_integration.py` | ✅ Worker integration |
| `integration/test_rate_limit_redis.py` | ✅ Redis rate limiting |
| `e2e/test_demo_functional.py` | ✅ Demo functional |
| `e2e/test_demo_ssrf.py` | ✅ SSRF demo |
| `e2e/test_demo_rate_limit.py` | ✅ Rate limit demo |
| `e2e/test_demo_failures.py` | ✅ Failure modes |
| `e2e/test_load.py` | ✅ Load testing |

### Frontend Tests
| Test File | Coverage |
|-----------|----------|
| `tests/dashboard.spec.ts` | ✅ Playwright E2E: Overview, Attack Simulator (demo), Agents, Approvals, Audit, Mobile, Permissions, Policies, Quarantine, Settings, Search |

**Gap:** No frontend-backend integration tests with real backend. Playwright tests run against demo mode only.

---

## 10. Recommended Fixes (Priority Order)

### Critical (Blockers for Integration)
1. **Implement Approval Queue backend** — Add `/v1/approvals` endpoints, approval workflow, single-use tokens
2. **Implement Quarantine backend** — Add `/v1/quarantine` endpoints, quarantine storage, release workflow
3. **Implement Agent Key Rotation** — Add `/v1/agents/{id}/rotate-key` endpoint
4. **Implement Workspace Rename** — Add `/v1/organizations/{id}` PATCH endpoint
5. **Implement Audit Hash-Chain** — Add hash-chain verification to `PersistentAuditStore`
6. **Align Attack Scenarios** — Make frontend scenarios match backend 7 core scenarios

### High (Integration Completeness)
7. **Connect Frontend to Real Backend** — Remove mock data fallbacks, ensure all buttons call real APIs
8. **Implement SSE Consumption** — Frontend should use `/v1/audit/stream` for real-time updates
9. **Fix Attack Simulator Integration** — Frontend `runSimulatorApi` should match backend scenarios
10. **Add Real Browser E2E Tests** — Playwright tests against running backend + worker + proxy

### Medium (Quality)
11. **Secure Defaults** — Change JWT secret, proxy auth, DB password defaults
12. **Add DNS Rebinding Scenario** — Implement in attack simulation lab
13. **Add Resource Exhaustion Scenario** — Implement with container limits
14. **Add Phishing Scenario** — Local fake login page
15. **Add Malicious File Download Scenario** — Harmless synthetic files

### Low (Polish)
16. **Consolidate Frontend Repos** — Remove duplicate `agentshield/frontend/`
17. **Fix CORS Configuration** — Set proper origins
18. **Worker↔Proxy Policy Sync** — Add runtime policy update mechanism
19. **Deployment Enrollment** — Implement hybrid deployment sync

---

## 11. Summary

**Overall Integration Status: ~75% Complete**

The backend is feature-complete for the core browser security and AI agent security platform. The frontend is visually complete but relies heavily on mock data and has significant gaps connecting to real backend endpoints.

**Key Blockers:**
- Approval Queue, Quarantine, Key Rotation, Workspace Rename, Audit Verification — all return 501
- Attack Simulator scenarios don't match between frontend and backend
- No real backend integration tests for frontend

**Path to Demo-Ready:**
1. Implement the 501 endpoints (or remove frontend UI for them)
2. Align attack scenarios
3. Switch frontend to `backendMode=true` and verify all flows
4. Run Docker Compose stack and verify end-to-end
5. Run Playwright tests against real backend