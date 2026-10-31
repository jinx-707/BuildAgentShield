# AgentShield — Final Integration Matrix

**Date:** 2026-10-31
**Backend Version:** (to be filled)
**Frontend Version:** (to be filled)

---

## Legend
- ✅ **Connected** — Frontend calls real backend endpoint, works end-to-end
- ⚠️ **Partial** — Frontend calls backend but with gaps/mismatches
- ❌ **Not Connected** — Frontend uses mock data or backend returns 501
- 🔄 **Missing Backend** — Frontend has UI but no backend endpoint exists
- 📝 **Documented Gap** — Known issue, documented in audit

---

## 1. Authentication

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| Login | `loginApi` | POST | `/v1/auth/login` | None | `App.tsx:handleLogin` | ✅ |
| Demo Login | `loginDemoBackend` | POST | `/v1/auth/login` | None | `App.tsx:bootstrap` | ✅ |
| Get Current User | `me` | GET | `/v1/auth/me` | Bearer | `App.tsx:restoreSession`, `loadBackendData` | ✅ |
| Logout | `logout` | POST | `/v1/auth/logout` | Bearer | `App.tsx:signOut` | ✅ |
| Restore Session | `restoreSession` | GET | `/v1/auth/me` | Bearer (from storage) | `App.tsx:bootstrap` | ✅ |

**Request/Response Schemas:**
- Login: `{email, password}` → `{access_token, token_type, organization_id, organization_name, role}`
- Me: → `{user_id, agent_id, organization_id, role, email, full_name}`

**Test Status:** Backend tests cover login, register, me. Frontend Playwright tests cover demo login.

---

## 2. Organizations

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Orgs | — | GET | `/v1/organizations` | Bearer | Not used in frontend | 🔄 |
| Get Org | — | GET | `/v1/organizations/{org_id}` | Bearer | Not used in frontend | 🔄 |
| Workspace Info | `getWorkspace` | — | Computed from session | — | `App.tsx:loadBackendData` | ⚠️ Local only |
| Rename Workspace | `updateWorkspace` | PATCH | `/v1/organizations/{org_id}` | Bearer | `App.tsx:updateWorkspaceApi` | ❌ Returns 501 |

**Note:** Frontend doesn't have org switching UI; uses first org from login.

---

## 3. Users

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Org Users | — | GET | `/v1/organizations/{org_id}/users` | Bearer | Not used in frontend | 🔄 |

---

## 4. Agents

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Agents | `getAgents` | GET | `/v1/organizations/{org_id}/agents` | Bearer | `App.tsx:loadBackendData`, Overview, Agents page | ✅ |
| Create Agent | `createAgent` | POST | `/v1/organizations/{org_id}/agents` | Bearer (agent:write) | `App.tsx:createAgent` | ✅ |
| Update Agent | `updateAgent` | PATCH | `/v1/agents/{agent_id}` | Bearer (agent:write) | `App.tsx:changeAgentStatus`, `saveCapability` | ⚠️ Status works, permissions throw 501 |
| Revoke Agent | `revoke_agent` | POST | `/v1/agents/{agent_id}/revoke` | Bearer (agent:delete) | `App.tsx:changeAgentStatus` (disable) | ✅ |
| Rotate Key | `rotateAgentKey` | POST | `/v1/agents/{agent_id}/rotate-key` | Bearer (agent:write) | `App.tsx:rotateKey` | ❌ Returns 501 |

**Request/Response Schemas:**
- Create: `{name}` → `{agent_id, name, secret}` (secret returned once)
- List: → `[{id, agent_id, name, status, created_at, last_activity_at}]`
- Update status: `{status: "Active"|"Disabled"}` — only disable (revoke) works

**Test Status:** Backend tests cover create, revoke, RBAC. Frontend create/disable tested in Playwright (demo mode).

---

## 5. Browser Sessions

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| Create Session | `createBrowserSession` | POST | `/v1/browser/session` | X-Agent-ID | `BrowserSessions.tsx:launch` | ✅ |
| Get Session | `getBrowserSession` | GET | `/v1/browser/session/{session_id}` | X-Agent-ID | `BrowserSessions.tsx` (restore) | ✅ |
| Close Session | `closeBrowserSession` | DELETE | `/v1/browser/session/{session_id}` | X-Agent-ID | `BrowserSessions.tsx:close` | ✅ |
| Navigate | `navigateBrowser` | POST | `/v1/browser/navigate` | X-Agent-ID | `BrowserSessions.tsx:navigate` | ✅ |
| Action | — | POST | `/v1/browser/action` | X-Agent-ID | Not connected in UI | 🔄 |
| Screenshot | — | POST | `/v1/browser/screenshot` | X-Agent-ID | Not connected in UI | 🔄 |
| Extract | — | POST | `/v1/browser/extract` | X-Agent-ID | Not connected in UI | 🔄 |
| Search | — | POST | `/v1/browser/search` | None | Not connected in UI | 🔄 |

**Request/Response Schemas:**
- Create: `{idle_timeout_ms?, max_age_ms?}` + `X-Agent-ID` → `{session_id, state, status, created_at, last_used_at, expires_at, current_url}`
- Navigate: `{url, session_id?, wait_until?}` + `X-Agent-ID` → `{request_id, requested_url, final_url, status_code, title, content, content_truncated, elapsed_ms, redirect_count, blocked_request_count, blocked_target_count, policy: {allowed, policy_name, reason}, inspection: {inspector_name, findings[], trust_label, highest_severity, summary}}`

**Test Status:** Backend integration tests cover full request path. Frontend Playwright tests only demo mode.

---

## 6. Policies

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Policies | `getPolicies` | GET | `/v1/organizations/{org_id}/policies` | Bearer | `App.tsx:loadBackendData`, Policy Manager | ✅ |
| Create Policy | `createPolicy` | POST | `/v1/organizations/{org_id}/policies` | Bearer (policy:write) | `App.tsx` (Create policy modal) | ✅ |
| Update Policy | `updatePolicy` | PATCH | `/v1/policies/{policy_id}` | Bearer (policy:write) | `App.tsx` (Activate/Deactivate) | ✅ |
| Get Policy | — | GET | `/v1/policies/{policy_id}` | Bearer | Not directly used | 🔄 |
| Policy Versions | — | GET | `/v1/organizations/{org_id}/policies/{policy_id}/versions` | Bearer | Not connected in UI | 🔄 |
| Rollback Policy | — | POST | `/v1/organizations/{org_id}/policies/{policy_id}/rollback` | Bearer (policy:write) | Not connected in UI | 🔄 |
| Activate Policy | — | POST | `/v1/organizations/{org_id}/policies/{policy_id}/activate` | Bearer (policy:write) | `App.tsx:updatePolicyApi` (via updatePolicy) | ✅ |
| Deactivate Policy | — | POST | `/v1/organizations/{org_id}/policies/{policy_id}/deactivate` | Bearer (policy:write) | `App.tsx:updatePolicyApi` (via updatePolicy) | ✅ |

**Request/Response Schemas:**
- Create: `{name, description?, allowed_domains[], blocked_domains[], default_domain_policy, allowed_ports[], allow_private_networks, agent_id?, is_default?}` → PolicyOut
- Update: `{name?, description?, allowed_domains?, blocked_domains?, default_domain_policy?, allowed_ports?, allow_private_networks?, is_active?, is_default?}` → PolicyOut (creates new version)

**Test Status:** Backend tests cover CRUD, versioning, rollback, activation, enforcement reflection.

---

## 7. Security Events / Audit Logs

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Audit Events | `getAudit` | GET | `/v1/organizations/{org_id}/audit` | Bearer (audit:read) | `App.tsx:loadBackendData`, `refreshAudit`, Audit Logs page | ✅ |
| Verify Audit Chain | `verifyAudit` | GET | `/v1/audit/verify` | Bearer | `App.tsx:verifyAuditChain` | ❌ Returns 501 |
| Download Audit | `downloadAudit` | GET | `/v1/organizations/{org_id}/audit` (client-side) | Bearer | `App.tsx:exportAudit` | ⚠️ Client-side only |
| SSE Stream | — | GET | `/v1/audit/stream` | Bearer/Token | Not connected | 🔄 |

**Note:** Frontend `getAudit` calls `/v1/organizations/{org_id}/audit` with limit/offset. Backend enterprise audit endpoint exists. Separate `/v1/audit/events` exists for in-memory store.

---

## 8. Threat Detection / AI Security

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| AI Agent Auth | — | POST | `/v1/ai-agent/authenticate` | Agent credentials | Not connected in UI | 🔄 |
| Execute Action | — | POST | `/v1/ai-agent/action` | Bearer (agent) | Not connected in UI | 🔄 |
| List Executions | — | GET | `/v1/ai-agent/organizations/{org_id}/executions` | Bearer | Not connected in UI | 🔄 |
| List Threats | — | GET | `/v1/ai-agent/organizations/{org_id}/threats` | Bearer | Not connected in UI | 🔄 |
| List DLP Findings | — | GET | `/v1/ai-agent/organizations/{org_id}/dlp` | Bearer | Not connected in UI | 🔄 |
| List Risk Assessments | — | GET | `/v1/ai-agent/organizations/{org_id}/risk` | Bearer | Not connected in UI | 🔄 |
| List Tool Decisions | — | GET | `/v1/ai-agent/organizations/{org_id}/tools` | Bearer | Not connected in UI | 🔄 |
| List Simulations | — | GET | `/v1/ai-agent/organizations/{org_id}/simulations` | Bearer | Not connected in UI | 🔄 |

**Note:** Frontend has no UI for AI agent security features. These are API-only endpoints.

---

## 9. DLP

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| DLP Findings | — | GET | `/v1/ai-agent/organizations/{org_id}/dlp` | Bearer | Not connected in UI | 🔄 |

**Note:** DLP runs inline during AI agent action execution. No separate UI.

---

## 10. Attack Simulation

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Scenarios | — | GET | `/v1/attack-simulation/scenarios` | None | Not directly used | 🔄 |
| Run Scenarios | `runSimulatorApi` | POST | `/v1/attack-simulation/run` | Bearer | `App.tsx:runSimulation` (Attack Simulator page) | ⚠️ Scenario mismatch |
| List Runs | — | GET | `/v1/attack-simulation/runs` | Bearer | Not connected in UI | 🔄 |
| Get Run + Evidence | — | GET | `/v1/attack-simulation/runs/{run_id}` | Bearer | Not connected in UI | 🔄 |

### Scenario Mapping

| Backend Scenario ID | Backend Name | Frontend Demo Scenario | Match |
|---------------------|--------------|------------------------|-------|
| unauthorized-destination | Unauthorized destination access | — | ❌ |
| ssrf-metadata | SSRF against mock metadata endpoint | — | ❌ |
| malicious-redirect | Malicious redirect to metadata | — | ❌ |
| indirect-prompt-injection | Indirect prompt injection | browser (Malicious browser content) | ⚠️ Partial |
| unauthorized-tool-invocation | Unauthorized tool invocation | — | ❌ |
| excessive-permissions | Excessive permissions | — | ❌ |
| sensitive-data-exfil | Sensitive data exfiltration | pii (PII leakage through email) | ⚠️ Partial |
| session-ownership-violation | Session ownership violation | — | ❌ |
| proxy-failure | Proxy failure / unreachable egress | — | ❌ |
| direct-egress-bypass | Direct egress bypass attempt | — | ❌ |

**Frontend Demo Scenarios (demo.ts):** pdf, ssh, traversal, env, terminal, pii, browser, payment, tampering, replay — **completely different set**

**Test Status:** Backend runs scenarios against mock targets. Frontend Playwright tests run demo scenarios only.

---

## 11. Deployments

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Deployments | — | GET | `/v1/organizations/{org_id}/deployments` | Bearer | Not connected in UI | 🔄 |
| Create Deployment | — | POST | `/v1/organizations/{org_id}/deployments` | Bearer (deployment:write) | Not connected in UI | 🔄 |

---

## 12. Dashboard / Health

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| Dashboard Metrics | — | GET | `/v1/organizations/{org_id}/dashboard` | Bearer | `App.tsx:getOverviewStats` | ✅ |
| Integration Health | — | GET | `/v1/organizations/{org_id}/dashboard` (service_health) | Bearer | `App.tsx:getIntegrationHealth` | ⚠️ Static mock data |
| Health Check | — | GET | `/health/ready`, `/health/live` | None | Docker health checks | ✅ |

---

## 13. Approvals

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Approvals | `getApprovals` | — | — | — | `App.tsx:loadBackendData`, Approval Queue page | ❌ Returns `[]` |
| Approve Request | `approveRequest` | — | — | — | `App.tsx:reviewApproval` | ❌ Returns 501 |
| Reject Request | `rejectRequest` | — | — | — | `App.tsx:reviewApproval` | ❌ Returns 501 |

**Status:** **Completely missing backend implementation.** Frontend has full UI with tabs (Pending/Approved/Rejected), review modal, comments.

---

## 14. Quarantine

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Quarantine | `getQuarantine` | — | — | — | `App.tsx:loadBackendData`, Quarantine page | ❌ Returns `[]` |
| Release Item | `releaseQuarantine` | — | — | — | `App.tsx:releaseQuarantinedItem` | ❌ Returns 501 |

**Status:** **Completely missing backend implementation.** Frontend has UI with 3 demo items.

---

## 15. Capabilities & Permissions

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| Toggle Capability | `saveCapability` | PATCH | `/v1/agents/{agent_id}` | Bearer | `App.tsx:saveCapability` | ❌ Returns 501 for permissions |
| Configure Scope | — | — | — | — | `App.tsx` (Configure modal) | 🔄 Local only |

**Note:** Frontend has 11 capabilities (documents, local_files, system_files, environment, terminal, browser, email, dlp, downloads, payments, external_api). Backend agent model has `permissions` JSONB but no API to update it.

---

## 16. Tools

| Frontend Function | Backend Endpoint | Method | Route | Auth | Frontend Consumer | Status |
|-------------------|------------------|--------|-------|------|-------------------|--------|
| List Tools | `getTools` | — | — | — | Not used | 🔄 Returns empty |
| Execute Tool | `executeTool` | — | — | — | Not used | ❌ Returns 501 |

---

## 17. SSE / WebSocket Events

| Event | Backend Endpoint | Frontend Consumer | Status |
|-------|------------------|-------------------|--------|
| Audit Events Stream | `/v1/audit/stream` (SSE) | Not connected | 🔄 |
| Browser Events | Published via broadcaster | Not connected | 🔄 |
| Security Incidents | Published via broadcaster | Not connected | 🔄 |

**Note:** Backend `EventBroadcaster` publishes to in-memory queues. Frontend uses polling (`refreshAudit`) instead of SSE.

---

## Summary Matrix

| Category | Endpoints Total | Connected | Partial | Not Connected | Missing Backend |
|----------|-----------------|-----------|---------|---------------|-----------------|
| Authentication | 5 | 5 | 0 | 0 | 0 |
| Organizations | 3 | 0 | 1 | 0 | 2 |
| Users | 1 | 0 | 0 | 0 | 1 |
| Agents | 5 | 3 | 1 | 0 | 1 |
| Browser Sessions | 7 | 4 | 0 | 0 | 3 |
| Policies | 8 | 5 | 0 | 0 | 3 |
| Audit/Events | 4 | 2 | 1 | 0 | 1 |
| AI Security | 8 | 0 | 0 | 0 | 8 |
| DLP | 1 | 0 | 0 | 0 | 1 |
| Attack Simulation | 4 | 1 | 1 | 0 | 2 |
| Deployments | 2 | 0 | 0 | 0 | 2 |
| Dashboard/Health | 3 | 2 | 1 | 0 | 0 |
| Approvals | 3 | 0 | 0 | 0 | 3 |
| Quarantine | 2 | 0 | 0 | 0 | 2 |
| Capabilities | 2 | 0 | 0 | 1 | 1 |
| Tools | 2 | 0 | 0 | 0 | 2 |
| SSE/Events | 3 | 0 | 0 | 0 | 3 |
| **TOTAL** | **63** | **22** | **5** | **1** | **35** |

**Connection Rate: 35% (22/63)** — Major integration work needed.

---

## Recommended Integration Fixes

### Immediate (Unblock Demo)
1. **Implement Approval Queue backend** — Add 3 endpoints, persist to DB
2. **Implement Quarantine backend** — Add 2 endpoints, persist to DB
3. **Implement Agent Key Rotation** — Add 1 endpoint
4. **Implement Workspace Rename** — Add 1 PATCH endpoint
5. **Implement Audit Verification** — Add hash-chain to PersistentAuditStore
6. **Align Attack Scenarios** — Update frontend to use backend's 10 scenarios

### Short-term
7. **Connect AI Security UI** — Build frontend pages for threat/DLP/risk/tool listings
8. **Add SSE Consumption** — Replace polling with `/v1/audit/stream`
9. **Connect Browser Actions/Screenshots/Extract** — Add UI for these features
10. **Add Policy Versioning UI** — History, rollback buttons

### Medium-term
11. **Implement Capabilities Permissions API** — PATCH agent permissions
12. **Add Deployment Management UI** — Enrollment, sync status
13. **Worker↔Proxy Policy Sync** — Runtime policy updates