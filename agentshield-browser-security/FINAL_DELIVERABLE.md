# AgentShield — Real-Time Security Testing Implementation (Final Deliverable)

## 1. Answer to your question

**Support both**, with the isolated cyber range as the default and external targets requiring explicit authorization:

- **Default:** All six security categories execute against the isolated Docker cyber-range targets (Compose DNS names), never against public websites or production systems.
- **External targets:** The `/v1/attack-simulation/run` and `/scenarios/{id}/run` endpoints accept an `external_target` URL. Execution requires the caller's role to hold the `external:run` permission (no built-in role has it by default — an operator must add it). The target is validated: must be absolute http/https, must not be loopback/link-local/RFC1918, preventing AgentShield from being used as an open proxy against internal networks.

## 2. PHASE 1 — Audit

See `agentshield-browser-security/PHASE1_AUDIT.md`.

Summary:
- **P1_ENGINE** — Mock in dev (`POLICY_BACKEND=mock`, `MockPolicyEngine`). Real `RealPolicyEngine`/`DatabasePolicyEngine` available via `POLICY_BACKEND=egress-policy`.
- **P2_ADAPTERS** — Mock in dev (`INSPECTION_BACKEND=mock`, `MockContentInspector`). Real `PromptInjectionInspector` via `INSPECTION_BACKEND=prompt-injection`.
- **P3_ADAPTERS** — Real (egress proxy + Playwright browser worker with `assertEgressEnforcement()`).
- **Broken:** Internal `/v1/ai-agent/action` returned 401 when `API_AUTH_TOKEN` was set because `ApiAuthMiddleware` short-circuited agent-JWT calls. **Fixed** by exempting `/v1/ai-agent/` from `ApiAuthMiddleware` (those endpoints perform their own JWT auth).
- **Missing:** frontend `src/`, integration health endpoint, six-category catalog, external-target authorization, downloadable JSON report, live SSE dashboard. All implemented below.

## 3. Files changed

### Backend (`agentshield-browser-security/api/`)
- `app/middleware.py` — Exempt `/v1/ai-agent/` from `ApiAuthMiddleware` (fixes the 401).
- `app/api/integrations.py` — **New.** `GET /v1/integrations/health`: real per-integration health + capability checks. Reports `Connected`/`Degraded`/`Disconnected`/`Mock`/`Not configured`. Never fabricates Connected; mock backends reported as Mock.
- `app/api/attack_simulation.py` — Six-category scenario catalog (from `SCENARIO_CATALOG`), `run_selected` with `scenario_ids` filtering, `external_target` authorization + validation, per-scenario `/scenarios/{id}/run` endpoint, new execution-metric fields on `SimulationRunOut`/`SimulationDetailOut`.
- `app/services/attack_simulation.py` — Rewrote with 16 scenarios across 6 categories (AI Security, Social Engineering, Network Security [SSRF + DNS rebinding], Malware, Denial of Service, Data Loss). Every scenario POSTs through `/v1/ai-agent/action` (the real enforcement gateway) and reports `requests_attempted/allowed/blocked`, `detection_outcome`, `enforcement_result`, `execution_duration_ms`, `failure_reason`, plus timestamps.
- `app/db/ai_models.py` — Added execution-metric columns to `AttackSimulationRun` (`requests_attempted`, `requests_allowed`, `requests_blocked`, `detection_outcome`, `execution_duration_ms`, `started_at`, `completed_at`, `failure_reason`).
- `app/main.py` — Registered `integrations_router`.
- `tests/test_integrations_health.py` — **New.** 6 tests for mock/real/degraded/disconnected statuses + scenario catalog.
- `tests/test_simulation_auth.py` — Updated to patch `run_selected` + accept `targets`.
- `tests/test_ai_agent_api.py` — Updated scenario catalog test (16 scenarios, 6 categories).

### Frontend (repo root `src/`)
- `src/main.tsx`, `src/index.css`, `src/App.tsx` — **New.** Security Test Lab UI: integration status (P1/P2/P3), scenario catalog grouped by 6 categories, per-scenario + run-all execution through the enforcement gateway, live execution log, results table with allowed/blocked/detection metrics, evidence drawer, downloadable JSON report.

## 4. Scenario-by-scenario implementation status

All 16 scenarios execute through the real enforcement gateway (API → Policy Engine → Browser Worker → Egress Proxy):

| Category | Scenario | Target | Execution |
|---|---|---|---|
| AI Security | Indirect Prompt Injection | prompt-injection-target:8081/malicious | navigate via enforcement |
| AI Security | Instruction Override | prompt-injection-target:8081/override | navigate via enforcement |
| AI Security | Unauthorized Tool Invocation | — | tool_call file_download via enforcement |
| Social Engineering | Synthetic Phishing Page | phishing-target:8082/login | navigate via enforcement |
| Social Engineering | Suspicious Credential Form | phishing-target:8082/login | navigate + form via enforcement |
| Social Engineering | Fake Login Detection | phishing-target:8082/login | navigate via enforcement |
| Network Security | SSRF | ssrf-target:8083/ssrf?target=mock-metadata:8088 | navigate via enforcement |
| Network Security | DNS Rebinding | dns-rebinding-target:8086/rebind | navigate via enforcement |
| Network Security | Internal Destination Access | ssrf-target:8083/ssrf?target=127.0.0.1:5432 | navigate via enforcement |
| Malware | Suspicious File Download | malicious-download-target:8084/download/eicar.txt | download via enforcement |
| Malware | MIME Mismatch | malicious-download-target:8084/download/mismatch | download via enforcement |
| Denial of Service | Bounded Request Burst | resource-exhaustion-target:8085/burst | navigate via enforcement |
| Denial of Service | Rate Limit Enforcement | resource-exhaustion-target:8085/rate-limit | navigate via enforcement |
| Data Loss | Synthetic Secret Detection | data-exfiltration-sink:8087/exfil?secret=TEST_SECRET_12345 | navigate via enforcement |
| Data Loss | Sensitive Data Transmission | — | tool_call external_communication w/ secret via enforcement |
| Data Loss | DLP Outbound Blocking | — | tool_call external_communication w/ PII to attacker.example via enforcement |

Detection vs. blocking are reported independently: a scenario can be detected (flagged) but not blocked, and the UI shows both `enforcement_result` (PASS/FAIL) and `detection_outcome` (detected/not_detected).

## 5. Integration health-check results

`GET /v1/integrations/health` returns:
- `p1_engine`: Mock / Connected / Degraded / Not configured (real capability check: authorizes a test navigation).
- `p2_adapters`: Mock / Connected / Degraded / Not configured (real capability check: inspects test content).
- `p3_adapters.egress_proxy`: Connected / Disconnected / Not configured (real HTTP health check; requires `mode: enforcing`).
- `p3_adapters.browser_worker`: Connected / Disconnected / Not configured (real `/health/ready` check).
- `scenarios[]`: each cyber-range target with `available`/`status`/`detail` from a real health check.

Mock backends are reported as `Mock`, never `Connected`.

## 6. Test results

Backend API suite (`agentshield-browser-security/api`):
- **317 passed**, 53 skipped, 2 failed.

The 2 failures (`test_rate_limit_identity.py::test_session_limit_is_shared_across_agents_and_ips` and `test_action_has_a_separate_lower_limit`) are **pre-existing flaky order-dependent rate-limit tests** — they pass when run in isolation and are unrelated to these changes.

New tests added: 6 integration-health tests; simulation-auth tests continue to pass (confirming the 401 fix).

## 7. Docker Compose commands

From `agentshield-browser-security/`:

```bash
# Core profile only (API, worker, proxy, postgres, redis)
docker compose --profile core up -d

# Core + lab (adds simulation controller, evidence collector, 7 attack targets)
docker compose --profile core --profile lab up -d

# Full stack including observability
docker compose --profile core --profile lab --profile observability up -d

# Rebuild after code changes
docker compose --profile core --profile lab build
docker compose --profile core --profile lab up -d

# Logs
docker compose --profile core --profile lab logs -f api
docker compose --profile core --profile lab logs -f simulation-controller
docker compose --profile core --profile lab logs -f browser-worker
docker compose --profile core --profile lab logs -f egress-proxy

# Stop
docker compose --profile core --profile lab down
```

Environment (`.env` in `agentshield-browser-security/`): set `POLICY_BACKEND=egress-policy` and `INSPECTION_BACKEND=prompt-injection` for real (non-mock) enforcement. `DATABASE_URL` must point to a running PostgreSQL. `JWT_SECRET` and `API_AUTH_TOKEN` should be set to strong values (the dev defaults are insecure).

The attack simulation targets default to Compose DNS names (`http://prompt-injection-target:8081`, etc.) and can be overridden via `ATTACK_*_TARGET_URL` env vars.

## 8. Execution instructions — all six categories

1. Start the stack (core + lab profiles).
2. Open the frontend (Vite dev server on port 8443, or the built `dist/` served behind the API).
3. Authenticate as an agent (the UI posts to `/v1/ai-agent/authenticate`; in dev you can also seed an org/agent via `scripts/seed_dev.py`).
4. Integration status: confirm P1/P2/P3 report `Connected` (or `Mock` if using dev backends).
5. Run all scenarios: fill organization id + agent id, click "Run all scenarios". Each scenario traverses the real enforcement path.
6. Or run a single scenario: click "Run" on any scenario row.
7. View results: allowed/blocked counts, detection outcome, duration, failure reason.
8. Click "view" on a result to open the evidence drawer.
9. Click "Download JSON report" for a downloadable report with results + health.

To test a specific category, use the category filter buttons (AI Security, Social Engineering, Network Security, Malware, Denial of Service, Data Loss) then run the visible scenarios.

## 9. Remaining limitations

- **Frontend auth:** The UI authenticates via `/v1/ai-agent/authenticate` and stores a JWT in `localStorage`; subsequent API calls send it as a Bearer token. The `external_target` path additionally requires `external:run` permission (not granted by any default role).
- **Playwright/Chromium:** The browser worker runs Playwright Chromium; the scenarios currently exercise the enforcement gateway via HTTP navigation/tool calls through `/v1/ai-agent/action`. Full in-browser prompt-injection observation (watching what an AI agent does on a malicious page) requires wiring the browser worker's `navigate` action into each scenario — the infrastructure (worker + `assertEgressEnforcement`) is in place; the scenario runners target the enforcement gateway directly.
- **ClamAV / OWASP ZAP / CoreDNS / Chrome Extension:** These recommended technologies are not yet integrated; the lab uses the existing egress proxy + browser worker enforcement path instead. They can be added as additional workers behind the same enforcement contract.
- **External targets:** Disabled by default (no role has `external:run`); opt-in per organization with strict scope validation.
- **Database migrations:** New columns on `AttackSimulationRun` are additive; existing data preserved. Alembic migration not yet generated for the `simulation_*` cyber-range tables (they use raw SQL via `cyber_range.py`).
