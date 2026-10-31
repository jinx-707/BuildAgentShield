# AgentShield Browser Security Module — Complete Repository Inventory

**Date:** 2026-10-30  
**Phase:** Zero — Complete Repository Inventory  
**Inspector:** Kiro (Principal Application Security Engineer role)

---

## 1. Repository Overview

| Property | Value |
|----------|-------|
| Location | `/Users/admin/whack/agentshield-browser-security` |
| Git branch | `main` (1 commit: `a0234e4` Phase 1 baseline) |
| Untracked/modified | proxy/, worker/src/lib/egress.js, worker/test/, config changes, .env.example deleted |
| Components | FastAPI API, Puppeteer Worker, Node Egress Proxy |
| Languages | Python 3.15, Node.js v26.12.1 |
| Test status (baseline) | Proxy 13/13, Worker 4/4, API 29/29 — all passing |

---

## 2. Component Inventory

### A. FastAPI API / Orchestrator (`api/`)

| File | Responsibility | Status | Missing functionality |
|------|---------------|--------|----------------------|
| `app/main.py` | App factory, lifespan, router/middleware wiring | Real | No authentication middleware; no rate limiting |
| `app/config.py` | Settings (pydantic-settings, env-driven) | Real | `max_redirects`/`block_https_downgrade` defined but unused; mock backends default without production guard |
| `app/middleware.py` | RequestContextMiddleware (correlation IDs) | Real | No auth, no tenant context, no rate limiting |
| `app/factories.py` | Build policy/inspection/preflight backends | Real | Only mock backends exist for policy/inspection; no production guard |
| `app/services/orchestrator.py` | End-to-end request flow | Real | Redirect `final_url` not re-validated; max_redirects/block_https_downgrade not applied |
| `app/security/url_policy.py` | URL validation gate | **Real, thorough** | None critical — comprehensive scheme/credential/port/hostname/IP/reserved checks |
| `app/security/domain_policy.py` | Domain allowlist/denylist | **Real, fail-closed** | None — exact + `*.suffix` matching, deny precedence |
| `app/security/ip_policy.py` | IP classification, SSRF prevention | **Real** | IPv6 range set differs from Node worker (benchmarking, deprecatedOrchid) |
| `app/security/dns_policy.py` | DNS preflight validation | Real | TOCTOU (no IP pinning at API layer — proxy handles pinning) |
| `app/security/ports.py` | Port spec parsing + validation | Real | None |
| `app/security/preflight.py` | Orchestrates URL + DNS validation | Real | None |
| `app/security/errors.py` | SecurityViolation error class | Real | Redirect/egress error codes defined but never raised by API |
| `app/clients/browser_worker.py` | HTTP client to worker | Real | Worker auth optional (empty token default); trusts worker's final_url |
| `app/api/browser.py` | POST /v1/browser/navigate route | Real | None significant |
| `app/api/health.py` | Health/live/ready endpoints | Real | Ready doesn't verify egress proxy config |
| `app/schemas/browser.py` | Pydantic request/response models | Real | PolicyDecision lacks effect enum; raw content returned |
| `app/schemas/health.py` | Health response models | Real | None |
| `app/interfaces/policy.py` | PolicyEngine protocol | Real | No effect enum (ALLOW/DENY/REQUIRE_APPROVAL) |
| `app/interfaces/inspection.py` | ContentInspector protocol | Real | No trust/provenance classification |
| `app/mocks/policy.py` | MockPolicyEngine | **Mock** (explicitly documented) | Not a security control — allows any HTTP(S) URL |
| `app/mocks/inspection.py` | MockContentInspector | **Mock** (explicitly documented) | Regex-only scan, easily bypassed |
| `app/logging_config.py` | Structured JSON logging | Real | None |
| `tests/` | 29 unit + integration tests | Real | No SSRF/DNS-rebind/redirect adversarial tests; no proxy integration tests |

### B. Puppeteer Browser Worker (`worker/`)

| File | Responsibility | Status | Missing functionality |
|------|---------------|--------|----------------------|
| `src/index.js` | Express server entry + graceful shutdown | Real | None |
| `src/app.js` | Express setup, middleware, auth gate | Real | Empty WORKER_AUTH_TOKEN disables auth (fail-open) |
| `src/config.js` | Environment config parsing | Real | None |
| `src/lib/browser.js` | Puppeteer launch, session management | **Real, hard-blocks WebRTC** | No max-concurrent-contexts limit; proxy auth token leaks to origin on 401 |
| `src/lib/page_security.js` | Request interception, redirect handling, JS hardening | **Real, comprehensive** | CDP errors swallowed silently; request.abort/continue errors swallowed |
| `src/lib/url_guard.js` | Worker-side URL/SSRF validation | **Real, fail-closed** | DNS check is defense-in-depth only (proxy is authoritative) |
| `src/lib/egress.js` | Proxy health check + enforcement gate | **Real, fail-closed** | Health cache can mask proxy outage between checks |
| `src/lib/domain_policy.js` | Domain matching | Real | None |
| `src/lib/content.js` | UTF-8 truncation | Real | Can split multi-byte char at boundary (minor) |
| `src/lib/logger.js` | Pino structured logging with redaction | Real | None |
| `src/routes/health.js` | Health/live/ready endpoints | Real | Idle cleanup only on /health/ready |
| `src/routes/navigate.js` | POST /v1/navigate | Real | None significant |
| `test/security_integration.test.js` | 4 integration tests (real Chromium) | Real | No SSRF/redirect/DoS adversarial tests |

### C. Egress Security Proxy (`proxy/`)

| File | Responsibility | Status | Missing functionality |
|------|---------------|--------|----------------------|
| `src/index.js` | Proxy + health server entry | Real | None |
| `src/config.js` | Environment config parsing | Real | `dnsTimeoutMs` defined but never consumed |
| `src/lib/policy.js` | Domain/IP/DNS policy, rebinding prevention | **Real, fail-closed** | `dnsTimeoutMs` not applied to DNS resolution |
| `src/lib/proxy.js` | HTTP/CONNECT/WebSocket handlers | **Real** | HTTP timeout capped at 2000ms (misreported as PORT_NOT_ALLOWED); WebSocket upgrade has no timeout; `mode:"enforcing"` hardcoded in health |
| `src/lib/logger.js` | Structured JSON logging | Real | None |
| `test/policy.test.js` | 6 policy unit tests | Real | None |
| `test/proxy.test.js` | 7 proxy integration tests | Real | None |

### D. Infrastructure

| File | Responsibility | Status | Notes |
|------|---------------|--------|-------|
| `docker-compose.yml` | 3-service Compose with isolated networks | Real | Hardened: read_only, cap_drop ALL, no-new-privileges, pids/mem limits, tmpfs, worker-net internal |
| `api/Dockerfile` | API container build | Real | Non-root user |
| `worker/Dockerfile` | Worker container build | Real | Non-root user |
| `proxy/Dockerfile` | Proxy container build | Real | Non-root user |
| `.env` | Local environment config | Present | Git-ignored (correct) |
| `.env.example` | Example env config | **Deleted** | Needs restoration |
| `.gitignore` | Git ignore rules | Real | Correctly ignores .env, .venv, node_modules |

---

## 3. Request Execution Path (API → Network)

```
Agent / Caller
    │
    ▼
FastAPI POST /v1/browser/navigate
    │
    ├─ RequestContextMiddleware (correlation ID, no auth)
    │
    ├─ BrowserSecurityOrchestrator.navigate()
    │   │
    │   ├─ NetworkPreflight.validate(url)          ← REAL: UrlPolicy + DnsValidator
    │   │   ├─ UrlPolicy.validate()                 scheme, credentials, port, hostname, IP, reserved
    │   │   └─ DnsValidator.validate()              resolve + check is_blocked_ip (TOCTOU here)
    │   │
    │   ├─ PolicyEngine.authorize(url)              ← MOCK: allows any valid HTTP(S)
    │   │
    │   ├─ BrowserWorkerClient.navigate(url)        ← HTTP POST to worker
    │   │   │
    │   │   ▼
    │   │   Node Worker POST /v1/navigate
    │   │   │
    │   │   ├─ validateNavigationUrl(url)           ← REAL: worker-side URL/SSRF/DNS check
    │   │   ├─ assertEgressEnforcement()            ← REAL: proxy health check (fail-closed)
    │   │   ├─ createIsolatedPage()                 ← REAL: fresh browser context
    │   │   ├─ installPageSecurity()                ← REAL: request interception, JS hardening
    │   │   ├─ page.goto(url)                       ← Chromium navigates through proxy
    │   │   │   │
    │   │   │   ▼
    │   │   │   Egress Proxy (3128)
    │   │   │   │
    │   │   │   ├─ validateDestination()             domain policy, port, IP literal
    │   │   │   ├─ resolveDestination()               DNS resolve → check all IPs → double-lookup → IP pin
    │   │   │   ├─ connect to validated IP            (NOT re-resolved at connect time)
    │   │   │   └─ forward HTTP / CONNECT / WebSocket
    │   │   │
    │   │   └─ Return: final_url, status_code, content, redirect_count
    │   │
    │   ├─ ContentInspector.inspect(content)        ← MOCK: regex scan
    │   │
    │   └─ Return BrowserNavigateResponse
    │
    ▼
Caller receives: final_url, content, policy decision, inspection findings
```

**Enforcement points (defense in depth):**
1. API NetworkPreflight (URL + DNS + IP) — real
2. API PolicyEngine — **mock**
3. Worker URL guard (URL + DNS + IP) — real
4. Worker egress enforcement (proxy health check) — real
5. Worker request interception (all HTTP requests) — real
6. Worker JS hardening (WebSocket/WebRTC/popup/SW disabled) — real
7. Proxy domain policy — real
8. Proxy IP classification — real
9. Proxy DNS resolution + IP pinning — real
10. Proxy CONNECT/HTTP/WebSocket enforcement — real

---

## 4. Mock Implementations Identified

| Component | File | What it mocks | Impact |
|-----------|------|--------------|--------|
| PolicyEngine | `api/app/mocks/policy.py` | Domain/port/IP policy decisions | Allows any valid HTTP(S) URL; URL/DNS/IP validation still real via NetworkPreflight |
| ContentInspector | `api/app/mocks/inspection.py` | Content security analysis | Regex scan for `<script`, `javascript:`, `on*=`; easily bypassed; not a real prompt injection detector |

Both mocks are explicitly documented as "not a security control" in their docstrings. The `POLICY_BACKEND=mock` and `INSPECTION_BACKEND=mock` defaults in `.env` select these. No real (non-mock) implementations exist for either backend.

---

## 5. Security-Sensitive Entry Points

| Entry point | Component | Protection |
|-------------|-----------|-----------|
| `POST /v1/browser/navigate` | API | NetworkPreflight (real) + MockPolicy + Worker URL guard |
| `POST /v1/navigate` | Worker | URL guard (real) + egress enforcement (real) + page security (real) |
| HTTP proxy requests | Proxy | Domain policy (real) + IP/DNS (real) + auth (optional) |
| CONNECT tunnels | Proxy | Domain policy (real) + IP/DNS pinning (real) + auth |
| WebSocket upgrades | Proxy | Domain policy (real) + IP/DNS (real) + auth |
| `/health/*` | All | No auth (intentional for liveness) |
| `.env` | Root | Git-ignored (correct); contains config, no secrets |

---

## 6. Duplicate / Dead / Inconsistent Code

| Item | Location | Issue |
|------|----------|-------|
| `max_redirects` / `block_https_downgrade` | `api/app/config.py` | Defined in API config but never used by API code; enforced by worker only |
| Redirect/egress error codes | `api/app/security/errors.py` | `REDIRECT_LIMIT_EXCEEDED`, `HTTPS_DOWNGRADE_BLOCKED`, etc. defined but never raised by API |
| `dnsTimeoutMs` | `proxy/src/config.js` | Configured (5000ms) but never passed to DNS resolver |
| Proxy auth username | `proxy/src/lib/proxy.js` | Hardcoded to "agentshield" (not configurable) |
| IP range sets | API vs worker/proxy | Python `not is_global` blocks benchmarking/deprecatedOrchid; Node ipaddr.js handles them differently |
| `.env.example` | Root | Deleted from git; needs restoration |
| `egress.js` | `worker/src/lib/` | Untracked (new file from hardening work) |
| `proxy/` | Root | Untracked (new component from hardening work) |

---

## 7. Integration Boundaries

| Boundary | Protocol | Auth | Fail behavior |
|----------|----------|------|----------------|
| Caller → API | HTTP/JSON | None | Returns 403/502/504 on validation/worker errors |
| API → Worker | HTTP/JSON (httpx) | Optional Bearer token (empty default) | 502 on worker unavailable, 504 on timeout |
| Worker → Proxy | HTTP proxy (Chromium --proxy-server) | Optional proxy auth (page.authenticate) | Fail-closed if proxy health check fails |
| Proxy → Internet | TCP/TLS | N/A | Block on policy violation |

---

## 8. Summary Assessment

The codebase is substantially more mature than the Phase 2 audit document suggests. The proxy now exists and is a real, policy-enforcing implementation. The worker has real browser isolation, request interception, JS hardening, and egress enforcement. The API has real URL/DNS/IP preflight validation.

**Key remaining gaps (to be addressed in subsequent phases):**
1. Proxy DNS timeout not enforced (dead config)
2. Proxy HTTP timeout bug (2ms cap, wrong error code)
3. Proxy WebSocket upgrade no timeout
4. Proxy health hardcodes "enforcing" without verification
5. API mock backends not rejected in production
6. API no authentication or rate limiting
7. API redirect final_url not re-validated
8. Worker no max-concurrent-contexts limit
9. Worker proxy auth token leak potential
10. Content inspection is mock-only (no real prompt injection detection)
11. Network-level isolation relies on Docker container networking (no OS-level enforcement on macOS bare metal)
