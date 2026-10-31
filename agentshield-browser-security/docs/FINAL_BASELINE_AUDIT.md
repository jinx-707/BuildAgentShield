# AgentShield Browser Security — Final Baseline Audit

**Date:** 2026-10-30
**Scope:** Complete repository inventory before final engineering pass
**Prior audit:** `PHASE_2_SECURITY_AUDIT.md` (Phase 2A)

---

## 1. Component Inventory

| Component | Language | Entry point | Port |
|---|---|---|---|
| FastAPI API / Orchestrator | Python 3.11+ | `api/app/main.py` | 8000 |
| Puppeteer Browser Worker | Node.js 22+ | `worker/src/index.js` | 8080 |
| Egress Security Proxy | Node.js 22+ | `proxy/src/index.js` | 3128 (proxy), 9090 (health) |

---

## 2. Architecture Diagram

```
Untrusted caller / AI agent
        |
        v  HTTP POST /v1/browser/navigate
FastAPI API (port 8000)
  - URL/DNS/IP preflight (NetworkPreflight)
  - Policy engine (RealPolicyEngine or MockPolicyEngine)
  - Rate limiting (RateLimitMiddleware)
  - Request ID propagation
  - Redirect final_url re-validation
  - Content inspection (PromptInjectionInspector or MockContentInspector)
        |
        v  HTTP POST /v1/navigate  [Bearer token optional]
Node.js Browser Worker (port 8080, internal only)
  - URL guard (validateNavigationUrl)
  - Egress proxy enforcement (assertEgressEnforcement)
  - Isolated browser context per request (createIsolatedPage)
  - Page security hardening (installPageSecurity)
  - Request interception (Puppeteer)
  - Popup/WebSocket/redirect blocking
        |
        v  HTTP CONNECT / HTTP proxy  [Basic auth optional]
Node.js Egress Proxy (port 3128, internal only)
  - Domain allowlist/denylist (createEgressPolicy)
  - Port policy
  - Private/reserved IP blocking (isBlockedAddress)
  - DNS resolution + rebinding protection (resolveDestination)
  - WebSocket CONNECT enforcement
  - Proxy authentication
  - Health server (port 9090)
        |
        v
Chromium (launched by Puppeteer)
  --proxy-server=http://egress-proxy:3128
  --host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE egress-proxy
  --disable-webrtc
  --force-webrtc-ip-handling-policy=disable_non_proxied_udp
  [+ 30+ hardening flags]
```

---

## 3. Baseline Test Results

| Suite | Command | Result |
|---|---|---|
| API unit + security tests | `cd api && python -m pytest -q` | **49 passed, 1 warning** |
| Proxy unit tests | `cd proxy && node --test` | **25 passed** |
| Worker security integration | `cd worker && node --test test/security_integration.test.js` | **4 passed** |

---

## 4. Existing Defects and Incomplete Areas

### 4.1 Resolved since Phase 2A (already in working tree)

| ID | Finding | Status |
|---|---|---|
| F-01 | WebSocket bypass | **Fixed** — proxy enforces WebSocket CONNECT; browser uses `--disable-webrtc`; page_security blocks WebSocket API |
| F-02 | Prerender bypass | **Fixed** — `DISABLED_FEATURES` list disables Prerender/SpeculationRules; page_security removes `<link rel=prerender>` |
| F-03 | Popup reaches target before close | **Fixed** — proxy blocks popup destination before TCP connection; test confirms zero target hits |
| F-04 | WebRTC UDP bypass | **Fixed** — `--disable-webrtc`, `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, page_security removes RTCPeerConnection |
| F-05 | Shared browser state | **Fixed** — `createIsolatedPage` uses `browser.createBrowserContext()` per request; test confirms cookie/localStorage isolation |
| F-06 | No proxy implementation | **Fixed** — `proxy/` fully implemented with domain/port/IP/DNS/WebSocket enforcement |
| F-09 | Mock backends in production | **Fixed** — `factories.py` raises `ValueError` for mock backends in production |
| F-11 | Chrome error page reported as 200 | **Fixed** — `navigate.js` detects `chrome-error://` and raises a policy error |
| F-13 | Container hardening incomplete | **Fixed** — `docker-compose.yml` has `read_only`, `cap_drop`, `no-new-privileges`, `pids_limit`, `mem_limit`, `tmpfs` |
| F-15 | Readiness ignores proxy | **Fixed** — `health.js` calls `assertEgressEnforcement`; returns 503 when proxy unavailable |

### 4.2 Remaining / Partially Addressed

| ID | Finding | Status |
|---|---|---|
| F-07 | DNS rebinding TOCTOU | **Mitigated** — proxy does double-resolve rebinding check; browser uses `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE <proxy-host>` forcing all DNS through proxy. Not fully eliminated at OS level. |
| F-08 | No API caller authentication | **Partially addressed** — rate limiting added; worker auth token added. No per-caller identity or tenant isolation. |
| F-10 | Chromium background traffic | **Mitigated** — browser forced through proxy; proxy enforces domain policy. Background traffic blocked unless domain is allowlisted. |
| F-12 | Thin policy/inspection contracts | **Improved** — `InspectionResult` now has `trust_label`, `content_classification`, `highest_severity`, `summary`. Policy contract still lacks agent/session identity. |
| F-14 | Node/Python IP range divergence | **Partially fixed** — proxy adds `benchmarking`, `amt`, `as112`, `deprecatedOrchid`, `orchid2`, `droneRemoteIdProtocolEntityTags` to blocked set. |
| F-16 | Per-subresource DNS no timeout | **Mitigated** — proxy handles DNS with timeout; worker URL guard still calls `dns.lookup` without timeout per subresource. |
| F-17 | Meta refresh TCP oracle | **Mitigated** — proxy blocks TCP connection before HTTP; network-level enforcement prevents the oracle. |

### 4.3 Production Blockers

| Blocker | Description |
|---|---|
| No API caller authentication | Any caller reaching port 8000 can drive the browser. Mitigated by localhost binding in Compose but not enforced at the API layer. |
| No per-caller session isolation | Multiple callers share the same worker; no tenant/agent identity in policy decisions. |
| Mock backends default | `POLICY_BACKEND=mock` and `INSPECTION_BACKEND=mock` are defaults; production requires explicit override. |
| Network-level egress isolation unverified | Docker network `internal: true` on `worker-net` prevents direct internet access from worker, but this cannot be verified without Docker. |
| No persistent audit storage | Security events are logged but not stored durably. |
| No secret management | Tokens are environment variables only. |

---

## 5. Security Controls Verified

| Control | Evidence |
|---|---|
| URL scheme allowlist | `file:`, `ftp:`, `data:` rejected with 403/422 |
| Private IP blocking | `127.0.0.1`, `10.x`, `172.16.x`, `192.168.x`, `169.254.169.254`, `::1`, `fd00:ec2::254` blocked |
| Domain allowlist/denylist | Default-deny; only `ALLOWED_DOMAINS` pass |
| Port allowlist | Only ports 80, 443 by default |
| DNS preflight | Resolves hostname; blocks private answers |
| DNS rebinding protection | Proxy double-resolves; second answer checked |
| Redirect re-validation | API re-validates `final_url` after worker returns |
| Redirect loop detection | Worker detects and blocks redirect loops |
| HTTPS downgrade blocking | HTTP redirect from HTTPS blocked |
| Worker auth token | Bearer token required when `WORKER_AUTH_TOKEN` set |
| Proxy auth token | Basic auth required when `PROXY_AUTH_TOKEN` set |
| Browser context isolation | Fresh `BrowserContext` per request; cookie/localStorage isolated |
| WebSocket blocking | Proxy enforces CONNECT; browser API disabled in page |
| WebRTC blocking | `--disable-webrtc`; RTCPeerConnection removed from page |
| Popup blocking | Proxy blocks destination; page handler closes popup |
| Prerender/prefetch blocking | Browser flags + page_security removes `<link rel=prerender>` |
| Rate limiting | In-memory sliding window per client IP |
| Production mock guard | `ValueError` raised if mock backend used in production |
| Container hardening | `read_only`, `cap_drop: ALL`, `no-new-privileges`, `pids_limit`, `mem_limit`, `tmpfs` |
| Egress proxy required | `REQUIRE_EGRESS_PROXY=true` fails closed; readiness check verifies proxy health |
| Proxy health enforcing check | `/health/ready` returns 503 when `defaultDomainPolicy != deny` |
