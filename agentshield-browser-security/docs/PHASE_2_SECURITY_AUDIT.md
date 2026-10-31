# Phase 2A Security Audit: Browser Security Foundation

**Date:** 2026-10-30  
**Scope:** `agentshield-browser-security` Phase 1 foundation  
**Audit type:** Code review plus controlled local browser testing  
**Production code modified during this phase:** None  
**Repository state:** Not a Git repository; no commit or branch evidence is available.

---

## 1. Executive Summary

The Phase 1 foundation is functional for a narrow happy path: top-level HTTP(S) navigation validates scheme, hostname, port, domain, DNS resolution, private IPs, metadata addresses, and redirects; HTTP subresources are intercepted; and real Chromium navigation works. However, the current implementation is **not ready for production or for exposure to untrusted agents**.

The core problem is that URL policy is enforced only at the Puppeteer request-interception layer and at the initial navigation call. Several browser-native network paths bypass that layer entirely:

- WebSocket upgrades reach blocked destinations.
- `<link rel="prerender">` navigation reaches blocked destinations with credentials.
- Popup navigation reaches blocked destinations before the popup is closed.
- WebRTC/STUN sends UDP to blocked destinations, even with the configured WebRTC flag.
- Browser background traffic reaches Google/update services even with `--disable-background-networking`.
- `REQUIRE_EGRESS_PROXY=true` is only a configuration check for a non-empty proxy URL; it is not network containment. A permissive proxy still allows the bypasses above.
- Browser state is shared across requests, so cookies and localStorage persist across navigations and would persist across agent sessions.

The first issue to fix is **network egress containment**, beginning with the confirmed WebSocket bypass and the fact that `REQUIRE_EGRESS_PROXY` does not enforce policy. The fix should combine a policy-enforcing egress proxy / network namespace with browser-level disabling or interception of non-HTTP channels. The exact files are listed in Section 9.

Test result summary: `29 passed` from the existing API test suite when run from `api/`, with one non-blocking Starlette/httpx deprecation warning. Docker was unavailable, so Compose was reviewed statically and not executed.

---

## 2. Scope, Methodology, and Limitations

### 2.1 Scope

Reviewed:

- `api/`: FastAPI routes, settings, security preflight, policy/inspection interfaces, mocks, worker client, orchestrator.
- `worker/`: Chromium launch, navigation route, URL guard, domain policy, request interception, popup handling, health endpoints, authentication.
- `docker-compose.yml`, Dockerfiles, `.env.example`, `README.md`.
- Existing tests and the Phase 1 integration flow.

Not in scope:

- Real internal services, cloud metadata endpoints, or production DNS.
- Phase 3 actions, search, screenshots, extraction, or sessions; these endpoints do not exist yet.
- Runtime validation of Docker Compose due to missing Docker.
- Exploitation against third-party systems.

### 2.2 Methodology

1. Static review of all API and worker security paths.
2. Existing test suite execution from `api/`.
3. Controlled local HTTP, TCP, UDP, WebSocket, and proxy harnesses.
4. Browser-level adversarial tests for redirects, subresources, WebSockets, popups, prerender, prefetch, meta refresh, JavaScript navigation, form POSTs, cookies/localStorage, WebRTC, and proxy behavior.
5. Comparison of API and worker policy logic for consistency.

The audit harness is outside the repository:

- `/var/folders/g_/_q_srvv953lb3p3_tc6g28s00000gn/T/opencode/phase2_audit_harness.py`
- `/var/folders/g_/_q_srvv953lb3p3_tc6g28s00000gn/T/opencode/phase2_audit_focus.py`
- `/var/folders/g_/_q_srvv953lb3p3_tc6g28s00000gn/T/opencode/prefetch_check.py`
- `/var/folders/g_/_q_srvv953lb3p3_tc6g28s00000gn/T/opencode/domain_check.py`
- Raw results: `audit_results.json`, `focus_results.json`, `prefetch_check.json`, `domain_check.json` in the same directory.

### 2.3 Environment

- macOS on Apple hardware.
- Chromium `156.0.0.0` as reported by headless user agent.
- Node.js `v26.12.1`.
- Python `3.15.0` in `.venv`.
- Docker not available (`docker: command not found`).

### 2.4 Limitations and caveats

- Docker/Compose behavior was not runtime-tested.
- The local fixture required `BROWSER_ALLOW_PRIVATE_NETWORKS=true` for page hosting on `127.0.0.1`; direct top-level private-IP blocking was tested separately with private networking disabled.
- macOS could not bind `127.0.0.2`; tests used multiple ports on `127.0.0.1` and `::1`.
- DNS rebinding was assessed from code and architecture, not exploited end-to-end.
- Private-IP/metadata access through prerender/WebSocket is inferred from the confirmed policy bypass and code path; the local fixture could not host a public page while private-network blocking was enabled.
- Running pytest from the repository root does not load `api/pyproject.toml`; async tests then fail because `asyncio_mode=auto` is not applied. Run from `api/`. This is a test-operations issue, not a production security finding.

---

## 3. Architecture and Trust Boundaries

### 3.1 Request path

```text
Untrusted caller / agent
        |
        v
FastAPI /v1/browser/navigate
        |
        +--> API NetworkPreflight (URL policy + DNS validation)
        |
        +--> PolicyEngine (currently mock)
        |
        +--> BrowserWorkerClient (optional bearer token)
                |
                v
        Node worker /v1/navigate
                |
                +--> Worker URL guard (URL policy + DNS validation)
                |
                +--> Puppeteer request interception
                |
                +--> Chromium
                        |
                        +--> HTTP(S) requests
                        +--> WebSocket upgrades        <-- not fully covered
                        +--> prerender navigation      <-- not covered
                        +--> popup navigation          <-- closed too late
                        +--> WebRTC/STUN UDP           <-- not covered
                        +--> background Google/update  <-- not covered
                        |
                        v
                Target sites / internal networks
```

### 3.2 Trust boundaries

| Boundary | Trust assumption | Current reality |
|---|---|---|
| Caller to API | Untrusted; should be authenticated and scoped | No API authentication, tenant identity, session ownership, or rate limiting |
| API to worker | Private service boundary; should authenticate | Worker auth exists but is optional and empty by default |
| Worker to proxy | Proxy is trusted to enforce egress | No proxy implementation exists; any configured proxy is trusted implicitly |
| Worker to target | Target is untrusted | Correct intent, but non-HTTP channels bypass policy |
| Returned content | Untrusted and potentially adversarial | Raw HTML returned with provenance-free findings; mock inspector is not a security control |
| Browser state | Should be isolated per caller/session | Single shared browser and default context; cookies/localStorage persist |

### 3.3 Key design observation

The design currently relies on application-layer request interception for network policy. That is insufficient for a browser. Chromium can initiate network traffic through paths that Puppeteer request interception does not fully mediate, and browser background services can initiate traffic independently of page requests. The policy boundary must ultimately be the network path, not only the page request event.

---

## 4. Verified Security Controls

The following controls worked in controlled tests.

| Control | Evidence |
|---|---|
| Top-level HTTP(S) only | `file:///etc/passwd` returned `400 URL_SCHEME_NOT_ALLOWED`. |
| Direct private IPv4 blocked | `http://127.0.0.1:<port>` returned `403 PRIVATE_IP_BLOCKED` with private networking disabled. |
| IPv6 loopback blocked | `http://[::1]:<port>` returned `403 PRIVATE_IP_BLOCKED`. |
| Metadata address blocked | `http://169.254.169.254/` returned `403 PRIVATE_IP_BLOCKED`. |
| DNS-to-private blocked | `localtest.me` resolving to loopback returned `403 PRIVATE_IP_BLOCKED` with private networking disabled. |
| Embedded credentials rejected | URL policy rejects username/password and `@` in authority. |
| Port allowlist | Disallowed top-level port returned `403 PORT_NOT_ALLOWED`. |
| Domain allowlist | Disallowed top-level domain returned `403 DOMAIN_BLOCKED` in policy paths. |
| Redirect destination blocked | Redirect to a disallowed port returned `403 REDIRECT_DESTINATION_BLOCKED`; target received zero requests. |
| HTTP subresource interception | Image, script, iframe, and fetch subresources to a disallowed port were blocked; `blocked_request_count=4`; target received zero requests. |
| `REQUIRE_EGRESS_PROXY` without proxy | Navigation returned `403 NETWORK_EGRESS_BLOCKED`; target received zero requests. |
| Unreachable proxy | Navigation returned `500`; target received zero requests. |
| Blocking proxy | Target received zero requests; proxy received the navigation attempts. |
| Proxy loopback handling | With `--proxy-bypass-list=<-loopback>`, loopback traffic was routed through the proxy rather than bypassing it. |
| Invalid proxy URL | Navigation returned `500`; target received zero requests. |
| Worker bearer auth | With `WORKER_AUTH_TOKEN` set, `/v1/navigate` returned `401 WORKER_AUTH_FAILED` without the token and `200` with it. |
| Health auth bypass | `/health/live` remained available without a token, as intended for health checks. |
| Non-root containers | API and worker Dockerfiles switch to an unprivileged user. |
| Worker not published | Compose exposes worker only on `worker-net`; no host port mapping. |
| API localhost binding | Compose publishes API on `127.0.0.1:${API_PORT}:8000`. |
| Existing tests | `29 passed, 1 warning` when run from `api/`. |

These controls are meaningful but are not sufficient because the non-HTTP bypasses in Section 5 bypass them.

---

## 5. Security Findings

### 5.1 Findings summary

| ID | Severity | Finding | Evidence |
|---|---|---|---|
| F-01 | CRITICAL | WebSocket upgrades bypass URL policy and reach blocked destinations | Target received `GET /ws` with `Upgrade: websocket`, returned `101`; `blocked_request_count=0` |
| F-02 | HIGH | `<link rel="prerender">` bypasses URL policy and sends credentialed requests to blocked destinations | Target received `GET /prerender`; cookie header `audit=secret`; `blocked_request_count=0` |
| F-03 | HIGH | Popup navigation reaches blocked destinations before the popup is closed | Target received `GET /popup`; `blocked_request_count=1` only after the request |
| F-04 | HIGH | WebRTC/STUN sends UDP outside HTTP policy and outside the proxy | Three 20-byte STUN packets reached a disallowed UDP port, including with a configured proxy |
| F-05 | HIGH | Browser state is shared across navigations; no per-session context isolation | Cookie and localStorage persisted across separate `newPage()` navigations |
| F-06 | HIGH | `REQUIRE_EGRESS_PROXY` is not network enforcement; no proxy service is implemented | A permissive proxy allowed WebSocket, popup, and prerender to reach blocked targets; `proxy/` is empty |
| F-07 | HIGH | DNS rebinding TOCTOU between preflight and Chromium resolution | API/worker resolve DNS; Chromium resolves separately; no IP pinning or connection-level verification |
| F-08 | HIGH | No API authentication, tenant isolation, session ownership, or rate limiting | No auth dependency or auth middleware in the API; only request-id middleware exists |
| F-09 | HIGH | Mock policy and inspection backends are allowed in production without a guard | Defaults are `mock`; mock policy allows any HTTP(S) URL; factories ignore `environment` |
| F-10 | MEDIUM | Chromium background traffic bypasses URL policy | Observed `www.google.com`, `accounts.google.com`, `clients2.google.com`, and `update.googleapis.com` traffic despite `--disable-background-networking` |
| F-11 | MEDIUM | Blocked egress can be reported as HTTP 200 with a Chrome error page | Blocking proxy returned 403 to Chromium; worker returned 200 with `status_code=403`, `final_url=chrome-error://chromewebdata/` |
| F-12 | MEDIUM | Policy/inspection contracts lack action, agent, approval, trust, and provenance semantics | `PolicyDecision` has only `allowed`; `InspectionResult` has only inspector name and findings; raw content is returned |
| F-13 | MEDIUM | Container and browser filesystem hardening is incomplete | Compose has no read-only FS, `cap_drop`, `no-new-privileges`, pids/memory limits, or tmpfs; no explicit download policy |
| F-14 | LOW | Node and Python blocked-IP range sets differ | Node allows IPv6 `benchmarking` (`2001:2::/48`) and `deprecatedOrchid` (`2001:10::/28`) ranges that Python rejects via `not is_global` |
| F-15 | LOW | Readiness ignores required egress proxy configuration | `/health/ready` returned 200 with `REQUIRE_EGRESS_PROXY=true` and no proxy, even though navigation would be blocked |
| F-16 | LOW | Per-subresource DNS lookups have no timeout or cache | Request interception calls DNS validation for every HTTP(S) subresource |
| F-17 | LOW | Meta refresh creates a TCP reachability oracle | Blocked meta refresh produced two TCP accepts on the disallowed target port but no HTTP request |

### F-01 (CRITICAL): WebSocket upgrades bypass URL policy

**Affected code:** `worker/src/lib/page_security.js:115-118`, `worker/src/lib/browser.js:63-76`

Puppeteer request interception covered ordinary HTTP(S) requests but did not prevent the WebSocket upgrade. The allowed test page opened:

```text
ws://127.0.0.1:<disallowed-port>/ws
```

The target server received a real HTTP upgrade request:

```text
GET /ws HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
```

and returned `101 Switching Protocols`. The worker response reported `blocked_request_count=0`.

The same result occurred when the worker was configured with a permissive egress proxy: the proxy received `CONNECT 127.0.0.1:<disallowed-port>` and the target still received the upgrade. A blocking proxy stopped the connection, but that only proves the proxy can enforce policy; it does not prove the worker does.

**Impact:** An allowed-origin page can open WebSockets to internal services, metadata endpoints, or arbitrary blocked ports. This is a direct SSRF/exfiltration path and bypasses domain, port, and private-IP policy. It is critical because the default configuration does not require an egress proxy.

### F-02 (HIGH): Prerender bypasses URL policy with credentials

**Affected code:** `worker/src/lib/page_security.js:115-118`

A page containing:

```html
<link rel="prerender" href="http://127.0.0.1:<disallowed-port>/prerender">
```

caused the target to receive a full HTTP GET. When the page first set a cookie, the request included it:

```text
GET /prerender-cookie HTTP/1.1
Cookie: audit=secret
```

The worker response reported `blocked_request_count=0`. The separate `<link rel="prefetch">` test was blocked (`blocked_request_count=1`, target zero hits), so the bypass is specific to prerender navigation.

A domain-level test also confirmed the bypass: with only `localtest.me` allowed and the target on `127.0.0.1`, prerender still reached the disallowed domain. With a permissive proxy, the prerender request went through the proxy to the disallowed target.

**Impact:** Credentialed GET requests can be sent to internal services for CSRF-like side effects, and the request is invisible to the policy layer. The same primitive likely reaches metadata/private addresses because the prerender request is not passed through `validateNavigationUrl`; direct metadata testing was limited by the local fixture constraints.

### F-03 (HIGH): Popup navigation reaches the target before close

**Affected code:** `worker/src/lib/page_security.js:120-123`

The popup handler increments `blockedRequestCount` and closes the popup, but closing happens after the popup has already initiated navigation. The target received:

```text
GET /popup HTTP/1.1
```

and a favicon request. The worker response reported `blocked_request_count=1`, but the request had already reached the target. A domain-level test confirmed that popup navigation also reached a disallowed domain when only another domain was allowlisted.

With a permissive proxy, the popup request went through the proxy to the disallowed target.

**Impact:** Popups can load internal pages, send credentialed requests, and potentially execute scripts before closure. The `blocked_request_count` metric is misleading because it increments after the network effect.

### F-04 (HIGH): WebRTC/STUN sends UDP outside HTTP policy and outside the proxy

**Affected code:** `worker/src/lib/browser.js:18`, `worker/src/lib/page_security.js` (no WebRTC handling)

The launch configuration includes:

```text
--force-webrtc-ip-handling-policy=disable_non_proxied_udp
```

That flag did not prevent UDP STUN traffic to a disallowed local UDP port. A page using `RTCPeerConnection` with `stun:127.0.0.1:<port>` produced three 20-byte STUN binding requests at the target. The UDP traffic was also observed when an egress proxy was configured; it was not proxied.

**Impact:** WebRTC provides a UDP egress path that bypasses HTTP/WebSocket policy and the proxy. At minimum this is a UDP reachability/port-scanning primitive; with ICE/TURN and data channels it can become a data-exfiltration channel. The effective flag behavior should be re-validated on the exact production Chromium build, but the tested build did not contain UDP.

### F-05 (HIGH): Browser state is shared across navigations

**Affected code:** `worker/src/routes/navigate.js:77`, `worker/src/lib/browser.js:63-76`

The worker calls `browser.newPage()` against a single shared browser and default browser context. There is no `browser.createBrowserContext()`, no incognito context, no per-session user-data directory, and no storage clearing between requests.

Controlled test:

1. Page A set `document.cookie = "audit=shared-cookie"` and `localStorage.setItem("audit", "shared-local-storage")`.
2. A separate navigation to Page B read both.
3. Results: `cookie_persisted=true`, `localstorage_persisted=true`.

**Impact:** Cookies, localStorage, IndexedDB, cache, and authentication state persist across requests and across any future agent/session identity. This creates cross-agent data leakage, authentication confusion, and persistent tracking. `request_id` is not an isolation boundary.

### F-06 (HIGH): `REQUIRE_EGRESS_PROXY` is not network enforcement

**Affected code:** `worker/src/routes/navigate.js:59-65`, `worker/src/lib/browser.js:21-26`, `docker-compose.yml:21-33`, `proxy/` (empty)

The current check is:

```js
if (config.requireEgressProxy && !config.egressProxyUrl) {
  throw new UrlValidationError(
    "NETWORK_EGRESS_BLOCKED",
    "the egress proxy is required but not configured",
    403,
  );
}
```

This only verifies that the environment variable is non-empty. It does not verify that the proxy is reachable, policy-enforcing, or the only network path. The `proxy/` directory exists but contains no implementation. The worker has no separate egress network in Compose; it is attached to `worker-net` and can use the host/container network path.

Test results:

| Configuration | Result |
|---|---|
| `REQUIRE_EGRESS_PROXY=true`, no proxy URL | Navigation 403, target zero hits |
| `REQUIRE_EGRESS_PROXY=true`, unreachable proxy | Navigation 500, target zero hits |
| `REQUIRE_EGRESS_PROXY=true`, blocking proxy | Target zero hits; worker returned 200 with Chrome error page |
| `REQUIRE_EGRESS_PROXY=true`, permissive proxy | WebSocket, popup, and prerender reached blocked targets through the proxy |
| `REQUIRE_EGRESS_PROXY=true`, invalid proxy URL | Navigation 500, target zero hits |
| `REQUIRE_EGRESS_PROXY=true`, no proxy, `/health/ready` | 200, despite navigation being blocked |

**Impact:** A generic proxy only relocates the bypass. If the proxy permits WebSocket CONNECT, popup GETs, or prerender GETs, the worker's URL policy is bypassed. The proxy must itself enforce the destination policy, and the worker must have no alternate egress path.

### F-07 (HIGH): DNS rebinding TOCTOU

**Affected code:** `api/app/security/dns_policy.py:51-77`, `worker/src/lib/url_guard.js:274-301`, `worker/src/lib/page_security.js:82`

The API and worker both perform DNS resolution during validation:

- API: `DnsValidator.validate()` resolves the hostname.
- Worker: `validateNavigationUrl()` resolves the hostname for the navigation and for intercepted requests.

Chromium then performs its own DNS resolution when it connects. There is no IP pinning, no `--host-resolver-rules` mapping, and no connection-level verification that the socket is connecting to the validated address. An attacker-controlled hostname can therefore return a public address during preflight and a private address to Chromium during the actual connection, subject to DNS caching and rebinding timing.

**Impact:** DNS-based SSRF protection is probabilistic rather than deterministic. This is a known TOCTOU class; it is more serious because no egress proxy is required by default. A policy-enforcing proxy that resolves and validates at connection time, or browser-level resolver pinning, is required.

### F-08 (HIGH): No API authentication, tenant isolation, session ownership, or rate limiting

**Affected code:** `api/app/main.py:66-74`, `api/app/api/browser.py:19-32`, `api/app/middleware.py:18-55`

The FastAPI app has request-id middleware and health/navigation routers, but no authentication dependency, no API key/token check, no tenant context, no session ownership check, and no rate limiting. The worker has optional bearer auth, but the API does not authenticate callers.

**Impact:** Anyone who can reach the API can drive the browser, consume resources, and potentially use the worker as a network pivot if egress is not contained. The default Compose binding to `127.0.0.1` reduces exposure, but the API itself has no defense in depth. This is also a prerequisite for per-agent isolation.

### F-09 (HIGH): Mock policy and inspection backends are not production-guarded

**Affected code:** `api/app/config.py:30-31`, `api/app/factories.py:11-26`, `api/app/mocks/policy.py:11-39`, `api/app/mocks/inspection.py:7-52`

Defaults:

```python
policy_backend: str = "mock"
inspection_backend: str = "mock"
```

`build_policy_engine()` and `build_content_inspector()` only implement `mock`; they do not reject mock backends when `environment == "production"`. `MockPolicyEngine` allows any HTTP(S) URL without credentials. `MockContentInspector` is a regex scanner and is explicitly documented as not a security control.

**Impact:** A production deployment can start successfully with no real policy enforcement and regex-only inspection. Because the worker has its own domain/port controls, not every target is allowed, but the API policy contract and content inspection are effectively absent.

### F-10 (MEDIUM): Chromium background traffic bypasses URL policy

**Affected code:** `worker/src/lib/browser.js:10-19`

`--disable-background-networking` did not prevent Chromium 156 from making external requests. Through the permissive proxy, the following were observed during normal navigations:

```text
CONNECT www.google.com:443
GET http://clients2.google.com/time/1/current?...
CONNECT accounts.google.com:443
CONNECT update.googleapis.com:443
POST http://update.googleapis.com/service/update2/json?...
```

These requests were not initiated by the target page and were not subject to `validateNavigationUrl`. With no proxy, they would be direct egress.

**Impact:** Browser telemetry/update traffic is outside the application policy boundary and may leak metadata or violate a strict no-egress requirement. The flag set is insufficient; a network-level deny-by-default egress path is required.

### F-11 (MEDIUM): Blocked egress can be reported as HTTP 200

**Affected code:** `worker/src/routes/navigate.js:89-118`

When a blocking proxy returns an HTTP 403 to Chromium, `page.goto()` can resolve with a response rather than throw. The worker then returns HTTP 200 with a body containing the Chrome error page:

```text
HTTP 200
status_code: 403
final_url: chrome-error://chromewebdata/
content: <Chrome error page>
```

The API client accepts this as a successful `WorkerNavigateResponse`. The same pattern appeared for JavaScript navigation and form POST attempts that were stopped at the request layer: the worker returned 200 with a Chrome error page rather than a policy error. In contrast, a proxy that blocked a CONNECT tunnel produced a 500.

**Impact:** Callers may treat a blocked or failed navigation as success. This is not an egress bypass by itself, but it undermines fail-closed behavior and can mislead an agent into acting on an error page. `blocked_request_count` is also unreliable because it can be incremented after a request has already reached the target (popup) or not incremented at all (prerender).

### F-12 (MEDIUM): Integration contracts lack action, agent, approval, trust, and provenance semantics

**Affected code:** `api/app/schemas/browser.py:29-49`, `api/app/interfaces/policy.py:6-11`, `api/app/interfaces/inspection.py:13-18`, `api/app/services/orchestrator.py:33-74`

Current policy request contains only `request_id` and `url`. Current decision contains only `allowed`, `policy_name`, and `reason`. There is no action type, agent identity, session identity, requested capability, approval requirement, obligation, policy version, or TTL. There is no `ALLOW` / `DENY` / `REQUIRE_APPROVAL` effect enum; denial is inferred from a boolean.

Current inspection result contains only `inspector_name` and a list of regex findings. There is no content classification, trust label, source provenance, sanitization result, or prompt-injection signal. The raw HTML is returned to the caller alongside the findings.

**Impact:** The contracts cannot express the Phase 2+ requirements for agent-scoped authorization, approvals, content trust, or provenance. Returning raw untrusted content without labels creates a prompt-injection risk for downstream agents. The mock inspector cannot be treated as a security control.

### F-13 (MEDIUM): Container and browser filesystem hardening is incomplete

**Affected code:** `docker-compose.yml:1-37`, `api/Dockerfile:1-23`, `worker/Dockerfile:1-39`, `worker/src/routes/navigate.js`

The Dockerfiles correctly run as non-root (`USER app`, `USER node`), and the worker is not published to the host. However:

- No `read_only: true`.
- No `cap_drop: ["ALL"]`.
- No `security_opt: ["no-new-privileges:true"]`.
- No `pids_limit`, memory limit, or CPU limit.
- No `tmpfs` for `/tmp` or Chromium profile/cache.
- No explicit download policy or download directory containment.
- No permission overrides for geolocation, camera, microphone, clipboard, notifications, or persistent storage.
- Chromium profile/cache location is not explicitly controlled.

**Impact:** A compromised or malicious browser process has more filesystem and resource freedom than necessary. This is defense-in-depth and availability risk rather than a direct policy bypass.

### F-14 (LOW): Node and Python blocked-IP range sets differ

**Affected code:** `worker/src/lib/url_guard.js:10-28`, `api/app/security/ip_policy.py:39-67`

Python uses `not parsed.is_global` as a catch-all, which blocks non-global special-use ranges. The Node `ipaddr.js` sets explicitly cover `unspecified`, `broadcast`, `multicast`, `linkLocal`, `reserved`, `ipv4Mapped`, `rfc6145`, `rfc6052`, `6to4`, `teredo`, plus private ranges. Documentation IPv4 ranges such as `192.0.2.0/24` are covered by Node's `reserved` range, and IPv6 documentation `2001:db8::/32` is also `reserved`. However, IPv6 benchmarking `2001:2::/48` is reported by `ipaddr.js` as `benchmarking` and IPv6 deprecated ORCHID `2001:10::/28` as `deprecatedOrchid`; neither is in the Node blocked set, while Python rejects both because `is_global` is false. AS112, AMT, ORCHIDv2, and drone-remote-ID ranges are global in Python and are not currently blocked by either side.

**Impact:** The API and worker can disagree about two special-use IPv6 ranges. This is unlikely to reach internal services directly, but it is a policy consistency defect and reduces confidence in defense in depth.

### F-15 (LOW): Readiness ignores required egress proxy configuration

**Affected code:** `worker/src/routes/health.js:25-37`, `api/app/api/health.py:35-70`, `worker/src/routes/navigate.js:59-65`

With `REQUIRE_EGRESS_PROXY=true` and no `EGRESS_PROXY_URL`, `/health/ready` returned 200. The readiness check only verifies that Chromium is connected; it does not verify proxy configuration or reachability.

**Impact:** Orchestrators can mark the worker ready while every navigation will fail with `NETWORK_EGRESS_BLOCKED`. This is an availability/operability issue, not a bypass.

### F-16 (LOW): Per-subresource DNS lookups have no timeout or cache

**Affected code:** `worker/src/lib/page_security.js:82`, `worker/src/lib/url_guard.js:274-301`

Every intercepted HTTP(S) request calls `validateNavigationUrl()`, which performs `dns.lookup(hostname, { all: true })` without a timeout or cache. Concurrent subresources can multiply DNS work; a slow resolver can delay request interception and navigation.

**Impact:** Potential latency amplification or resource exhaustion. It also increases the DNS rebinding surface because resolution is repeated at request time.

### F-17 (LOW): Meta refresh creates a TCP reachability oracle

**Affected code:** `worker/src/lib/page_security.js:48-105`

A meta refresh to a disallowed port returned `403 PORT_NOT_ALLOWED` and sent no HTTP request, but the target still observed two TCP accepts on the disallowed port. This means Chromium attempted a connection before the request was blocked.

**Impact:** A page can use meta refresh (or similar speculative connection mechanisms) to probe TCP reachability of internal ports even when HTTP requests are blocked. The information leak is weaker than a full request and is classified LOW, but it reinforces that TCP-level egress must be controlled by the network layer.

---

## 6. Egress Proxy Enforcement Evaluation

### 6.1 What was tested

| Scenario | Expected | Observed |
|---|---|---|
| Proxy required, unset | Fail closed | 403 `NETWORK_EGRESS_BLOCKED`; target zero hits; `/health/ready` 200 |
| Proxy required, unreachable | Fail closed | 500; target zero hits |
| Proxy required, blocking local target | No egress | Target zero hits; proxy saw requests; worker returned HTTP 200 with Chrome error page |
| Proxy required, blocking public target | No egress | 500; target zero hits |
| Proxy required, permissive proxy | Proxy enforces? | WebSocket, popup, prerender reached blocked targets; subresources blocked by worker policy; meta blocked; WebRTC UDP bypassed proxy |
| Proxy required, invalid URL | Fail closed | 500; target zero hits |
| Proxy optional, no proxy | Direct browser access | Background Google/update traffic and all page network paths use direct egress |
| Forwarding proxy, subresource | Worker policy blocks | Target zero hits; `blocked_request_count=4`; proxy only saw the page |
| Forwarding proxy, WebSocket | Proxy should enforce | Proxy saw `CONNECT` to target; blocking proxy stopped it; permissive proxy allowed it |
| Forwarding proxy, popup | Proxy should enforce | Proxy saw `GET` to target; blocking proxy stopped it; permissive proxy allowed it |
| Forwarding proxy, prerender | Proxy should enforce | Proxy saw `GET` to target; blocking proxy stopped it; permissive proxy allowed it |

### 6.2 Conclusion

`REQUIRE_EGRESS_PROXY=true` currently means "a proxy URL string is present." It does not mean:

- The proxy is reachable.
- The proxy is the only network path.
- The proxy enforces the same domain/port/private-IP policy.
- WebSocket CONNECT is policy-checked.
- WebRTC UDP is blocked or proxied.
- Browser background traffic is blocked or policy-checked.

A proxy is the right architectural direction, but it must be a policy-enforcement point, not just a transport. The current `proxy/` directory is empty, so this control does not exist yet.

### 6.3 Recommended egress architecture

1. Put the worker on an internal network with no default route to the internet or internal networks.
2. Route all worker egress through a dedicated proxy service.
3. Make the proxy enforce:
   - Allowed domains (including wildcard rules).
   - Allowed ports.
   - Private, loopback, link-local, metadata, documentation, benchmarking, and special-use ranges.
   - DNS resolution and connection IP, with rebinding protection.
   - WebSocket `CONNECT` targets.
   - Optional method/header policy.
4. Deny all non-HTTP protocols at the network layer, including UDP, except explicitly required proxy traffic.
5. Block or disable browser background services, prerender, popups, and WebRTC at the browser level as defense in depth.
6. Require the proxy in production; make missing/unreachable proxy a readiness failure, not only a navigation failure.
7. Add a startup check that the proxy is reachable and policy-enforcing.

---

## 7. Browser Isolation Evaluation

### 7.1 Current isolation model

- One Chromium browser per worker process.
- One default browser context.
- One new page per navigation.
- Page closed after navigation.
- No context/session/agent identity.
- No storage clearing.
- No download or permission policy.
- No WebSocket/WebRTC/prerender/popup network policy.
- `page.setBypassServiceWorker(true)` is used, which is good, but it does not isolate state.

### 7.2 Confirmed state leakage

| State | Result |
|---|---|
| Cookies | Persisted across separate pages/navigations |
| localStorage | Persisted across separate pages/navigations |
| Browser context | Shared default context |
| Agent/session identity | Not represented in browser state |
| Request ID | Correlation only; not an isolation boundary |

### 7.3 Additional isolation gaps

- No `BrowserContext` per agent/session/request.
- No incognito context or per-context user data directory.
- No context-level proxy configuration.
- No context-level permission overrides.
- No download directory or download cancellation policy.
- No upload/file chooser policy.
- No clipboard, geolocation, camera, microphone, notification, or persistent-storage policy.
- No per-session cache/cookie partition.
- No per-session resource quota.
- No guaranteed context cleanup on crash.

### 7.4 Recommended browser isolation architecture

1. Create a fresh `BrowserContext` per agent session, or at minimum per navigation request, using `browser.createBrowserContext()`.
2. Assign a unique proxy/egress identity per context if per-tenant egress policy is required.
3. Clear or destroy the context after the session/request.
4. Disable or explicitly gate:
   - `window.open` / popup creation.
   - Prerender and prefetch beyond policy.
   - WebRTC, or force it through a controlled TURN/TCP path.
   - Background networking and component updates.
   - Downloads and file choosers.
   - Permissions not required for the task.
5. Use CDP target auto-attach with `waitForDebuggerOnStart` so new targets can be instrumented before they execute network requests.
6. Add per-context and per-browser memory/CPU/disk limits.
7. Run the browser in a read-only container with a tmpfs profile and a dedicated unprivileged user.
8. Test state leakage as a regression test: cookie, localStorage, IndexedDB, cache, and auth state must not cross sessions.

---

## 8. Integration Contract Assessment

### 8.1 Policy contract

Current shape:

```python
class PolicyRequest(BaseModel):
    request_id: str
    url: str

class PolicyDecision(BaseModel):
    allowed: bool
    policy_name: str
    reason: str
```

Gaps:

- No effect enum (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`).
- No agent ID, tenant ID, session ID, or caller identity.
- No action/capability being authorized.
- No policy version or decision TTL.
- No obligations or conditions.
- No approval workflow metadata.
- No requested resource classification.
- No distinction between a navigation and a future action/search/extract operation.
- Mock policy allows any HTTP(S) URL, so the contract is not exercised against a real deny path at the API layer.

### 8.2 Inspection contract

Current shape:

```python
class InspectionResult(BaseModel):
    inspector_name: str
    findings: list[Finding] = Field(default_factory=list)
```

Gaps:

- No content classification or trust label.
- No provenance (origin, redirect chain, final URL, fetch time, signature).
- No sanitized/unsafe content split.
- No prompt-injection score or instruction/data boundary.
- No indication that the inspector is mock or non-authoritative.
- Raw HTML is returned directly in `BrowserNavigateResponse.content`.
- The mock inspector uses four regexes and is explicitly not a security control.

### 8.3 Recommended contract changes

Policy:

```text
PolicyRequest:
  request_id, agent_id, session_id, action, url, method, resource_context

PolicyDecision:
  effect: ALLOW | DENY | REQUIRE_APPROVAL
  policy_name, policy_version, reason
  obligations: list[str]
  approval: optional {approval_id, expires_at}
  ttl_seconds
```

Inspection:

```text
InspectionResult:
  inspector_name, inspector_version
  classification: trusted | untrusted | suspicious | malicious | unknown
  findings
  provenance: {requested_url, final_url, redirect_chain, fetched_at, content_type}
  sanitized_content
  raw_content_ref
  prompt_injection: {score, signals}
```

Response:

- Return trust/provenance alongside content.
- Do not present mock findings as authoritative.
- Reject `mock` backends when `environment=production` unless an explicit unsafe override is set.
- Version the policy and inspection contracts.

---

## 9. Production Readiness and Recommended Remediation Plan

### 9.1 Verdict

**Not production ready.** The foundation is a good Phase 1 prototype, but the network policy boundary is incomplete. The current security model is bypassable through standard browser features, and the egress proxy control is not implemented.

### 9.2 First issue to fix

**Fix F-01 and its root cause F-06 first: browser egress is not contained, and `REQUIRE_EGRESS_PROXY` is not network enforcement.**

The immediate goal is: an allowed page must not be able to reach a blocked domain, port, private address, or metadata endpoint through WebSocket, popup, prerender, WebRTC, or background traffic. The durable fix is network-level default-deny egress through a policy-enforcing proxy, plus browser-level hardening.

Files that need modification:

- `worker/src/lib/browser.js`
  - Add/mandate proxy configuration.
  - Disable prerender, WebRTC, background networking, component updates, sync, domain reliability, and other non-essential services.
  - Consider per-context proxy configuration.
- `worker/src/lib/page_security.js`
  - Intercept WebSocket creation/upgrade with CDP (`Network.webSocketCreated`, `Network.webSocketWillSendHandshakeRequest`) or block WebSocket schemes unless explicitly allowed.
  - Attach to new targets before navigation with CDP auto-attach / `waitForDebuggerOnStart` so popups and prerender targets cannot race the handler.
  - Prevent popup creation or attach interception before the popup navigates.
  - Block prerender and WebRTC at the page/network layer.
- `worker/src/config.js`
  - Require `EGRESS_PROXY_URL` when `REQUIRE_EGRESS_PROXY` is true.
  - Default to requiring the proxy in production.
  - Validate the proxy URL and add explicit non-HTTP egress settings.
- `worker/src/routes/navigate.js`
  - Keep the fail-closed proxy check, and surface proxy/network failures as policy errors rather than HTTP 200 with a Chrome error page.
- `proxy/`
  - Implement the policy-enforcing egress proxy (currently empty).
  - Enforce destination allowlist, port policy, private/special-use IP blocking, DNS rebinding protection, and WebSocket `CONNECT` policy.
- `docker-compose.yml`
  - Add the proxy service.
  - Put the worker on an internal network with no direct internet/default route.
  - Add read-only filesystem, `cap_drop`, `no-new-privileges`, pids/memory limits, and tmpfs.
- `worker/Dockerfile`
  - Harden Chromium launch/runtime and ensure the proxy/network path is the only egress.
- `api/app/config.py`, `.env.example`, `README.md`
  - Make production requirements explicit: egress proxy required, mock backends forbidden, private networking off.
- `worker/src/routes/health.js`, `api/app/api/health.py`
  - Make readiness fail when the required proxy is missing or unreachable.
- `api/tests/integration/test_worker_integration.py` and worker tests
  - Add regression cases for WebSocket, prerender, popup, WebRTC, permissive proxy, blocking proxy, and context isolation.

### 9.3 Remediation sequence

**P0 — contain egress**

1. Implement and deploy the policy-enforcing egress proxy.
2. Remove direct worker egress at the network layer.
3. Block WebSocket, WebRTC, prerender, and popup bypasses at the browser level.
4. Require the proxy in production and fail readiness when absent/unreachable.
5. Fix HTTP 200 semantics for blocked/proxy-refused navigation.
6. Add regression tests for every confirmed bypass.

**P1 — isolate callers and sessions**

1. Add API authentication and caller identity.
2. Add tenant/agent/session ownership and authorization.
3. Add rate limiting and concurrency limits.
4. Create a fresh browser context per session/request.
5. Add per-context storage cleanup and permission/download policy.
6. Guard mock backends in production.

**P2 — harden integration and operations**

1. Extend policy/inspection contracts with action, approval, trust, and provenance.
2. Return sanitized/classified content with trust labels.
3. Add DNS pinning/rebinding protection and connection-level IP verification.
4. Add container resource limits and read-only filesystem.
5. Reconcile Node and Python special-use IP ranges.
6. Add observability for blocked egress, proxy denials, context lifecycle, and browser background traffic.

### 9.4 Acceptance criteria for the first fix

- A page on an allowed origin cannot open a WebSocket to a disallowed domain, port, or private IP, with or without a proxy.
- A page cannot use prerender, popup, prefetch, meta refresh, or WebRTC to reach a disallowed destination.
- A permissive or unresponsive proxy cannot be used to bypass worker policy.
- The worker has no direct internet or internal-network route outside the proxy.
- `/health/ready` fails when the required proxy is missing or unreachable.
- Blocked egress returns a clear policy error, not HTTP 200 with a Chrome error page.
- Regression tests cover all of the above and run in CI.
- Context isolation tests prove cookies/localStorage/IndexedDB do not cross sessions.

### 9.5 Test evidence checklist

- [x] Top-level private IP, metadata, DNS-to-private, and `file:` blocks.
- [x] Redirect and HTTP subresource blocking.
- [x] `REQUIRE_EGRESS_PROXY` without proxy and with unreachable proxy.
- [x] WebSocket bypass confirmed.
- [x] Prerender bypass confirmed with cookie.
- [x] Popup bypass confirmed.
- [x] WebRTC UDP bypass confirmed.
- [x] Cookie/localStorage persistence confirmed.
- [x] Permissive proxy bypass confirmed.
- [x] Worker bearer auth behavior confirmed.
- [x] Existing API tests: 29 passed from `api/`.
- [ ] Docker/Compose runtime validation (blocked by missing Docker).
- [ ] End-to-end DNS rebinding exploit (code-level finding only).
- [ ] Direct metadata access via prerender/WebSocket under private-network blocking (inferred from confirmed bypass path).
