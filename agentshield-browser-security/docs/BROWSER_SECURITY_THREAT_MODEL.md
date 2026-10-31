# AgentShield Browser Security — Threat Model

**Date:** 2026-10-30  
**Phase:** One — Threat Model and Security Requirements

---

## A. SSRF (Server-Side Request Forgery)

### Threat

An agent-controlled browser request reaches internal infrastructure, cloud metadata endpoints, or private networks.

### Protected ranges

| Range | Type | Blocked by |
|-------|------|-----------|
| 127.0.0.0/8 | IPv4 loopback | API `is_blocked_ip`, Worker `isBlockedAddress`, Proxy `isBlockedAddress` |
| 10.0.0.0/8 | IPv4 private | All three (gated by `allow_private_networks=false`) |
| 172.16.0.0/12 | IPv4 private | All three |
| 192.168.0.0/16 | IPv4 private | All three |
| 169.254.0.0/16 | IPv4 link-local | All three (always blocked) |
| ::1/128 | IPv6 loopback | All three |
| fc00::/7 | IPv6 unique-local | All three |
| fe80::/10 | IPv6 link-local | All three (always blocked) |
| ::ffff:0:0/96 | IPv4-mapped IPv6 | All three (unwrapped to IPv4, then checked) |
| 169.254.169.254 | AWS/GCP metadata | All three (explicit blocklist) |
| 169.254.170.2 | ECS metadata | All three |
| 100.100.100.200 | Alibaba metadata | All three |
| fd00:ec2::254 | AWS IPv6 metadata | All three |
| 224.0.0.0/4 | IPv4 multicast | All three (always blocked) |
| 0.0.0.0/8 | IPv4 unspecified | All three (always blocked) |
| 2001:10::/28 | Deprecated ORCHID | Worker/proxy: blocked by ipaddr.js `deprecatedOrchid`; API: blocked by `not is_global` |
| 2001:2::/48 | Benchmarking | Worker/proxy: blocked by ipaddr.js `benchmarking`; API: blocked by `not is_global` |

### IP classification approach

Worker and proxy use `ipaddr.js` (library, not manual list) for range classification with a small explicit blocklist for metadata IPs. The API uses Python's `ipaddress.is_global` as a catch-all. Parse failures are treated as blocked (fail-closed) in all three.

### Edge cases handled

- Decimal IP forms (`2130706433` → 127.0.0.1): blocked as ambiguous
- Hex IP forms (`0x7f000001`): blocked as ambiguous
- Octal IP forms (`0177.0.0.1`): blocked as ambiguous
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`): unwrapped, checked as IPv4
- 6to4, Teredo, NAT64: unwrapped/blocked
- Scoped IPv6 (`fe80::1%eth0`): blocked (API rejects `%`)

### Test requirements

- Direct IP literal navigation to each range
- DNS resolution to each range
- IPv4-mapped IPv6 bypass attempts
- Ambiguous numeric forms
- Parser confusion (mixed decimal/hex/octal)

---

## B. DNS Rebinding

### Threat

An attacker-controlled DNS record returns a public IP during preflight validation, then returns a private IP when the browser/proxy connects.

### Current protection

The **egress proxy** is the authoritative DNS enforcement boundary:
1. Proxy resolves DNS at connection time (not preflight)
2. Proxy performs **double-lookup**: resolve → check all IPs → resolve again → check again
3. Proxy **pins to the first validated IP** and connects to that literal IP (never re-resolves at connect time)
4. Worker's `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE <proxy>` prevents Chromium from resolving DNS itself; all DNS goes through the proxy

### Residual risk

The API's DNS preflight is a TOCTOU (resolves at preflight, Chromium connects later), but this is defense-in-depth only. The proxy's IP pinning is the real mitigation. If the proxy is bypassed (e.g., `REQUIRE_EGRESS_PROXY=false`), the API preflight's DNS check becomes the only gate and is vulnerable to rebinding.

### Test requirements

- Deterministic test resolver that returns public then private
- Mixed DNS answers (any private member blocks)
- DNS timeout behavior
- DNS error behavior
- Multiple A/AAAA records

---

## C. Redirect Attacks

### Threat

An approved destination redirects to a prohibited destination (private IP, metadata, unapproved domain, HTTP downgrade).

### Current protection (worker)

1. `page.setRequestInterception(true)` intercepts all requests including redirects
2. `inspectRedirectChain()` checks: `max_redirects` exceeded, HTTPS→HTTP downgrade, redirect loops
3. Each redirect hop is re-validated through `validateNavigationUrl()` (re-resolves DNS per hop)
4. Blocked redirect destination on main frame → `REDIRECT_DESTINATION_BLOCKED` error surfaced

### Current protection (proxy)

The proxy validates each new connection independently. Redirect targets that create new connections go through `resolveDestination()` → domain policy → IP check → DNS pinning. A redirect to a blocked destination is rejected at the proxy level.

### Gaps

- API does not re-validate `final_url` after worker returns (delegates to worker)
- API's `max_redirects` / `block_https_downgrade` config is unused by API code (worker enforces via its own env config)

### Test requirements

- Redirect from approved → private IP
- Redirect from approved → metadata
- HTTPS → HTTP downgrade
- Redirect loop
- Redirect chain exceeding limit
- Redirect to IP literal
- Redirect to unapproved domain

---

## D. Browser-Level Attacks

### Capabilities and enforcement

| Capability | Status | Enforcement |
|-----------|--------|-------------|
| Popups | **Blocked** | `window.open` → no-op (JS); `page.on("popup")` → always close; `targetcreated` → close non-main pages |
| New tabs | **Blocked** | `targetcreated` handler closes unexpected page targets |
| Frames/iframes | **Intercepted** | Request interception covers iframe navigation; subresource URLs validated |
| Service workers | **Blocked** | `navigator.serviceWorker` → undefined (JS); `setBypassServiceWorker(true)` (CDP); `ServiceWorkerBackgroundSync` disabled |
| WebSockets | **Blocked** | `WebSocket`/`MozWebSocket` → throwing constructor (JS); `page.on("websocket")` → close (CDP backstop); proxy validates ws/wss |
| WebRTC | **Hard-blocked** | `RTCPeerConnection` → undefined (JS); launch throws if `allowWebrtc=true`; `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`; `--webrtc-ip-handling-policy=disable_non_proxied_udp` |
| WebTransport | **N/A** | No WebTransport API in current Chromium headless; no launch flag needed |
| WebUSB | **Disabled** | `--disable-extensions`, no device permissions granted |
| WebBluetooth | **Disabled** | `--deny-permission-prompts`, no device permissions |
| Downloads | **Restricted** | No download path configured; browser contexts closed after each request |
| File URLs | **Blocked** | Scheme allowlist: only `http:`/`https:`; `file:` rejected |
| Data URLs | **Allowed (non-nav)** | `data:`/`blob:`/`about:` allowed for non-navigation subresources only; blocked for navigation |
| Browser extensions | **Disabled** | `--disable-extensions`, `--disable-plugins` |
| Debugging interface | **Not exposed** | No `--remote-debugging-port`; `--proxy-server` routes all traffic |
| Web workers | **Allowed** | Workers are page-scoped; network requests from workers go through request interception |
| Shared workers | **Allowed** | Same as web workers — network through interception |
| Prerendering | **Blocked** | `--disable-features=Prerender,SpeculationRules,...`; JS strips `<link rel="prerender">` + MutationObserver |
| Speculative connections | **Blocked** | `--disable-features=NetworkPrediction,PreconnectToSearch`; JS strips preconnect/prefetch/dns-prefetch links |
| DNS prefetching | **Blocked** | `--host-resolver-rules=MAP * ~NOTFOUND` prevents browser DNS; `dns-prefetch` links stripped |
| QUIC | **Disabled** | `--disable-quic` |
| HTTP/2 | **Allowed** | Goes through proxy; proxy handles HTTP/1.1 upstream |
| HTTP/3 | **Disabled** | QUIC disabled |
| Browser cache | **Disabled** | `Network.setCacheDisabled(true)` (CDP) |
| Cookies | **Isolated** | Fresh `createBrowserContext()` per request; closed in `finally` |
| Local storage | **Isolated** | Fresh browser context per request |
| IndexedDB | **Isolated** | Fresh browser context per request |
| Persistent storage | **Isolated** | Fresh browser context; no shared user-data directory |

### Test requirements

- Popup → blocked destination (already tested)
- WebSocket to blocked destination (already tested)
- WebRTC restriction (already tested)
- Service worker registration blocked
- File URL navigation blocked
- Data URL navigation blocked
- Large HTML response handling
- Navigation timeout

---

## E. Prompt Injection and Untrusted Content

### Threat

Webpage content contains instructions designed to manipulate the AI agent or downstream systems into executing attacker-desired actions.

### Current state

The `MockContentInspector` performs a simple regex scan for `<script`, `javascript:`, and `on*=` handlers. This is explicitly documented as "not a security control" and does not detect prompt injection patterns.

### Required detection patterns

- "ignore previous instructions" / "disregard the above"
- "you are now..." / "act as..." role manipulation
- "reveal your system prompt" / "show me your instructions"
- Credential/secret extraction requests
- Tool invocation manipulation ("run this command", "call this API")
- Navigation to attacker-controlled destinations
- Hidden instructions in HTML comments, ARIA labels, metadata
- Obfuscated instructions (base64, unicode, HTML entities)
- Indirect prompt injection via embedded content

### Content trust model

| Content source | Trust level |
|---------------|-------------|
| System instructions | Trusted |
| Developer instructions | Trusted |
| User requests | Semi-trusted (user is authenticated) |
| Webpage content | **Untrusted** |
| Tool output | Semi-trusted (depends on source) |

The API response must clearly mark webpage content as untrusted. Returned HTML must not be treated as instructions by downstream agents.

### Test requirements

- Detection of common prompt injection patterns
- Obfuscated instruction detection
- False positive tolerance (legitimate content not flagged)
- Trust labeling in API response

---

## F. Denial of Service

### Threat

Resource exhaustion through large pages, infinite redirects, slow responses, excessive concurrency, or browser crashes.

### Current limits

| Resource | Limit | Enforced by |
|----------|-------|-------------|
| URL length | 4096 chars | API UrlPolicy, Worker url_guard |
| Request body | 32KB (worker), 1MB (FastAPI default) | Worker express.json, FastAPI |
| Content extraction | 512KB (maxContentBytes) | Worker content.js |
| Navigation timeout | 20000ms (configurable 1000-60000) | Worker navigate route |
| Redirect limit | 5 (configurable, max 20) | Worker page_security |
| Browser context idle timeout | 300000ms (5 min) | Worker browser.js |
| Proxy connect timeout | 10000ms | Proxy proxy.js |
| Proxy health check timeout | 3000ms | Worker egress.js |

### Gaps

- No max-concurrent-browser-contexts limit (DoS via many parallel navigations)
- Proxy DNS has no timeout (can hang indefinitely)
- Proxy HTTP upstream timeout misconfigured (capped at 2000ms)
- Proxy WebSocket upgrade has no timeout
- No per-caller rate limiting at API

### Test requirements

- Large HTML response (truncation at 512KB)
- Navigation timeout enforcement
- Concurrent session behavior
- Browser crash recovery
- Repeated navigation
- Session cleanup after timeout

---

## G. Network-Level Egress Isolation

### Threat

The browser process establishes direct outbound connections bypassing the egress proxy.

### Current enforcement (application layer)

- `--proxy-server=<proxy_url>`: routes all browser HTTP traffic through proxy
- `--proxy-bypass-list=<-loopback>`: prevents loopback bypass (sends loopback through proxy too)
- `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE <proxy>`: browser cannot resolve any DNS; all resolution goes through proxy
- `--disable-quic`: blocks QUIC (UDP-based)
- WebRTC hard-blocked: no UDP egress path
- Request interception: all HTTP requests validated before continuing

### Current enforcement (network layer — Docker Compose)

- `worker-net` is `internal: true` — no direct internet access from worker container
- `egress-net` is the only network with internet access
- Proxy is on both `worker-net` and `egress-net`
- Worker can only reach the proxy (no direct internet route)

### Residual risk (bare metal macOS)

On macOS without Docker, there is no OS-level network isolation. The browser process can theoretically bypass the proxy via:
- Direct TCP connections (if Chromium ignores --proxy-server for some protocols)
- UDP traffic (mitigated by WebRTC block + QUIC disable)
- DNS bypass (mitigated by --host-resolver-rules)

The `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE <proxy>` is the strongest application-level control: it prevents the browser from resolving any hostname, so even if a request bypassed the proxy, it would have no IP to connect to. The only hostname the browser can resolve is the proxy itself.

**This is application-level enforcement, not OS-level.** For production, Docker Compose with `internal: true` worker network provides the network-level boundary. On bare metal, the proxy + host-resolver-rules combination is strong but not absolute.

### Test requirements

- Proxy down → browser navigation fails (no direct egress)
- DNS bypass attempt → blocked by host-resolver-rules
- Direct TCP attempt from browser → no route (host-resolver-rules prevents DNS)
- Docker network isolation → worker cannot reach internet directly
