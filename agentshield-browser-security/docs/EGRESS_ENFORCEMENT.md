# Egress Enforcement — Network Isolation Analysis

**Date:** 2026-10-30  
**Phase:** Five — Network-Level Egress Isolation

---

## 1. Actual Enforcement Boundary

The egress enforcement boundary is **layered** across three controls:

| Layer | Control | Strength |
|-------|---------|----------|
| 1. Application (Chromium) | `--proxy-server` + `--proxy-bypass-list=<-loopback>` + `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE <proxy>` | Strong application-level; prevents browser DNS and routes all traffic through proxy |
| 2. Application (Proxy) | Default-deny domain policy + IP classification + DNS IP pinning + CONNECT validation | Strong policy enforcement at connection time |
| 3. Network (Docker) | `worker-net` is `internal: true` (no direct internet); proxy is on `worker-net` + `egress-net` | OS-level isolation in Docker deployment |

### Layer 1: Chromium launch flags

The browser is launched with:
```
--proxy-server=http://127.0.0.1:3128
--proxy-bypass-list=<-loopback>
--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1
```

- `--proxy-server`: all HTTP/HTTPS traffic routes through the egress proxy
- `--proxy-bypass-list=<-loopback>`: the `<-loopback>` token reverses Chromium's implicit localhost bypass, so loopback traffic also goes through the proxy
- `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`: maps every hostname to NOTFOUND except the proxy host, so the browser cannot resolve any destination DNS itself. The proxy handles all DNS resolution.

Additionally:
- `--disable-quic`: blocks QUIC (UDP-based HTTP/3)
- WebRTC is hard-blocked: launch throws if `BROWSER_ALLOW_WEBRTC=true`; JS APIs are removed per-page
- `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`: prevents non-proxied UDP

### Layer 2: Proxy policy enforcement

The proxy enforces at connection time:
1. Domain policy (default-deny, exact + `*.suffix` matching, blocklist precedence)
2. Port allowlist (default 80,443)
3. IP classification (ipaddr.js, blocks private/loopback/link-local/metadata/special-use)
4. DNS resolution with double-lookup + IP pinning (connects to validated IP, not re-resolved)
5. CONNECT tunnel validation
6. WebSocket upgrade validation

### Layer 3: Docker network isolation

```yaml
networks:
  worker-net:
    internal: true    # no direct internet access
  egress-net:          # proxy-only internet access
```

The browser worker container is on `worker-net` only (internal). It cannot reach the internet directly. The proxy is on both `worker-net` and `egress-net`, acting as the only gateway.

---

## 2. Allowed Network Paths

| Source | Destination | Protocol | Enforcement |
|--------|------------|----------|-------------|
| Worker | Proxy (3128) | TCP HTTP proxy | `worker-net` network + proxy health check |
| Worker | Proxy health (9090) | TCP HTTP | `worker-net` network + health probe |
| Proxy | Internet (80,443) | TCP HTTP/HTTPS | Domain policy + IP check + DNS pinning |
| API | Worker (8080) | TCP HTTP | `edge` + `worker-net` networks |
| API | Caller | TCP HTTP | `edge` network (127.0.0.1 binding) |

---

## 3. Blocked Network Paths

| Source | Destination | Why blocked | Enforcement layer |
|--------|------------|-------------|-------------------|
| Browser | Any non-proxy host | `--host-resolver-rules=MAP * ~NOTFOUND` | Chromium launch flag |
| Browser | Direct internet (bypassing proxy) | `--proxy-server` + Docker `internal: true` | Chromium + Docker |
| Browser | Loopback services | `--proxy-bypass-list=<-loopback>` + proxy IP check | Chromium + proxy |
| Browser | Private IPs (10/8, 172.16/12, 192.168/16) | Proxy `isBlockedAddress` | Proxy |
| Browser | Cloud metadata (169.254.169.254) | Proxy `ALWAYS_BLOCKED_ADDRESSES` | Proxy |
| Browser | Link-local (169.254/16) | Proxy `ALWAYS_BLOCKED_RANGES` | Proxy |
| Browser | IPv6 loopback (::1) | Proxy `isBlockedAddress` | Proxy |
| Browser | WebSocket to blocked dest | JS `WebSocket` → throws + proxy validation | JS + proxy |
| Browser | WebRTC/STUN/TURN | JS API removed + launch hard-block + QUIC disabled | JS + launch |
| Browser | UDP traffic | WebRTC blocked + QUIC disabled | Launch flags + JS |
| Browser | Prerender/speculative | `--disable-features` + JS MutationObserver | Launch + JS |
| Browser | Service workers | `navigator.serviceWorker` → undefined + CDP bypass | JS + CDP |
| Browser | Popups | `window.open` → no-op + `page.on("popup")` → close | JS + CDP |

---

## 4. How Direct Egress Is Prevented

### DNS bypass prevention
`--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE <proxy-host>` prevents the browser from resolving any hostname. Even if a request bypassed the proxy, the browser has no IP address to connect to (all DNS returns NOTFOUND except the proxy).

### Proxy bypass prevention
`--proxy-server` routes all traffic through the proxy. `--proxy-bypass-list=<-loopback>` prevents localhost bypass. Docker `internal: true` on `worker-net` prevents direct TCP connections to the internet.

### UDP bypass prevention
WebRTC APIs are removed at the JS level. `--disable-quic` blocks QUIC. `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` prevents non-proxied UDP. No other UDP-capable browser APIs are available (WebTransport not in headless Chromium).

---

## 5. DNS Handling

- The browser does NOT resolve DNS (host-resolver-rules prevents it)
- The proxy resolves DNS at connection time using `dns.lookup`
- The proxy performs a double-lookup to detect DNS rebinding
- The proxy pins to the first validated IP and connects to that literal IP (never re-resolves)
- DNS timeout is enforced (5s default, configurable via `PROXY_DNS_TIMEOUT_MS`)
- DNS failures are fail-closed (request rejected)

---

## 6. IPv6 Handling

- IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are unwrapped and checked as IPv4
- IPv6 loopback (`::1`), unique-local (`fc00::/7`), link-local (`fe80::/10`) are blocked
- IPv6 metadata (`fd00:ec2::254`) is in the explicit blocklist
- 6to4, Teredo, NAT64 are unwrapped/blocked
- Non-unicast IPv6 ranges are blocked by default

---

## 7. UDP Handling

- WebRTC is hard-blocked (launch fails if enabled; JS APIs removed)
- QUIC is disabled (`--disable-quic`)
- No other UDP-capable browser APIs are exposed
- The proxy does not handle UDP (it's an HTTP/CONNECT proxy)

---

## 8. Proxy Failure Behavior

| Scenario | Behavior | Tested? |
|----------|----------|---------|
| Proxy process stopped | Worker `/health/ready` → degraded; navigation → 502 `browser_worker_failure` | Yes (E2E) |
| Proxy health check fails | `assertEgressEnforcement()` throws `EGRESS_PROXY_UNAVAILABLE` | Yes (unit) |
| Proxy returns non-enforcing mode | Health probe fails (requires `mode: "enforcing"`) | Yes (unit) |
| Proxy not configured | `assertEgressEnforcement()` throws `NETWORK_EGRESS_BLOCKED` | Yes (unit) |
| Proxy health cache expired | Re-probes on next navigation; fails closed if proxy is down | Yes (unit) |
| No proxy, `REQUIRE_EGRESS_PROXY=true` | Launch fails; browser does not start | Yes (unit) |

---

## 9. Reproducing Bypass Tests

### Test: Browser cannot resolve DNS
```bash
# Start proxy + worker
# Navigate to a domain NOT in the allowlist
# The browser should not be able to resolve the hostname
# (host-resolver-rules prevents resolution)
```

### Test: Proxy down → no direct egress
```bash
# Start proxy + worker + API
# Verify navigation works
# Stop proxy
# Attempt navigation → should fail with 502
# Check worker /health/ready → degraded
```

### Test: Direct TCP bypass attempt
```bash
# In Docker deployment:
# docker exec into worker container
# Attempt curl to external host → should fail (worker-net is internal)
# Attempt curl through proxy → should work (proxy on egress-net)
```

---

## 10. Remaining Deployment Limitations

### macOS bare metal (development)
On macOS without Docker, there is no OS-level network isolation. The application-level controls (proxy-server, host-resolver-rules, WebRTC block, QUIC disable) are strong but not absolute:

- **Risk**: A Chromium vulnerability could bypass `--proxy-server` and make a direct TCP connection. Mitigated by `--host-resolver-rules=MAP * ~NOTFOUND` (no DNS to resolve), but a hardcoded IP address could theoretically bypass.
- **Mitigation**: Use Docker Compose deployment for production. The `internal: true` worker network provides OS-level isolation.

### Docker (production)
Docker Compose provides proper network isolation:
- Worker container is on `worker-net` (internal, no internet)
- Proxy is the only gateway to `egress-net`
- Container hardening: read-only FS, cap_drop ALL, no-new-privileges, pids/mem limits

### Unresolved: OS-level firewall rules
The Docker `internal: true` network prevents outbound traffic, but does not apply per-process firewall rules. A compromised worker process could potentially use raw sockets if container capabilities were not dropped (they are: `cap_drop: ALL`).
