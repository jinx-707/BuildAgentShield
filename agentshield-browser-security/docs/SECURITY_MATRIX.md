# Security Control Matrix

**Date:** 2026-10-31  
**Scope:** Implemented controls in the API, worker, proxy, deployment, and tests.

## Legend

- **Implemented:** enforced in code and covered by tests.
- **Partial:** enforced, but with a documented residual risk or deployment dependency.
- **Deployment-dependent:** requires operator configuration or network isolation.
- **Not implemented:** out of scope or a known gap.

## Network and SSRF

| Control | Layer | Status | Evidence / notes |
| --- | --- | --- | --- |
| HTTP(S)-only URL schemes | API, worker, proxy | Implemented | URL policy and proxy reject other schemes |
| Embedded credentials rejected | API, worker | Implemented | `INVALID_URL` / worker URL guard |
| Ambiguous numeric IP forms rejected | API, worker, proxy | Implemented | Decimal/hex/octal forms blocked |
| Loopback/private/link-local blocked by default | API, worker, proxy | Implemented | `ALLOW_PRIVATE_NETWORKS=false` default |
| Cloud metadata addresses blocked | API, worker, proxy | Implemented | Includes AWS/GCP/ECS/Alibaba and IPv6 metadata |
| IPv4-mapped IPv6 unwrapped and checked | API, worker, proxy | Implemented | `::ffff:127.0.0.1` blocked |
| Multicast, unspecified, reserved ranges blocked | API, worker, proxy | Implemented | Fail-closed parse behavior |
| Domain allowlist/denylist | API, worker, proxy | Implemented | Default-deny; blocklist precedence |
| Wildcard matching without suffix bypass | API, worker, proxy | Implemented | `*.example.com` does not allow `example.com` |
| Port allowlist | API, worker, proxy | Implemented | Default `80,443` |
| DNS preflight | API | Implemented | Defense in depth; not authoritative |
| DNS double-lookup and IP pinning | Proxy | Implemented | Proxy connects to validated literal IP |
| Proxy is the authoritative egress boundary | Deployment | Deployment-dependent | `REQUIRE_EGRESS_PROXY=true`; Docker internal network |
| Worker has no direct internet route | Deployment | Deployment-dependent | Compose `worker-net` is `internal: true` |
| Redirect destination revalidation | API, worker, proxy | Implemented | API revalidates worker `final_url` |
| Redirect limit and loop detection | Worker | Implemented | `MAX_REDIRECTS` |
| HTTPS downgrade blocked | Worker | Implemented | `BLOCK_HTTPS_DOWNGRADE=true` |
| WebSocket upgrades policy-checked | Proxy, worker | Implemented | Proxy validates upgrade; page security blocks WebSocket API |
| WebRTC hard-blocked | Worker | Implemented | Launch fails if enabled; page APIs removed |
| Popups/prerender/prefetch blocked | Worker | Implemented | Page security and browser flags |

## Browser isolation and execution

| Control | Layer | Status | Evidence / notes |
| --- | --- | --- | --- |
| No arbitrary JavaScript execution endpoint | API, worker | Implemented | Supported actions only |
| No raw CDP exposure | API, worker | Implemented | No caller-controlled CDP |
| Ephemeral browser profile | Worker | Implemented | No host profile/cookies |
| Chromium sandbox not disabled | Worker, deployment | Implemented | No `--no-sandbox` |
| Per-request isolated browser context | Worker | Implemented | Separate contexts |
| Session owner binding | API, worker | Implemented | `X-Agent-ID` owner check |
| Session ID alone is not authorization | Worker | Implemented | Owner required on every operation |
| Concurrent use of one session refused | Worker | Implemented | `409 SESSION_CHECKED_OUT` |
| Idle, max-age, and lease cleanup | Worker | Implemented | Background sweep; in-flight requests protected |
| Browser crash recovery | Worker | Implemented | Sessions invalidated; worker relaunches |
| Downloads and file inputs refused | Worker | Implemented | Click/submit guards |
| Guarded form submission | Worker | Implemented | Destination validation; confirmation for risky submissions |

## Content and data handling

| Control | Layer | Status | Evidence / notes |
| --- | --- | --- | --- |
| Bounded navigation content | Worker | Implemented | `BROWSER_MAX_CONTENT_BYTES` |
| Bounded extraction text/links | Worker | Implemented | Byte and record limits |
| Hidden content excluded from extraction | Worker | Implemented | `hidden_content_excluded` |
| Page-derived content labeled untrusted | API, worker | Implemented | `trust_label: "untrusted"` |
| Typed values redacted/withheld | Worker, API | Implemented | No typed-value logging; redaction |
| Screenshots bounded and in-memory | Worker, API | Implemented | Dimensions, bytes, rate, concurrency, timeout |
| No filesystem path disclosure | Worker, API | Implemented | In-memory PNG response |
| Search provider results prevalidated | API | Implemented | Preflight + policy before return |
| Search keys held as secrets | API | Implemented | `SecretStr`; not logged/returned |
| Mock policy/inspection rejected in production | API | Implemented | Startup guard |
| Prompt-injection inspection | API | Partial | Heuristic detector, not a complete sanitizer |
| Raw HTML not returned for execution | API | Implemented | Caller receives bounded content |

## Authentication, authorization, and abuse control

| Control | Layer | Status | Evidence / notes |
| --- | --- | --- | --- |
| API bearer authentication | API | Implemented | Optional in dev; required in production |
| Worker bearer authentication | Worker | Implemented | Optional in dev; required in production |
| Proxy Basic authentication | Proxy | Partial | Optional; strongly recommended |
| Timing-safe token comparison | API, worker, proxy | Implemented | Constant-time comparisons |
| Request ID validation/propagation | API, worker | Implemented | Bounded pattern |
| API-wide rate limit | API | Implemented | Before auth/routing |
| Per-category rate limits | API | Implemented | Navigation, search, session, action, extract, screenshot |
| Tenant/session/IP dimensions | API | Implemented | First exceeded dimension wins |
| Shared Redis counters | API, Redis | Implemented | Atomic Lua script |
| Memory backend rejected in production | API | Implemented | Startup failure |
| Rate-limit backend failure fails closed | API | Implemented | `503` by default |
| Explicit fail-open mode | API | Partial | Requires `RATE_LIMIT_FAIL_OPEN=true`; not recommended |
| Trusted-proxy-aware XFF | API | Implemented | Direct peer authoritative; rightmost untrusted |
| Malformed trusted XFF rejected | API | Implemented | `400 INVALID_FORWARDED_FOR` |
| ASGI proxy-header bypass closed | Deployment | Implemented | `--no-proxy-headers` in Dockerfile/README/E2E |
| Owner-based session authorization | API, worker | Implemented | Not a substitute for tenant isolation |

## Deployment hardening

| Control | Layer | Status | Evidence / notes |
| --- | --- | --- | --- |
| API published on loopback only | Compose | Implemented | `127.0.0.1:${API_PORT}:8000` |
| Worker no published port | Compose | Implemented | `expose` only |
| Proxy no published port | Compose | Implemented | `expose` only |
| Internal worker network | Compose | Implemented | `worker-net.internal: true` |
| Non-root containers | Dockerfiles | Implemented | API/worker/proxy users |
| Read-only root filesystems | Compose | Implemented | With tmpfs mounts |
| Capability drop | Compose | Implemented | `cap_drop: ALL` |
| `no-new-privileges` | Compose | Implemented | All services |
| Resource limits | Compose | Implemented | Memory, pids, CPU |
| Structured JSON logging | API, worker, proxy | Implemented | Request IDs and redaction |
| Persistent audit storage | n/a | Not implemented | Logs are not an audit ledger |
| Full tenant isolation | n/a | Not implemented | Owner-bound sessions only |

## Known residual risks

1. **Docker Compose was not executed in this environment.** Configuration was reviewed statically; runtime container behavior, sandbox compatibility, and network isolation were not verified here.
2. **Proxy authentication is optional.** Any network peer that can reach the proxy without `PROXY_AUTH_TOKEN` may use it, subject to destination policy. Set a strong token and keep the proxy internal.
3. **The API and worker can be configured with mocks in development.** Production rejects mock policy/inspection backends, but operators must set real backends explicitly.
4. **Prompt-injection detection is heuristic.** It flags suspicious content; it is not a guarantee that untrusted content is safe.
5. **DNS rebinding is mitigated at the proxy, not by API preflight alone.** If the proxy is bypassed, the API preflight is not sufficient.
6. **E2E depends on external services.** DEMO 1 uses `example.com`; DEMO 5 uses DuckDuckGo.
7. **No persistent audit ledger or SIEM integration.** JSON logs are the current evidence trail.
8. **`RATE_LIMIT_BURST` is defined but not used.** It is reserved; do not rely on burst behavior.
9. **The final acceptance verdict is controlled-demo, not production.** See `FINAL_ACCEPTANCE_REPORT.md`.
