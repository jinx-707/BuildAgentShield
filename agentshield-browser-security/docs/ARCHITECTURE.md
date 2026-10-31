# Architecture

**Date:** 2026-10-31

## Purpose

AgentShield Browser Security provides a controlled boundary between an AI agent and the public web. It supports navigation, persistent browser sessions, bounded extraction, guarded actions, screenshots, and provider search. It does not expose arbitrary JavaScript execution, raw CDP, file downloads, or caller-controlled output paths.

## Components

| Component | Runtime | Default port | Responsibility |
| --- | --- | --- | --- |
| FastAPI API | Python 3.11+ | 8000 | Caller authentication, validation, policy, rate limiting, orchestration, inspection, response shaping |
| Browser worker | Node.js 22+ | 8080 | Chromium lifecycle, sessions, navigation, extraction, actions, screenshots |
| Egress proxy | Node.js 22+ | 3128 (proxy), 9090 (health) | Default-deny domain/port policy, DNS validation and IP pinning, HTTP/CONNECT/WebSocket enforcement |
| Chromium | Puppeteer-managed | n/a | Actual page rendering and browser execution |
| Redis | Redis 5+ client protocol | 6379 | Shared fixed-window rate-limit counters across API replicas |

## Trust boundaries

```
Untrusted caller / AI agent
        |
        |  HTTPS or loopback HTTP
        v
[Boundary 1: API authentication, request validation, rate limiting]
        |
        v
FastAPI API
        |
        |  Internal HTTP + optional bearer token
        v
[Boundary 2: worker authentication and session ownership]
        |
        v
Browser worker
        |
        |  Chromium proxy settings; optional proxy Basic auth
        v
[Boundary 3: egress policy, DNS pinning, IP classification]
        |
        v
Egress proxy
        |
        |  Network egress
        v
Public internet
```

The caller is never trusted. Page-derived content is always labeled `untrusted`. The worker is internal-only and must not be published to callers. The proxy is the authoritative network destination boundary.

## Request flows

### Navigation

1. API authenticates the caller when `API_AUTH_TOKEN` is configured.
2. API rate-limits the API-wide scope, then the `navigation` category.
3. API validates scheme, credentials, hostname, port, domain policy, DNS answers, and IP classification.
4. API authorizes the destination with the configured policy engine.
5. API calls the worker with a validated URL and request ID.
6. Worker re-validates the URL, checks egress-proxy readiness, and launches an isolated context.
7. Chromium routes through the proxy; the proxy re-resolves and validates the destination and pins the validated IP.
8. Worker returns bounded text and metadata, never raw HTML to the caller.
9. API re-validates the final URL after redirects, inspects content, and returns an untrusted-labeled response.

### Persistent session, action, extraction, screenshot

1. `POST /v1/browser/session` requires `X-Agent-ID` and creates an owner-bound context.
2. `POST /v1/browser/navigate` may reference that session; the worker refuses use by another owner.
3. `POST /v1/browser/extract` reads bounded text, links, lists, and tables from the owned session.
4. `POST /v1/browser/action` runs `click`, `type`, `scroll`, `page_state`, or guarded `submit_form`.
5. `POST /v1/browser/screenshot` captures a bounded in-memory PNG.
6. Concurrent requests on one session return `409` rather than sharing a page.
7. Idle, absolute-age, and stranded-lease cleanup close contexts without closing an in-flight request.

### Search

1. Caller supplies a query, not a URL.
2. API contacts only the operator-selected fixed provider endpoint.
3. Brave is full web search and requires `SEARCH_API_KEY`.
4. DuckDuckGo Instant Answer is a clearly labeled limited keyless fallback, not full web search.
5. Every result URL is preflighted and authorized before it is returned.
6. Blocked results are dropped and counted in `filtered_count`.

### Rate limiting

- API-wide limit runs before authentication and routing.
- Category limits run after request-body validation.
- Dimensions are agent identity (`X-Agent-ID` when valid), session ID when supplied, and client IP.
- Redis uses one Lua script for atomic `INCR` + `PEXPIRE`; memory counters are process-local and development-only.
- Backend errors fail closed with `503` unless `RATE_LIMIT_FAIL_OPEN=true` is explicitly configured.
- The direct TCP peer is authoritative. `X-Forwarded-For` is used only when that peer is in `RATE_LIMIT_TRUSTED_PROXIES`; the rightmost untrusted address becomes the client identity.
- The API must run with `--no-proxy-headers` (or the ASGI-server equivalent). Uvicorn otherwise trusts `X-Forwarded-For` from `127.0.0.1` by default and rewrites `request.client.host` before the application can apply its own trusted-proxy rules.

## Deployment topology

Docker Compose defines three services:

- `api`: published on `127.0.0.1:${API_PORT}` only, attached to `edge` and `worker-net`.
- `browser-worker`: no host port, attached only to the internal `worker-net`.
- `egress-proxy`: no host port, attached to `worker-net` and `egress-net`.

`worker-net` is `internal: true`. The worker cannot reach the internet directly. Only the proxy is attached to `egress-net`.

## Policy ownership

The same canonical policy values are loaded into the API, worker, and proxy:

- `ALLOWED_DOMAINS`
- `BLOCKED_DOMAINS`
- `DEFAULT_DOMAIN_POLICY`
- `ALLOWED_PORTS`

Each service logs a 16-hex-character policy fingerprint derived from the canonical JSON. Operators can compare startup logs to detect drift. Policy must be configured consistently; the proxy is the final enforcement layer.

## Failure behavior

| Failure | Caller-visible behavior |
| --- | --- |
| Invalid request | `400` or `422` with a structured error envelope |
| Blocked destination or policy denial | `403` |
| Missing/incorrect API token | `401` |
| Missing/invalid agent identity | `400` |
| Session not found | `404` |
| Session owned by another agent | `403 SESSION_FORBIDDEN` |
| Session busy | `409` |
| Rate limit exceeded | `429` with `Retry-After` |
| Rate-limit backend unavailable | `503` by default |
| Worker unavailable or invalid worker response | `502` |
| Worker request timeout | `504` |
| Worker navigation timeout | `504 NAVIGATION_TIMEOUT` |
| Search provider timeout | `504 SEARCH_PROVIDER_TIMEOUT` |
| Search provider unavailable | `503 SEARCH_PROVIDER_UNAVAILABLE` |
| Browser launch failure | `502` with a worker failure code |
| Screenshot too large | `413 SCREENSHOT_DIMENSIONS_EXCEEDED` |
| Payload too large | `400 INPUT_LENGTH_EXCEEDED` or `413` |

## Key invariants

- No arbitrary JavaScript execution endpoint.
- No raw HTML returned to the caller.
- No host browser profile, cookies, or credentials.
- Chromium sandbox is not disabled.
- WebRTC is hard-blocked.
- Downloads and file inputs are refused.
- Session IDs are logical identities, never credentials.
- Page-derived content is always untrusted.
- The worker has no public ingress.
- The proxy, not the API preflight, is the authoritative DNS/egress boundary.

## Non-goals

This module does not provide a full WAF, a production policy authoring system, persistent audit storage, full multi-tenant isolation, file download handling, PDF generation, or a browser extension platform.
