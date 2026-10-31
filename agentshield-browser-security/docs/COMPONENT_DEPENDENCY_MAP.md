# Component Dependency Map

**Module:** AgentShield Browser Security — Prompt 1 Core Integration  
**Date:** 2026-10-31

## Overview

This document maps the components of the AgentShield browser security gateway,
their dependencies, communication paths, and implementation status.

## Components

| Component | Runtime | Language | Port | Status |
|-----------|---------|----------|------|--------|
| FastAPI API | Python 3.11+ / Uvicorn | Python | 8000 | Implemented |
| Browser worker | Node.js 22+ | Node.js | 8080 | Implemented |
| Egress proxy | Node.js 22+ | Node.js | 3128 / 9090 | Implemented |
| Chromium | Puppeteer | C++ | n/a | Implemented |
| Redis (optional) | Redis 5+ | n/a | 6379 | Optional (dev: memory) |

## Dependency Map

```
AI Agent / Caller
        |
        | HTTPS / loopback HTTP (X-Agent-ID, Authorization)
        v
+-----------------------------+
| FastAPI API (port 8000)     |
|  - Caller auth (Bearer)     |
|  - Request validation       |
|  - Rate limiting            |
|  - Policy engine (egress-policy or mock) |
|  - Content inspector (prompt-injection or mock) |
|  - Network preflight (URL + DNS) |
|  - Orchestration            |
|  - Audit events             |
+-----------------------------+
        |
        | Internal HTTP (X-Agent-ID, X-Request-ID, Bearer WORKER_AUTH_TOKEN)
        v
+-----------------------------+
| Browser worker (port 8080)  |
|  - Worker auth (Bearer)     |
|  - Session registry (owner-bound) |
|  - URL guard + domain policy |
|  - Egress proxy enforcement |
|  - Chromium context lifecycle |
|  - Request interception / redirect validation |
+-----------------------------+
        |
        | Chromium --proxy-server (HTTP/CONNECT)
        v
+-----------------------------+
| Egress proxy (port 3128)    |
|  - Proxy auth (Basic)       |
|  - Domain/port/IP policy    |
|  - DNS rebinding protection |
|  - Metadata IP blocking     |
+-----------------------------+
        |
        | Network egress
        v
Public internet / Controlled destination
```

## Communication Paths

### API → Worker

- Protocol: HTTP (internal, on `worker-net` in Compose)
- Auth: `Authorization: Bearer <WORKER_AUTH_TOKEN>` when configured
- Identity: `X-Agent-ID` header (forwarded verbatim, not a credential)
- Request ID: `X-Request-ID` header
- Endpoints used by API:
  - `GET /health/live`, `GET /health/ready` — readiness
  - `POST /v1/session`, `GET /v1/session/{id}`, `DELETE /v1/session/{id}` — session lifecycle
  - `POST /v1/navigate` — constrained navigation
  - `POST /v1/extract` — bounded text extraction
  - `POST /v1/action` — guarded browser action
  - `POST /v1/screenshot` — bounded PNG capture

### Worker → Proxy

- Protocol: HTTP/CONNECT via Chromium `--proxy-server`
- Auth: `Proxy-Authorization: Basic agentshield:<PROXY_AUTH_TOKEN>` when configured
- The worker never connects directly to destinations when `REQUIRE_EGRESS_PROXY=true` and no proxy is reachable (fail-closed).
- When `REQUIRE_EGRESS_PROXY=false`, Chromium may connect directly (development-only explicit mode).

### API → Redis (optional)

- Protocol: Redis RESP
- Purpose: Shared fixed-window rate-limit counters across API replicas
- Dev default: process-local memory (not shared, not production-safe)

### API → Search provider

- Protocol: HTTPS to fixed provider endpoint
- Purpose: Web search with pre-validated result URLs
- Caller supplies a query, never a URL

## Implementation Matrix

| Capability | API | Worker | Proxy | Tests | Status |
|------------|-----|--------|-------|-------|--------|
| Caller authentication | ✅ | ❌ | ❌ | ✅ | Implemented |
| Worker authentication | ❌ | ✅ | ❌ | ✅ | Implemented |
| Proxy authentication | ❌ | ❌ | ✅ | ✅ | Implemented |
| URL validation (scheme, creds, hostname, port) | ✅ | ✅ | ✅ | ✅ | Implemented |
| DNS preflight | ✅ | ✅ | ✅ | ✅ | Implemented |
| Private IP / metadata blocking | ✅ | ✅ | ✅ | ✅ | Implemented |
| Domain allowlist/denylist | ✅ | ✅ | ✅ | ✅ | Implemented |
| Default-deny policy | ✅ | ✅ | ✅ | ✅ | Implemented |
| Redirect validation | ✅ (re-check) | ✅ (interception) | ❌ | ✅ | Implemented |
| Session lifecycle (create/get/close) | ✅ | ✅ | ❌ | ✅ | Implemented |
| Session ownership enforcement | ❌ (delegates) | ✅ | ❌ | ✅ | Implemented |
| Browser navigation | ❌ (orchestrates) | ✅ | ❌ | ✅ | Implemented |
| Bounded extraction | ✅ | ✅ | ❌ | ✅ | Implemented |
| Guarded browser actions | ✅ | ✅ | ❌ | ✅ | Implemented |
| Bounded screenshots | ✅ | ✅ | ❌ | ✅ | Implemented |
| Content inspection | ✅ | ❌ | ❌ | ✅ | Implemented |
| Policy engine | ✅ | ❌ | ❌ | ✅ | Implemented |
| Rate limiting | ✅ | ❌ | ❌ | ✅ | Implemented |
| Audit events | ✅ | ❌ | ❌ | ✅ | Implemented |
| Egress proxy enforcement | ❌ | ✅ | ✅ | ✅ | Implemented |
| No silent direct-egress fallback | ✅ | ✅ | ✅ | ✅ | Implemented |
| OpenAPI documentation | ✅ | ❌ | ❌ | ❌ | Implemented |
| Persistent database (PostgreSQL) | ❌ | ❌ | ❌ | ❌ | Missing (Prompt 2) |
| RBAC / Organizations | ❌ | ❌ | ❌ | ❌ | Missing (Prompt 2) |
| Real-time monitoring (SSE/WS) | ❌ | ❌ | ❌ | ❌ | Missing (Prompt 2) |

## Key Invariants

1. **All outbound traffic flows through the proxy.** The API enforces policy before calling the worker; the worker requires egress-proxy readiness before navigating; the proxy is the final network boundary.
2. **No silent direct-egress fallback.** When `REQUIRE_EGRESS_PROXY=true`, navigation fails if the proxy is not configured or unhealthy. The worker sets `--host-resolver-rules=MAP * ~NOTFOUND` when no proxy is configured and proxy is required.
3. **Session IDs are not credentials.** Session ownership is verified by the worker against the `X-Agent-ID` presented by the caller.
4. **Page-derived content is untrusted.** All extracted/returned content carries `trust_label: "untrusted"`.
5. **No arbitrary JavaScript execution.** There is no `evaluate` or raw CDP endpoint.
6. **Chromium sandbox is not disabled.** `--no-sandbox` is never passed.

## Configuration Consistency

The same canonical policy values must be loaded into all three components:

- `ALLOWED_DOMAINS`
- `BLOCKED_DOMAINS`
- `DEFAULT_DOMAIN_POLICY`
- `ALLOWED_PORTS`

Each component logs a 16-hex-character SHA-256 fingerprint of the canonical policy at startup. Operators compare fingerprints across services to detect drift.

## Implementation Status Summary

- **Implemented:** API, worker, proxy, policy engine, content inspection, session lifecycle, rate limiting, auth, audit events, Docker Compose, startup scripts, OpenAPI docs.
- **Partially implemented:** Rate-limit Redis backend (code exists, defaults to memory in dev).
- **Missing:** PostgreSQL persistence, RBAC, organizations, real-time monitoring, SIEM integration, signed policy distribution, hybrid control/data plane separation (Prompts 2-4).
