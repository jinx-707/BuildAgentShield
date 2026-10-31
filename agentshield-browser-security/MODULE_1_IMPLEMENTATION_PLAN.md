# AgentShield Browser Security — Module 1 Implementation Plan

**Date:** 2026-10-31  
**Repository:** `/Users/admin/whack/agentshield-browser-security`  
**Status:** Pre-implementation — no source files modified  
**Audit baseline:** `MODULE_1_COMPLETION_AUDIT.md`

---

## 1. Current Architecture

### 1.1 Components and Responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│  FastAPI API  (api/  — Python 3.12+, port 8000)                │
│                                                                  │
│  Routes:  POST /v1/browser/navigate                             │
│           GET  /health/live  /health/ready  /health             │
│                                                                  │
│  Middleware stack (innermost first):                            │
│    RateLimitMiddleware  — in-memory sliding window, per IP      │
│    ApiAuthMiddleware    — Bearer token, timing-safe             │
│    RequestContextMiddleware — X-Request-ID propagation          │
│                                                                  │
│  Security pipeline (orchestrator.py):                           │
│    NetworkPreflight.validate()  →  URL + DNS + IP               │
│    PolicyEngine.authorize()     →  domain allowlist/denylist    │
│    BrowserWorkerClient.navigate()  →  HTTP to worker            │
│    [re-validate final_url after redirects]                      │
│    ContentInspector.inspect()   →  prompt injection scan        │
└───────────────────┬─────────────────────────────────────────────┘
                    │ HTTP Bearer  worker-net (Docker internal)
┌───────────────────▼─────────────────────────────────────────────┐
│  Node Worker  (worker/  — Node.js 22+, port 8080)              │
│                                                                  │
│  Routes:  POST /v1/navigate                                     │
│           GET  /health/live  /health/ready  /health             │
│                                                                  │
│  Per-request pipeline (navigate.js):                            │
│    validateNavigationUrl()     — URL/DNS/IP guard               │
│    assertEgressEnforcement()   — proxy health check             │
│    createIsolatedPage()        — fresh BrowserContext           │
│    installPageSecurity()       — interception + JS hardening    │
│    page.goto()                 — navigate through proxy         │
│    truncateUtf8(page.content()) — return HTML                   │
└───────────────────┬─────────────────────────────────────────────┘
                    │ HTTP CONNECT / proxy  worker-net
┌───────────────────▼─────────────────────────────────────────────┐
│  Egress Proxy  (proxy/  — Node.js 22+, port 3128 / 9090)       │
│                                                                  │
│  Handles:  HTTP, HTTPS CONNECT, WebSocket CONNECT               │
│  Enforces: domain allowlist/denylist, port policy,              │
│            private/reserved IP blocking,                        │
│            DNS resolution + double-resolve rebinding check,     │
│            optional proxy auth token                            │
│  Health:   GET /health/ready  (port 9090)                       │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Docker Network Topology

```
edge        — API exposed on 127.0.0.1:8000  (external callers)
worker-net  — API ↔ worker  (internal: true — no internet access)
egress-net  — proxy → internet  (outbound only)

worker container: worker-net only → cannot reach internet directly
proxy container: worker-net + egress-net
api container: edge + worker-net
```

### 1.3 Key File Map

| Area | Files |
|---|---|
| API app wiring | `api/app/main.py`, `api/app/config.py`, `api/app/factories.py` |
| API routes | `api/app/api/browser.py`, `api/app/api/health.py` |
| API orchestration | `api/app/services/orchestrator.py` |
| API schemas | `api/app/schemas/browser.py`, `api/app/schemas/health.py` |
| API client | `api/app/clients/browser_worker.py` |
| API middleware | `api/app/middleware.py` |
| API security | `api/app/security/` (8 files — do not modify) |
| API interfaces | `api/app/interfaces/inspection.py`, `api/app/interfaces/policy.py` |
| API mocks | `api/app/mocks/inspection.py`, `api/app/mocks/policy.py` |
| Worker entry | `worker/src/index.js`, `worker/src/app.js`, `worker/src/config.js` |
| Worker routes | `worker/src/routes/navigate.js`, `worker/src/routes/health.js` |
| Worker browser | `worker/src/lib/browser.js` |
| Worker security | `worker/src/lib/page_security.js`, `worker/src/lib/url_guard.js` |
| Worker egress | `worker/src/lib/egress.js` |
| Worker content | `worker/src/lib/content.js` |
| Proxy entry | `proxy/src/index.js` |
| Proxy policy | `proxy/src/lib/policy.js` |
| Proxy transport | `proxy/src/lib/proxy.js` |

---

## 2. Existing Security Controls (Invariants — Must Not Be Weakened)

Every new feature must route through or alongside these controls.

| Control | Enforcement point | Tested by |
|---|---|---|
| URL scheme allowlist (http/https only) | `UrlPolicy.validate()`, `validateNavigationUrl()` | `test_security_hardening.py`, `test_worker_integration.py` |
| Domain allowlist / denylist | `DomainPolicy` (all 3 components) | `test_security_hardening.py`, `policy.test.js` |
| Port allowlist | `PortPolicy` (all 3 components) | `policy.test.js` |
| Private/reserved IP blocking | `is_blocked_ip()` / `isBlockedAddress()` | `policy.test.js`, `test_security_hardening.py` |
| DNS preflight | `DnsValidator` (API), `validateNavigationUrl` (worker), `resolveDestination` (proxy) | `test_security_hardening.py`, `policy.test.js` |
| DNS rebinding double-resolve | Proxy `resolveDestination()` | `proxy.test.js` |
| Redirect re-validation | Orchestrator `final_url` re-check | `test_security_hardening.py` |
| HTTPS→HTTP downgrade block | `page_security.js` `inspectRedirectChain()` | integration test |
| Prompt injection labeling | `PromptInjectionInspector` — `trust_label` always "untrusted" | `test_security_hardening.py` |
| Browser context isolation | `createIsolatedPage()` — fresh `BrowserContext` | `security_integration.test.js` |
| Worker→internet blocked | `--host-resolver-rules=MAP * ~NOTFOUND` | `security_integration.test.js` |
| Production fail-closed | factory guards + Settings validators | `test_security_hardening.py`, `test_api_auth.py` |
| Container restrictions | `docker-compose.yml` `cap_drop`, `no-new-privileges`, `read_only` | Docker build |

---

## 3. Missing Functionality

### 3.1 Critical

| # | Feature | Current state |
|---|---|---|
| C1 | Search provider client + `/v1/browser/search` endpoint | Entirely absent |
| C2 | Persistent browser sessions (create, reuse, cleanup) | Per-request only; `sessionId` is accepted and ignored |
| C3 | Text-only extraction endpoint | Raw HTML returned; no text-only path |
| C4 | `sessionId` propagation: API → worker | Header field exists in navigate.js (`x-agent-session`) but is not wired from the API schema or orchestrator |

### 3.2 High

| # | Feature | Current state |
|---|---|---|
| H1 | Browser actions: click, type, scroll, guarded form submit | No endpoints |
| H2 | Screenshot endpoint | No endpoint |
| H3 | Background session expiration timer | `closeExpiredContexts()` called only on `/health/ready`; no `setInterval` |
| H4 | Reverse-proxy-aware rate limiting | `request.client.host` used directly; no `X-Forwarded-For` handling |

### 3.3 Medium

| # | Feature | Current state |
|---|---|---|
| M1 | Distributed rate limiting | In-memory only; one process |
| M2 | Container seccomp profile for Chromium | Not documented or configured |
| M3 | `.env.example` restoration | File was deleted from tree |

---

## 4. Dependency Graph

```
C1 (Search) ────────────────────────────────► Phase 10 Demo 1
                                                    ▲
C3 (Text Extraction) ─── needs ──► C2 (Sessions) ─┤
                  └──────────────────────────────► Demo 3 (inject → detect)
H1 (Actions) ────── needs ──────► C2 (Sessions) ──► Demo 5 (form submit blocked)
H2 (Screenshot) ─── needs ──────► C2 (Sessions)
C4 (sessionId wire) ────────────► C2 (Sessions) prerequisite
H3 (bg expiry) ──────────────────► C2 (Sessions) prerequisite
H4 (IP header) ─────────────────► standalone, no deps
M1 (distributed RL) ────────────► H4 prerequisite for full correctness
```

**Critical path:**  
`H3 (bg expiry)` → `C4 (sessionId wire)` → `C2 (Sessions)` → `H1 (Actions)` → `H2 (Screenshot)`  
`C1 (Search)` is independent and can proceed in parallel with C2.  
`C3 (Text extraction)` is independent and can proceed in parallel with C2.  
`H4 (rate limit)` is independent and can proceed at any time.

---

## 5. File-Level Implementation Plan

### Feature C1 — Search Provider Client + Endpoint

**New files:**

| File | Component | Purpose |
|---|---|---|
| `api/app/clients/search_provider.py` | API | Abstract `SearchProvider` protocol + `BraveSearchClient` (or `SerpApiClient`) implementation; raises typed errors |
| `api/app/schemas/search.py` | API | `SearchRequest`, `SearchResult`, `SearchResponse` Pydantic models |
| `api/app/services/search_orchestrator.py` | API | `SearchOrchestrator`: validate query → call provider → validate every result URL → return |
| `worker/src/lib/search.js` | Worker | Search provider call wrapper (HTTP, timeout, error normalization) |
| `worker/src/routes/search.js` | Worker | `POST /v1/search` handler |

**Modified files:**

| File | What changes |
|---|---|
| `api/app/api/browser.py` | Add `POST /v1/browser/search` route |
| `api/app/clients/browser_worker.py` | Add `search()` method |
| `api/app/config.py` | Add `search_provider`, `search_api_key`, `search_max_results`, `search_timeout_seconds` settings |
| `worker/src/app.js` | Register `/v1/search` router |
| `worker/src/config.js` | Add `searchApiKey`, `searchProvider`, `searchMaxResults`, `searchTimeoutMs` |

**Security requirement:** Every URL in search results must pass `NetworkPreflight.validate()` + `PolicyEngine.authorize()` before being returned to the caller. A result URL pointing to a blocked domain must be removed from the result set, not cause a 400/403. The search query itself must be length-limited and sanitized (no injection into provider query string).

---

### Feature C2 — Persistent Browser Sessions

Sessions need two halves: a session store in the worker and an API surface.

**New files:**

| File | Component | Purpose |
|---|---|---|
| `worker/src/lib/session_store.js` | Worker | `SessionStore` class: `create(sessionId)`, `get(sessionId)`, `release(sessionId, contextInfo)`, `delete(sessionId)`, `closeExpired(now)`. Stores `{ context, page, lastUsedAt, createdAt, sessionId }`. Thread of ownership model: a session is checked-out (locked) during a request, released after. |
| `worker/src/routes/session.js` | Worker | `POST /v1/session` (create) and `DELETE /v1/session/:id` (close) |
| `api/app/schemas/session.py` | API | `SessionCreateRequest`, `SessionCreateResponse`, `SessionDeleteResponse` |
| `api/app/services/session_service.py` | API | `SessionService`: proxies session lifecycle to worker |

**Modified files:**

| File | What changes |
|---|---|
| `api/app/api/browser.py` | Add `POST /v1/browser/session` and `DELETE /v1/browser/session/{session_id}` routes |
| `api/app/clients/browser_worker.py` | Add `create_session()` and `delete_session()` methods |
| `worker/src/app.js` | Register `/v1/session` router |
| `worker/src/lib/browser.js` | `createIsolatedPage()` gains optional `reuseContext` parameter; when a `sessionId` matches an open session in the store, reuse the stored context and page rather than creating a new one |
| `worker/src/routes/navigate.js` | Pass `sessionId` header to the session store lookup; call `SessionStore.checkout(sessionId)` if provided, else create ephemeral context |
| `worker/src/config.js` | Add `sessionMaxIdleMs`, `sessionMaxAgeMs`, `sessionMaxCount` |

**Worker session store design:**

```
SessionStore {
  sessions: Map<sessionId, SessionEntry>
  SessionEntry: {
    contextId: string          // internal UUID
    context: BrowserContext
    page: Page                 // one page per session
    createdAt: number
    lastUsedAt: number
    checkedOut: boolean        // true while a request is using it
  }

  create(agentId, requestId) → sessionId
    - max session count enforced
    - calls createIsolatedPage() → stores context+page
    - returns new sessionId (UUID)

  checkout(sessionId, requestId) → SessionEntry | null
    - returns null if sessionId unknown
    - sets checkedOut = true; updates lastUsedAt
    - if already checked out → 409 Conflict

  release(sessionId)
    - sets checkedOut = false; updates lastUsedAt

  delete(sessionId)
    - calls context.close()
    - removes from map

  closeExpired(now)
    - closes sessions where lastUsedAt > sessionMaxIdleMs
    - closes sessions where createdAt > sessionMaxAgeMs
    - skips checked-out sessions (close after release)
}
```

**Security requirements:**
- Session IDs are server-generated UUIDs — never caller-supplied.
- A session is tied to the `agentId` (from `X-Agent-ID` header) that created it. Requests with a different `agentId` receive 403 on any session operation.
- Sessions use isolated `BrowserContext` — same guarantee as per-request contexts.
- Checked-out sessions cannot be closed by a concurrent request; `DELETE /v1/session/:id` during an active checkout is deferred until released.

---

### Feature C3 — Text Extraction Endpoint

**New files:**

| File | Component | Purpose |
|---|---|---|
| `worker/src/lib/extractor.js` | Worker | `extractText(page)` — calls `page.evaluate(() => document.body.innerText)` and strips multi-byte boundary artifacts; `extractMetadata(page)` — title, canonical URL, meta og:* tags |
| `worker/src/routes/extract.js` | Worker | `POST /v1/extract` — takes `{ session_id, selector? }`, returns `{ text, metadata, content_truncated }` |
| `api/app/schemas/extract.py` | API | `ExtractRequest`, `ExtractResponse` |
| `api/app/services/extract_service.py` | API | Calls worker `/v1/extract`; runs `ContentInspector.inspect()` on the plain text result |

**Modified files:**

| File | What changes |
|---|---|
| `api/app/api/browser.py` | Add `POST /v1/browser/extract` route |
| `api/app/clients/browser_worker.py` | Add `extract()` method |
| `worker/src/app.js` | Register `/v1/extract` router |

**Security requirement:** The `text` field in the response is plain text (no HTML). The `ContentInspector` must scan the plain text, not the raw HTML. `trust_label` must still be "untrusted". No `<script>` content reaches the caller.

---

### Feature C4 — `sessionId` Propagation

This is a prerequisite for C2 but can be delivered as a minimal plumbing change before the full session store is built.

**Modified files:**

| File | What changes |
|---|---|
| `api/app/schemas/browser.py` | Add optional `session_id: str | None = None` to `BrowserNavigateRequest` |
| `api/app/services/orchestrator.py` | Thread `session_id` through `BrowserWorkerClient.navigate()` call |
| `api/app/clients/browser_worker.py` | Include `X-Agent-Session` header in navigate request when `session_id` is provided |
| `worker/src/routes/navigate.js` | Already reads `req.get("x-agent-session")` and passes to `createIsolatedPage`; wire to session store checkout in C2 |

The worker already passes the header to `createIsolatedPage`. C4 is therefore minimal on the worker side; it only requires the API to forward the field.

---

### Feature H1 — Browser Actions

**New files:**

| File | Component | Purpose |
|---|---|---|
| `worker/src/lib/actions.js` | Worker | `performAction(page, action)`: `click({ selector, x, y })`, `type({ selector, text })`, `scroll({ direction, distance })`. All read a validated session page. |
| `worker/src/routes/action.js` | Worker | `POST /v1/action` — requires `session_id`; enforces action permission policy |
| `api/app/schemas/action.py` | API | `ActionRequest` (union type: `ClickAction | TypeAction | ScrollAction`), `ActionResponse` |
| `api/app/services/action_service.py` | API | Policy check → call worker `/v1/action` |

**Modified files:**

| File | What changes |
|---|---|
| `api/app/api/browser.py` | Add `POST /v1/browser/action` route |
| `api/app/clients/browser_worker.py` | Add `action()` method |
| `worker/src/app.js` | Register `/v1/action` router |
| `api/app/config.py` | Add `allowed_actions` setting (comma-separated; default `"click,type,scroll"`); `allow_form_submit: bool` (default `false`) |
| `worker/src/config.js` | Add `allowedActions`, `allowFormSubmit` |

**Security requirements:**
- All actions require an active session (C2 is a hard dependency).
- `type` action: text longer than `MAX_TYPE_LENGTH` (e.g. 4096 chars) is rejected. Content of typed text is logged (redacted for fields named `password`, `token`, `secret`).
- `click` action: clicking `<input type=file>`, `<a download>`, or any element that would trigger a file chooser or download is blocked.
- Form submission: `allow_form_submit` defaults to `false`. When false, `click` on `<button[type=submit]>` or `<input[type=submit]>` is rejected with 403.
- Actions operate on the session page only — no ability to navigate to a new URL via action (enforced by disabling `window.open` in `page_security.js`, already done).

---

### Feature H2 — Screenshot Endpoint

**New files:**

| File | Component | Purpose |
|---|---|---|
| `worker/src/routes/screenshot.js` | Worker | `POST /v1/screenshot` — requires `session_id`; calls `page.screenshot({ encoding: 'base64', type: 'webp', quality: 80 })`; returns base64 |
| `api/app/schemas/screenshot.py` | API | `ScreenshotRequest`, `ScreenshotResponse` |

**Modified files:**

| File | What changes |
|---|---|
| `api/app/api/browser.py` | Add `POST /v1/browser/screenshot` |
| `api/app/clients/browser_worker.py` | Add `screenshot()` method |
| `worker/src/app.js` | Register `/v1/screenshot` router |

**Security requirement:** Screenshots require an active session. Maximum image size enforced (`BROWSER_MAX_SCREENSHOT_BYTES`, default 4 MB). Screenshots are not stored server-side; returned inline as base64.

---

### Feature H3 — Background Session Expiration Timer

**Modified files:**

| File | What changes |
|---|---|
| `worker/src/index.js` | After `server.listen(...)`, add `setInterval(() => sessionStore.closeExpired(Date.now()), config.sessionCleanupIntervalMs)`. The interval ref is `unref()`'d so it does not block shutdown. During shutdown, clear the interval and call `sessionStore.closeExpired(Date.now())` once before `closeBrowser()`. |
| `worker/src/config.js` | Add `sessionCleanupIntervalMs` (default 30000 — 30 s) |

Note: `closeExpiredContexts()` in `browser.js` continues to be called from `/health/ready`. The timer and the health check both call the same cleanup function; this is safe because both check `checkedOut` before closing.

---

### Feature H4 — Reverse-Proxy-Aware Rate Limiting

**Modified files:**

| File | What changes |
|---|---|
| `api/app/middleware.py` | `RateLimitMiddleware.dispatch()`: extract client IP from `X-Forwarded-For` when `trusted_proxy_count > 0`. Take the `trusted_proxy_count`-th IP from the right of the `X-Forwarded-For` list. Fall back to `request.client.host` when the header is absent or the count is 0. |
| `api/app/config.py` | Add `rate_limit_trusted_proxy_count: int = Field(default=0, ge=0, le=10)` |

**Security note:** Never trust `X-Forwarded-For` unconditionally. The `trusted_proxy_count` approach means only the operator-configured number of rightmost hops are trusted. When `trusted_proxy_count=0` (default), behaviour is unchanged from today.

---

### Feature M1 — Distributed Rate Limiting (Optional / Medium Priority)

Not required for single-instance deployment. Design only:

- Replace `RateLimitMiddleware._hits` dict with a Redis `EVALSHA` Lua sliding-window counter.
- Add `redis_url: str = ""` to `Settings`.
- When `redis_url` is empty, fall back to the in-memory implementation (backwards compatible).
- Dependency: `redis>=5.0.0,<6.0.0` added to `requirements.txt` only when `redis_url` is set (lazy import).

This is not planned for the current implementation sprint. Document as a follow-up.

---

## 6. API Contracts to Introduce

All new routes share the same authentication and rate-limiting middleware as `/v1/browser/navigate`.

### 6.1 `POST /v1/browser/search`

```
Request:
  Authorization: Bearer <API_AUTH_TOKEN>
  X-Request-ID: <optional>
  Content-Type: application/json
  {
    "query": "string (1–500 chars)",
    "max_results": 5,           // optional, 1–20, default 5
    "safe_search": true         // optional, default true
  }

Response 200:
  {
    "request_id": "string",
    "query": "string",
    "results": [
      {
        "title": "string",
        "url": "string",        // pre-validated by NetworkPreflight
        "snippet": "string",
        "position": 1
      }
    ],
    "provider": "string",
    "elapsed_ms": 240,
    "filtered_count": 0         // results removed due to URL policy
  }

Errors:
  400  INVALID_QUERY      — empty query or exceeds length
  403  SEARCH_DOMAIN_BLOCKED — all results blocked by policy
  429  RATE_LIMIT_EXCEEDED
  502  SEARCH_PROVIDER_ERROR — provider returned error
  504  SEARCH_PROVIDER_TIMEOUT
```

### 6.2 `POST /v1/browser/session`

```
Request:
  Authorization: Bearer <API_AUTH_TOKEN>
  X-Agent-ID: <agent identifier, required>
  Content-Type: application/json
  {
    "idle_timeout_ms": 300000   // optional, 30000–1800000, default 300000
  }

Response 201:
  {
    "session_id": "uuid",
    "agent_id": "string",
    "created_at": "ISO8601",
    "idle_timeout_ms": 300000
  }

Errors:
  400  INVALID_AGENT_ID   — missing or invalid X-Agent-ID
  503  SESSION_LIMIT      — worker at max concurrent sessions
```

### 6.3 `DELETE /v1/browser/session/{session_id}`

```
Request:
  Authorization: Bearer <API_AUTH_TOKEN>
  X-Agent-ID: <must match session owner>

Response 200:
  { "session_id": "uuid", "closed": true }

Errors:
  403  SESSION_FORBIDDEN   — X-Agent-ID does not match session owner
  404  SESSION_NOT_FOUND
```

### 6.4 `POST /v1/browser/extract`

```
Request:
  Authorization: Bearer <API_AUTH_TOKEN>
  X-Request-ID: <optional>
  Content-Type: application/json
  {
    "session_id": "uuid",       // required — must be an active session
    "selector": "string"        // optional CSS selector, default: body
  }

Response 200:
  {
    "request_id": "string",
    "session_id": "uuid",
    "text": "string",           // plain text, no HTML
    "metadata": {
      "title": "string",
      "url": "string",
      "description": "string | null",
      "canonical_url": "string | null"
    },
    "content_truncated": false,
    "inspection": {             // same InspectionResult schema as navigate
      "inspector_name": "string",
      "findings": [...],
      "trust_label": "untrusted",
      "content_classification": "string",
      "highest_severity": "string",
      "summary": "string"
    }
  }

Errors:
  403  SESSION_FORBIDDEN / policy
  404  SESSION_NOT_FOUND
  409  SESSION_CHECKED_OUT
```

### 6.5 `POST /v1/browser/action`

```
Request:
  Authorization: Bearer <API_AUTH_TOKEN>
  X-Request-ID: <optional>
  Content-Type: application/json
  {
    "session_id": "uuid",
    "action": "click" | "type" | "scroll",
    "selector": "string",       // CSS selector (required for click, type)
    "text": "string",           // required for type (1–4096 chars)
    "direction": "up" | "down", // required for scroll
    "distance": 300             // pixels, scroll only (1–10000)
  }

Response 200:
  {
    "request_id": "string",
    "session_id": "uuid",
    "action": "click",
    "success": true,
    "elapsed_ms": 45
  }

Errors:
  400  INVALID_ACTION     — unknown action or missing required field
  403  ACTION_FORBIDDEN   — action not in allowed_actions, or form submit blocked
  403  SESSION_FORBIDDEN
  404  SESSION_NOT_FOUND  / ELEMENT_NOT_FOUND
  409  SESSION_CHECKED_OUT
  504  ACTION_TIMEOUT
```

### 6.6 `POST /v1/browser/screenshot`

```
Request:
  Authorization: Bearer <API_AUTH_TOKEN>
  X-Request-ID: <optional>
  Content-Type: application/json
  {
    "session_id": "uuid"
  }

Response 200:
  {
    "request_id": "string",
    "session_id": "uuid",
    "image": "<base64 WebP>",
    "format": "webp",
    "width": 1280,
    "height": 720,
    "size_bytes": 42000
  }

Errors:
  403  SESSION_FORBIDDEN
  404  SESSION_NOT_FOUND
  409  SESSION_CHECKED_OUT
  413  SCREENSHOT_TOO_LARGE  — exceeds BROWSER_MAX_SCREENSHOT_BYTES
```

---

## 7. Security Considerations for New Features

### 7.1 Search

**URL injection via search results.** Every URL in the provider response must be validated through `NetworkPreflight.validate()` before being returned to the caller. Results whose URL fails validation are silently dropped (counted in `filtered_count`). The caller never sees an unvalidated URL.

**Query length.** Queries over 500 characters are rejected before calling the provider. This prevents provider-side injection via extremely long queries.

**API key exposure.** `SEARCH_API_KEY` must never appear in logs or responses. The `Settings` validator should use `pydantic.SecretStr` for this field.

**Provider SSRF.** The search provider client is a separate `httpx.AsyncClient` that calls the provider's HTTPS API directly (not through the egress proxy — the provider is a trusted third party). The client must only connect to the configured provider hostname; no user-controlled URLs are passed to it.

### 7.2 Sessions

**Session ID guessing.** Session IDs are server-generated `uuid4()` values. They must not be derived from or influenced by caller-supplied values.

**Cross-agent leakage.** The `X-Agent-ID` header identifies the agent. Session operations require the `X-Agent-ID` to match the session creator. This check must be timing-safe (`hmac.compare_digest`).

**Session hijacking.** Since session IDs are opaque UUIDs, an attacker who obtains a session ID can use it. Mitigations: short idle timeout (default 5 min), mandatory `X-Agent-ID` cross-check, session IDs not logged at INFO level.

**Checkout deadlock.** If a worker request crashes without calling `SessionStore.release()`, the session stays checked out forever. Implement a `max_checkout_duration` (e.g. 120 s) after which a checked-out session is force-released.

**Cookie poisoning via persistent sessions.** Since a persistent session reuses a `BrowserContext`, cookies accumulated by one navigation survive to the next. This is intentional for multi-step workflows. However, it means the agent could navigate to a malicious site that sets cookies affecting subsequent navigations. Mitigations: domain allowlist prevents the malicious navigation from succeeding; each session's `BrowserContext` is completely isolated from all others.

### 7.3 Extraction

**Script content leakage.** `innerText` does not include `<script>` content. The extractor must use `document.body.innerText` rather than `innerHTML` or `textContent`. Verify that `innerText` excludes `display:none` content on the target platforms.

**Selector injection.** The caller-supplied `selector` CSS string must be validated (max length, no `:root`, no `*`-unbounded patterns) before calling `page.$eval(selector, ...)`. An invalid selector causes Puppeteer to throw; handle this as a 400.

### 7.4 Actions

**Click on dangerous elements.** Before calling `page.click(selector)`, evaluate the element type: file inputs and download links must be blocked. This check must run inside `page.evaluate()` before the click to avoid a TOCTOU race.

**Type into password fields.** Text typed into `<input type=password>` must be redacted in logs. Logging the `text` field verbatim is not acceptable.

**Form submission.** `allow_form_submit` defaults to `false`. When false, clicking any submit element returns 403 without executing the click in the browser. This is a policy decision at the action level, not in Puppeteer.

**Scroll distance.** Maximum scroll distance is enforced server-side (1–10000 px). Negative values are rejected.

### 7.5 Rate Limiting

**`X-Forwarded-For` forgery.** With `trusted_proxy_count=0` (default), the header is ignored entirely — no change from current behaviour. With `trusted_proxy_count=1`, only the rightmost hop in the header is trusted. An attacker who controls the leftmost entries in `X-Forwarded-For` cannot affect their rate limit bucket when only the rightmost entry is used.

---

## 8. Test Plan

### 8.1 Baseline (Confirmed, No External Services)

All commands run from the repository root.

| Suite | Command | Count | External service |
|---|---|---|---|
| API unit + security | `cd api && source .venv/bin/activate && python -m pytest tests/ --ignore=tests/integration -q` | **79 passed** | None |
| API integration (real worker + Chromium) | `cd api && source .venv/bin/activate && python -m pytest tests/integration/ -q` | **8 passed** | Puppeteer/Chromium |
| Proxy unit + integration | `cd proxy && node --test` | **53 passed** | None |
| Worker unit (auth, no browser) | `cd worker && node --test test/worker_auth.test.js` | **23 passed** | None |
| Worker security integration (real Chromium) | `cd worker && node --test test/security_integration.test.js` | **4 passed** | Chromium + proxy |
| **Total** | | **167 passed, 0 failed, 0 skipped** | |

### 8.2 Tests to Add — Feature C1 (Search)

**Unit tests** (`api/tests/test_search.py`):
- `test_search_validates_query_length` — query > 500 chars returns 400
- `test_search_validates_empty_query` — empty string returns 400
- `test_search_filters_blocked_result_urls` — result URL on blocked domain is dropped from results; `filtered_count` incremented
- `test_search_validates_private_ip_result_urls` — result URL resolving to private IP is dropped
- `test_search_returns_provider_timeout_as_504` — provider timeout returns 504 SEARCH_PROVIDER_TIMEOUT
- `test_search_returns_provider_error_as_502`
- `test_search_returns_normalized_results` — title, url, snippet, position all present
- `test_search_requires_auth` — no token returns 401

**Unit tests** (`api/tests/test_search_client.py`):
- `test_search_client_forwards_api_key_securely` — API key appears in Authorization header, not URL
- `test_search_client_timeout_raises_typed_error`
- `test_search_client_parses_provider_response`

**Worker tests** (`worker/test/search.test.js`):
- `test_search_route_validates_required_fields`
- `test_search_route_requires_auth_token`
- `test_search_route_returns_normalized_results`

### 8.3 Tests to Add — Feature C2 (Sessions)

**Unit tests** (`api/tests/test_sessions.py`):
- `test_create_session_returns_session_id_and_agent_id`
- `test_create_session_requires_agent_id_header`
- `test_create_session_requires_auth`
- `test_delete_session_succeeds_for_owner`
- `test_delete_session_forbidden_for_non_owner` — different X-Agent-ID returns 403
- `test_delete_session_not_found` — unknown session_id returns 404
- `test_navigate_with_session_id_forwards_header`
- `test_navigate_with_unknown_session_id_returns_404`

**Worker unit tests** (`worker/test/session_store.test.js`):
- `test_create_session_generates_uuid`
- `test_checkout_returns_null_for_unknown_id`
- `test_checkout_sets_checked_out_true`
- `test_checkout_returns_conflict_when_already_checked_out`
- `test_release_sets_checked_out_false`
- `test_delete_closes_browser_context`
- `test_close_expired_removes_idle_sessions`
- `test_close_expired_skips_checked_out_sessions`
- `test_max_checkout_duration_force_releases_stuck_session`

**Worker integration tests** (`worker/test/session_integration.test.js` — real Chromium):
- `test_session_reuses_browser_context_across_requests`
- `test_session_cookies_persist_across_navigate_calls`
- `test_different_sessions_have_isolated_state` — Demo 4 scenario
- `test_session_expires_after_idle_timeout`

### 8.4 Tests to Add — Feature C3 (Extraction)

**Unit tests** (`api/tests/test_extract.py`):
- `test_extract_returns_plain_text_not_html`
- `test_extract_strips_script_content`
- `test_extract_runs_prompt_injection_inspection_on_text`
- `test_extract_trust_label_always_untrusted`
- `test_extract_requires_session_id`
- `test_extract_rejects_invalid_selector` — selector > max length returns 400
- `test_extract_returns_metadata`

**Adversarial** (`api/tests/test_extract_adversarial.py`):
- `test_extract_with_prompt_injection_in_visible_text` — text contains "Ignore previous instructions"; `inspection.findings` has PI-001, `trust_label == "untrusted"` — **Demo 3 scenario**
- `test_extract_does_not_include_script_tag_content`
- `test_extract_does_not_include_hidden_element_content`

### 8.5 Tests to Add — Feature H1 (Actions)

**Unit tests** (`api/tests/test_actions.py`):
- `test_click_action_succeeds_on_allowed_element`
- `test_click_action_blocked_on_file_input` — returns 403 ACTION_FORBIDDEN
- `test_click_action_blocked_on_submit_when_form_submit_disabled` — Demo 5 scenario
- `test_click_action_allowed_on_submit_when_form_submit_enabled`
- `test_type_action_within_length_limit`
- `test_type_action_exceeds_length_limit` — returns 400
- `test_scroll_action_valid`
- `test_scroll_action_exceeds_max_distance` — returns 400
- `test_action_requires_session_id`
- `test_action_requires_auth`
- `test_unknown_action_returns_400`

**Worker unit tests** (`worker/test/actions.test.js`):
- `test_click_validates_element_type_before_clicking`
- `test_type_redacts_password_field_in_logs`
- `test_scroll_enforces_max_distance`

### 8.6 Tests to Add — Feature H2 (Screenshot)

**Unit tests** (`api/tests/test_screenshot.py`):
- `test_screenshot_returns_base64_webp`
- `test_screenshot_requires_session_id`
- `test_screenshot_requires_auth`
- `test_screenshot_exceeds_max_size_returns_413`

### 8.7 Tests to Add — Feature H3 (Background Expiry)

**Worker unit tests** (`worker/test/session_expiry.test.js`):
- `test_background_timer_calls_close_expired`
- `test_timer_is_unreffed` — shutdown does not hang on timer
- `test_expiry_timer_cleared_on_shutdown`

### 8.8 Tests to Add — Feature H4 (Rate Limit IP Header)

**Unit tests** (`api/tests/test_rate_limit_proxy.py`):
- `test_rate_limit_uses_client_host_when_trusted_proxy_count_zero` — default, X-Forwarded-For ignored
- `test_rate_limit_uses_rightmost_forwarded_ip_when_count_one`
- `test_rate_limit_cannot_be_bypassed_by_forged_x_forwarded_for_when_count_zero`
- `test_rate_limit_isolates_different_real_ips`

### 8.9 Adversarial / End-to-End Tests (Phase 10)

These require the full Docker stack running. Planned as a separate test suite (`tests/e2e/`).

| Test | Scenario | Validates |
|---|---|---|
| `test_e2e_safe_search_and_navigate` | Search for a company, visit top result | Demo 1 |
| `test_e2e_malicious_redirect_blocked` | Navigate URL that 302s to 169.254.169.254 | Demo 2 |
| `test_e2e_prompt_injection_detected` | Page contains "Ignore previous instructions…"; verify findings | Demo 3 |
| `test_e2e_cross_agent_session_isolation` | Agent A and Agent B verify no state leakage | Demo 4 |
| `test_e2e_form_submit_blocked` | Agent clicks submit button with default policy | Demo 5 |

---

## 9. Implementation Sequence

The sequence below is ordered by: (1) dependency (blocked by what), (2) risk (security-sensitive first), (3) value (demo coverage).

### Phase A — Session foundation (prerequisite for H1, H2, C4)

```
Step A1: Feature H3 — Background expiry timer
  Files: worker/src/index.js, worker/src/config.js
  Tests: worker/test/session_expiry.test.js
  Risk: Low — additive change to index.js; does not touch browser.js security code

Step A2: Feature C4 — sessionId propagation (API → worker header)
  Files: api/app/schemas/browser.py, api/app/services/orchestrator.py,
         api/app/clients/browser_worker.py
  Tests: api/tests/test_api_navigate.py (extend existing)
  Risk: Low — adds an optional header; existing tests continue to pass

Step A3: Feature C2 — Persistent sessions (worker store + API endpoints)
  Files (new): worker/src/lib/session_store.js,
               worker/src/routes/session.js,
               api/app/schemas/session.py,
               api/app/services/session_service.py
  Files (modified): worker/src/app.js, worker/src/lib/browser.js,
                    worker/src/routes/navigate.js,
                    api/app/api/browser.py,
                    api/app/clients/browser_worker.py,
                    api/app/config.py
  Tests: api/tests/test_sessions.py, worker/test/session_store.test.js,
         worker/test/session_integration.test.js
  Risk: Medium — browser.js modification; session checkout/release must be correct
```

### Phase B — Content features (independent of actions)

```
Step B1: Feature C3 — Text extraction endpoint
  Files (new): worker/src/lib/extractor.js,
               worker/src/routes/extract.js,
               api/app/schemas/extract.py,
               api/app/services/extract_service.py
  Files (modified): worker/src/app.js,
                    api/app/api/browser.py,
                    api/app/clients/browser_worker.py
  Tests: api/tests/test_extract.py, api/tests/test_extract_adversarial.py
  Risk: Low — new route; does not modify existing security code
  Depends: C2 (sessions required for extract endpoint)
```

### Phase C — Search (independent, parallel with Phase B)

```
Step C1: Feature C1 — Search provider client + endpoint
  Files (new): api/app/clients/search_provider.py,
               api/app/schemas/search.py,
               api/app/services/search_orchestrator.py,
               worker/src/lib/search.js,
               worker/src/routes/search.js
  Files (modified): api/app/api/browser.py,
                    api/app/clients/browser_worker.py,
                    api/app/config.py,
                    worker/src/app.js,
                    worker/src/config.js
  Tests: api/tests/test_search.py, api/tests/test_search_client.py,
         worker/test/search.test.js
  Risk: Low security risk — calls external HTTPS API; result URLs validated
  Depends: None (search does not need sessions)
  Requires external: Search provider API key (SEARCH_API_KEY env var)
  First provider: Brave Search API (free tier, no SDK dependency)
    Fallback: DuckDuckGo Instant Answer (no key required for basic use)
```

### Phase D — Actions and Screenshot

```
Step D1: Feature H1 — Browser actions
  Files (new): worker/src/lib/actions.js,
               worker/src/routes/action.js,
               api/app/schemas/action.py,
               api/app/services/action_service.py
  Files (modified): worker/src/app.js,
                    api/app/api/browser.py,
                    api/app/clients/browser_worker.py,
                    api/app/config.py,
                    worker/src/config.js
  Tests: api/tests/test_actions.py, worker/test/actions.test.js
  Risk: Medium — element type check must be correct to prevent dangerous clicks
  Depends: C2 (sessions)

Step D2: Feature H2 — Screenshot
  Files (new): worker/src/routes/screenshot.js,
               api/app/schemas/screenshot.py
  Files (modified): worker/src/app.js,
                    api/app/api/browser.py,
                    api/app/clients/browser_worker.py,
                    worker/src/config.js
  Tests: api/tests/test_screenshot.py
  Risk: Low — screenshot is read-only
  Depends: C2 (sessions)
```

### Phase E — Rate limiting hardening

```
Step E1: Feature H4 — Trusted proxy rate limiting
  Files (modified): api/app/middleware.py, api/app/config.py
  Tests: api/tests/test_rate_limit_proxy.py
  Risk: Low — additive to existing rate limiter; default (count=0) is unchanged
  Depends: None

Step E2 (optional): Feature M1 — Redis rate limiting
  Defer until multi-replica deployment is required
```

### Phase F — End-to-end tests

```
Step F1: E2E test suite
  Files (new): api/tests/e2e/conftest.py, api/tests/e2e/test_demos.py
  Requires: Full docker-compose stack
  Validates: All 5 demo scenarios
```

---

## 10. Acceptance Criteria

### C1 — Search

- [ ] `POST /v1/browser/search` returns structured results with title, URL, snippet, position
- [ ] Every result URL has passed `NetworkPreflight.validate()` + `PolicyEngine.authorize()`
- [ ] Result URLs pointing to blocked domains are silently dropped; `filtered_count` reflects this
- [ ] Query over 500 characters returns 400 `INVALID_QUERY`
- [ ] Provider timeout returns 504 `SEARCH_PROVIDER_TIMEOUT`
- [ ] Provider error returns 502 `SEARCH_PROVIDER_ERROR`
- [ ] `SEARCH_API_KEY` does not appear in any log line
- [ ] All 167 existing tests still pass

### C2 — Sessions

- [ ] `POST /v1/browser/session` returns a server-generated UUID session ID
- [ ] `DELETE /v1/browser/session/{session_id}` closes the context and returns 200
- [ ] `DELETE` with wrong `X-Agent-ID` returns 403
- [ ] Navigating with a valid `session_id` reuses the same `BrowserContext`
- [ ] Navigating with an unknown `session_id` returns 404
- [ ] Two sessions have isolated cookies and localStorage (Demo 4 scenario verified)
- [ ] Sessions expire after `sessionIdleTimeoutMs` of inactivity
- [ ] Background timer runs independently of health check calls
- [ ] Session checkout during an active request prevents concurrent use (returns 409)
- [ ] All 167 existing tests still pass

### C3 — Text extraction

- [ ] `POST /v1/browser/extract` returns plain text, not raw HTML
- [ ] `<script>` tag content does not appear in `text` field
- [ ] `display:none` content does not appear in `text` field
- [ ] `trust_label` is "untrusted" in all cases
- [ ] Prompt injection in visible page text is detected (PI-001 finding returned)
- [ ] Invalid selector returns 400
- [ ] Missing `session_id` returns 422
- [ ] All 167 existing tests still pass

### C4 — sessionId propagation

- [ ] `BrowserNavigateRequest` accepts optional `session_id`
- [ ] When `session_id` is provided, the `X-Agent-Session` header is forwarded to the worker
- [ ] When `session_id` is absent, behaviour is identical to current (no header sent)
- [ ] All 167 existing tests still pass

### H1 — Actions

- [ ] `click` succeeds on a normal element and returns `success: true`
- [ ] `click` on a file input returns 403 `ACTION_FORBIDDEN`
- [ ] `click` on a submit element with `allow_form_submit=false` returns 403 (Demo 5)
- [ ] `type` into a field succeeds within length limits
- [ ] `type` over 4096 chars returns 400
- [ ] `type` into a password field is not logged verbatim
- [ ] `scroll` within distance limits succeeds
- [ ] `scroll` over 10000 px returns 400
- [ ] Missing `session_id` returns 422
- [ ] All 167 existing tests still pass

### H2 — Screenshot

- [ ] Returns base64-encoded WebP image
- [ ] Includes `width`, `height`, `size_bytes` in response
- [ ] Image exceeding `BROWSER_MAX_SCREENSHOT_BYTES` returns 413
- [ ] Missing `session_id` returns 422
- [ ] All 167 existing tests still pass

### H3 — Background expiry

- [ ] `setInterval` for `closeExpiredContexts` is established in `index.js` at startup
- [ ] Timer interval is `sessionCleanupIntervalMs` (default 30 s, configurable)
- [ ] Timer is `unref()`'d — worker shuts down cleanly without waiting for timer
- [ ] Shutdown clears the interval and runs one final cleanup
- [ ] Idle sessions are closed within 2× the cleanup interval
- [ ] All 167 existing tests still pass

### H4 — Trusted proxy rate limiting

- [ ] With `RATE_LIMIT_TRUSTED_PROXY_COUNT=0` (default), behaviour is identical to today
- [ ] With `RATE_LIMIT_TRUSTED_PROXY_COUNT=1`, the rightmost `X-Forwarded-For` IP is used for bucketing
- [ ] Two different real IPs are rate-limited independently when count=1
- [ ] Forged `X-Forwarded-For` does not affect rate limiting when count=0
- [ ] All 167 existing tests still pass

---

## Appendix: Search Provider Selection

**Brave Search API** is recommended as the first provider:
- RESTful JSON API at `https://api.search.brave.com/res/v1/web/search`
- Free tier: 2000 queries/month
- Requires `X-Subscription-Token` header (configured as `SEARCH_API_KEY`)
- Returns `title`, `url`, `description` per result
- No external SDK required — plain `httpx.AsyncClient` call

**DuckDuckGo Instant Answer API** as a no-key fallback:
- `https://api.duckduckgo.com/?q=...&format=json`
- Limited result set (no full web search, only Instant Answers and related topics)
- Suitable for integration testing without an API key

The `SearchProvider` interface will be designed so that either backend can be wired up via `SEARCH_PROVIDER=brave|duckduckgo` env var, with `brave` as the production default.

---

## Appendix: Files Not to Touch

The following files implement security controls that are complete and tested. No implementation phase should modify them:

- `api/app/security/` (all 8 files)
- `api/app/interfaces/` (both files)  
- `api/app/mocks/` (both files — development-only, not to be replaced with stubs)
- `proxy/src/lib/policy.js` and `proxy/src/lib/proxy.js`
- `proxy/src/index.js`
- `worker/src/lib/page_security.js`
- `worker/src/lib/url_guard.js`
- `worker/src/lib/egress.js`
- `worker/src/lib/domain_policy.js`
- `docker-compose.yml` (except adding seccomp profile)
- All three `Dockerfile`s (except adding seccomp)
- All existing test files
