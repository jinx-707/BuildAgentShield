# API Reference

**Date:** 2026-10-31  
**Base URL (local):** `http://127.0.0.1:8000`

## Authentication

When `API_AUTH_TOKEN` is set, every non-health endpoint requires:

```http
Authorization: Bearer <API_AUTH_TOKEN>
```

Health endpoints are always exempt. In production, startup fails if `API_AUTH_TOKEN` is empty.

Session, extraction, action, and screenshot endpoints also require a logical agent identity:

```http
X-Agent-ID: agent-42
```

`X-Agent-ID` is not a credential. It binds a session to an owner; API authentication remains the caller authentication control.

## Common headers

| Header | Direction | Meaning |
| --- | --- | --- |
| `Authorization` | Request | Optional/required API bearer token |
| `X-Agent-ID` | Request | Logical agent identity for session ownership |
| `X-Request-ID` | Request/response | Correlation ID; validated or generated |
| `X-Agent-Session` | Internal | Worker session identity header |
| `Retry-After` | Response | Seconds until a rate-limit retry |
| `X-RateLimit-Limit` | Response | Limit for the rejected scope |
| `X-RateLimit-Remaining` | Response | `0` on rejection |
| `X-RateLimit-Scope` | Response | `tenant`, `session`, or `ip` |

## Error envelope

API validation and worker policy errors use:

```json
{
  "detail": {
    "code": "DOMAIN_BLOCKED",
    "message": "destination is not permitted"
  }
}
```

Rate-limit errors use:

```json
{
  "error": "rate_limit_exceeded",
  "code": "RATE_LIMIT_EXCEEDED",
  "message": "too many requests for this scope",
  "scope": "ip",
  "category": "navigation",
  "limit": 30,
  "retry_after": 42
}
```

Rate-limit backend failures use:

```json
{
  "error": "rate_limit_backend_unavailable",
  "code": "RATE_LIMIT_BACKEND_UNAVAILABLE",
  "message": "the rate-limit backend is unavailable"
}
```

FastAPI request-body validation failures return `422` with FastAPI's standard `detail` list.

## Health

### `GET /health/live`

Process liveness. Does not check dependencies.

```json
{
  "status": "ok",
  "service": "agentshield-browser-security-api",
  "version": "0.1.0",
  "checks": { "process": "ok" }
}
```

### `GET /health/ready` and `GET /health`

Checks worker readiness and, when `REQUIRE_EGRESS_PROXY=true` and `EGRESS_PROXY_HEALTH_URL` is set, proxy readiness.

Returns `200` when ready, `503` with `status: "degraded"` when a dependency is unavailable or degraded.

## `POST /v1/browser/navigate`

Validates, authorizes, navigates, re-validates the final URL, and inspects returned content.

Request:

```json
{
  "url": "https://example.com/",
  "wait_until": "networkidle2",
  "timeout_ms": 15000,
  "session_id": "optional-session-id"
}
```

| Field | Type | Rules |
| --- | --- | --- |
| `url` | absolute HTTP(S) URL | Required; credentials, ambiguous IP forms, disallowed schemes/ports/domains, private/metadata destinations rejected |
| `wait_until` | enum | `load`, `domcontentloaded`, `networkidle0`, `networkidle2` |
| `timeout_ms` | integer | `1000`–`60000`; default `15000` |
| `session_id` | string | Optional; `^[A-Za-z0-9._:-]{1,128}$`; logical identity only |

Response:

```json
{
  "request_id": "req-1",
  "requested_url": "https://example.com/",
  "final_url": "https://example.com/",
  "status_code": 200,
  "title": "Example Domain",
  "content": "Example Domain ...",
  "content_truncated": false,
  "elapsed_ms": 812,
  "redirect_count": 0,
  "blocked_request_count": 0,
  "blocked_target_count": 0,
  "policy": {
    "allowed": true,
    "policy_name": "egress-policy",
    "reason": "allowed"
  },
  "inspection": {
    "inspector_name": "prompt-injection",
    "findings": [],
    "trust_label": "untrusted",
    "content_classification": "untrusted",
    "highest_severity": "none",
    "summary": ""
  }
}
```

`content` is bounded plain text or sanitized content, never raw HTML returned for caller execution. Treat all page-derived content as untrusted.

Common errors: `400 INVALID_URL`, `403 DOMAIN_BLOCKED`, `403 PRIVATE_IP_BLOCKED`, `403 PORT_NOT_ALLOWED`, `403 policy_denied`, `403 REDIRECT_DESTINATION_BLOCKED`, `403 HTTPS_DOWNGRADE_BLOCKED`, `502 browser_worker_failure`, `504 NAVIGATION_TIMEOUT`, `504 browser_worker_timeout`.

## `POST /v1/browser/session`

Requires `X-Agent-ID`. Creates an owner-bound persistent browser context.

Request (optional):

```json
{
  "idle_timeout_ms": 300000,
  "max_age_ms": 900000
}
```

The worker enforces its configured ceilings. A value the worker considers too large is refused with a precise `400`; values can shorten but not extend operator limits.

Response `201`:

```json
{
  "session_id": "9f1b...",
  "state": "idle",
  "status": "idle",
  "created_at": "2026-10-31T00:00:00Z",
  "last_used_at": "2026-10-31T00:00:00Z",
  "expires_at": "2026-10-31T00:15:00Z",
  "idle_timeout_ms": 300000,
  "max_age_ms": 900000,
  "active_requests": 0,
  "closing_requested": false,
  "current_url": null
}
```

## `GET /v1/browser/session/{session_id}`

Requires `X-Agent-ID`. Returns session lifecycle metadata for the owner. Unknown ID: `404`. Another owner: `403 SESSION_FORBIDDEN`.

## `DELETE /v1/browser/session/{session_id}`

Requires `X-Agent-ID`. Requests close. A close during an in-flight request is deferred until the request finishes.

```json
{
  "session_id": "9f1b...",
  "closed": true,
  "closing": false,
  "request_id": "req-2"
}
```

## `POST /v1/browser/extract`

Requires `X-Agent-ID`. Extracts bounded text, metadata, links, lists, and tables from an owned session.

Request:

```json
{ "session_id": "9f1b..." }
```

Response includes:

- `metadata`: title, URL, description, canonical URL, site name, language.
- `content`: text, byte length, truncation flag.
- `links`, `lists`, `tables`: bounded structured records.
- `truncation`: per-collection flags.
- `security`: `trust_label: "untrusted"`, hidden-content exclusion metadata, warnings.
- `inspection`: configured content inspection result.

Hidden content is excluded from extracted text. Limits are controlled by `BROWSER_MAX_EXTRACTION_TEXT_BYTES` and `BROWSER_MAX_EXTRACTION_LINKS`.

## `POST /v1/browser/action`

Requires `X-Agent-ID`. Runs a guarded action inside an owned session.

Request:

```json
{
  "session_id": "9f1b...",
  "action": "click",
  "target": { "role": "button", "name": "Continue" },
  "timeout_ms": 10000
}
```

Supported actions:

| Action | Required fields | Notes |
| --- | --- | --- |
| `click` | `target` | Plain CSS selector or accessible role/name; submit controls, file inputs, and download links are refused |
| `type` | `target`, non-empty `text` | UTF-8 byte limit; typed values are redacted/withheld from returned page text |
| `scroll` | `direction`, `amount` or `distance` | Maximum `5000` px |
| `page_state` | none | No target allowed |
| `submit_form` | `target` | Destination revalidated; cross-origin, sensitive-field, destructive, and payment submissions require `confirm: true` |

Targets:

```json
{ "selector": "#search", "index": 0 }
```

or:

```json
{ "role": "button", "name": "Continue", "index": 0 }
```

Only plain CSS selectors are supported. Puppeteer-specific selectors such as `aria/`, `text/`, `xpath/`, `pierce/`, `>>>`, and `::-p-` are rejected.

Response includes `success`, resulting URL/title, bounded page text, `security.trust_label: "untrusted"`, warnings, inspection, and redirect/block counters.

Common errors: `400 INVALID_TARGET`, `400 INPUT_LENGTH_EXCEEDED`, `403 FORM_METHOD_NOT_ALLOWED`, `403 SESSION_FORBIDDEN`, `404 SESSION_NOT_FOUND`, `409 SESSION_CHECKED_OUT`, `504 ACTION_TIMEOUT`.

## `POST /v1/browser/screenshot`

Requires `X-Agent-ID`. Captures a bounded PNG from an owned session.

Request:

```json
{
  "session_id": "9f1b...",
  "full_page": false,
  "clip": { "x": 0, "y": 0, "width": 800, "height": 600 },
  "timeout_ms": 10000
}
```

`full_page` and `clip` cannot be combined. Limits:

- Width/height: `BROWSER_SCREENSHOT_MAX_WIDTH`, `BROWSER_SCREENSHOT_MAX_HEIGHT`
- Full-page height: `BROWSER_SCREENSHOT_MAX_FULL_PAGE_HEIGHT`
- Bytes: `BROWSER_SCREENSHOT_MAX_BYTES`
- Concurrency: `BROWSER_SCREENSHOT_MAX_CONCURRENT`
- Per-session rate and lifetime count: `BROWSER_SCREENSHOT_RATE_LIMIT_PER_MINUTE`, `BROWSER_SCREENSHOT_MAX_PER_SESSION`
- Timeout: `BROWSER_SCREENSHOT_TIMEOUT_MS`

Success response: `200 image/png` with:

```http
Cache-Control: no-store, max-age=0
Content-Disposition: inline; filename="screenshot.png"
X-Content-Type-Options: nosniff
X-Screenshot-Width: 1280
X-Screenshot-Height: 720
X-Screenshot-Bytes: 12345
X-Screenshot-Full-Page: false
X-Screenshot-Elapsed-Ms: 120
```

Images are held in memory. No filesystem path is exposed.

Common errors: `400 INVALID_REQUEST`, `413 SCREENSHOT_DIMENSIONS_EXCEEDED`, `413 SCREENSHOT_TOO_LARGE`, `429` screenshot rate limit, `504 SCREENSHOT_TIMEOUT`.

## `POST /v1/browser/search`

Runs a provider search and pre-validates every result URL.

Request:

```json
{
  "query": "Python programming language",
  "max_results": 5,
  "safe_search": true
}
```

| Field | Type | Rules |
| --- | --- | --- |
| `query` | string | 1–500 characters, non-blank |
| `max_results` | integer or null | 1–20; also capped by `SEARCH_MAX_RESULTS` |
| `safe_search` | boolean | Default `true`; provider mapping is best-effort |

Response:

```json
{
  "request_id": "req-3",
  "query": "Python programming language",
  "provider": "duckduckgo-instant-answer",
  "provider_mode": "limited_fallback",
  "provider_notice": "DuckDuckGo Instant Answer is a limited keyless fallback...",
  "results": [
    {
      "title": "Python",
      "url": "https://www.python.org/",
      "snippet": "...",
      "source": "www.python.org",
      "position": 1,
      "retrieved_at": "2026-10-31T00:00:00Z",
      "trust_label": "untrusted"
    }
  ],
  "filtered_count": 0,
  "results_truncated": false,
  "elapsed_ms": 230,
  "trust_label": "untrusted",
  "inspection": { "trust_label": "untrusted" }
}
```

Provider modes:

- `full`: Brave web search; requires `SEARCH_API_KEY`.
- `limited_fallback`: DuckDuckGo Instant Answer; explicitly not full web search.

Blocked result URLs are omitted and counted. Provider titles and snippets are untrusted.

Common errors: `503 SEARCH_NOT_CONFIGURED`, `504 SEARCH_PROVIDER_TIMEOUT`, `503 SEARCH_PROVIDER_UNAVAILABLE`, `502 SEARCH_PROVIDER_AUTH_FAILED`, `502 SEARCH_PROVIDER_INVALID_RESPONSE`, `429 SEARCH_PROVIDER_RATE_LIMITED`.

## Worker internal API

The worker is not caller-facing. It exposes `/health`, `/health/live`, `/health/ready`, `/v1/session`, `/v1/navigate`, `/v1/extract`, `/v1/action`, and `/v1/screenshot` for the API only. It must have no public ingress. When `WORKER_AUTH_TOKEN` is set, all non-health worker endpoints require a bearer token; production startup fails if it is empty.

## Proxy internal API

The proxy is not caller-facing. It listens for HTTP proxy, `CONNECT`, and WebSocket upgrade traffic, plus a health server. It enforces domain, port, IP, DNS, and authentication policy. `PROXY_AUTH_TOKEN` is optional in configuration but strongly recommended in any shared environment.

## Rate-limit scopes

Limits apply per fixed window (`RATE_LIMIT_WINDOW_SECONDS`) to:

1. API-wide (`RATE_LIMIT_PER_MINUTE`)
2. `navigation`
3. `search`
4. `session_create`
5. `action`
6. `extract`
7. `screenshot`

Each category can be checked across tenant, session, and IP dimensions. The first exceeded dimension returns `429` with its scope. Counters are shared through Redis in production.
