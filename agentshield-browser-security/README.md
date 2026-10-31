# AgentShield Browser Security

Standalone foundation for AgentShield Module 1: browser and web search security. It is designed to run independently now and to be merged into the main AgentShield repository later without restructuring.

This repository implements the control plane, the browser execution boundary, and an enforcing egress proxy. The default `.env.example` selects the development mock policy and inspection backends for local startup; production startup rejects mock backends. Do not treat mock results as production security controls.

## Architecture

```
AI agent / caller
       |
       v
FastAPI security API  (security orchestration, policy, inspection)
       |
       v  internal HTTP
Node.js browser worker  (Puppeteer execution)
       |
       v
isolated Chromium process
```

Responsibilities:

- **FastAPI service** owns request validation, policy authorization, worker orchestration, content inspection, request IDs, and structured logging.
- **Node.js worker** owns browser lifecycle, persistent sessions, constrained navigation, bounded text extraction, guarded browser actions, and bounded screenshots. It never exposes arbitrary JavaScript execution or raw browser internals.
- **Worker isolation** is enforced by deployment topology. The Compose worker has no published host port and is attached only to a private worker network shared with the API. It can make outbound browsing connections but cannot receive public inbound traffic.
- **Replaceable interfaces** are defined in `api/app/interfaces/`. The current `mock` implementations live in `api/app/mocks/`.
- **No arbitrary JavaScript execution endpoint** is implemented.
- **Persistent sessions are owner-bound.** The API forwards the authenticated agent identity as `X-Agent-ID`; the worker refuses a session unless the supplied identity matches the registered owner. A session ID alone is never authorization.
- **Extracted page content is always untrusted.** The worker returns plain text and structured records only, never raw HTML, and the API attaches an explicit `trust_label: "untrusted"`.
- **Search results are pre-validated.** Every provider result URL passes the same URL, DNS, and policy checks as navigation. Blocked destinations are dropped and counted, not returned as navigable results.
- **Browser actions are constrained.** Supported actions are `click`, `type`, `scroll`, `page_state`, and guarded `submit_form`. They reuse the caller's persistent session and existing URL/network policy. There is no arbitrary JavaScript, unrestricted CDP, or caller-controlled output path.
- **Screenshots stay in memory.** The worker enforces viewport, full-page, clip, dimension, byte, rate, concurrency, timeout, and per-session limits. The API returns PNG bytes with fixed headers and never discloses a filesystem path.
- **No host browser profile, cookies, or credentials** are used. Puppeteer launches Chromium with an ephemeral profile.
- **Chromium's sandbox is not disabled.** The worker does not pass `--no-sandbox` or `--disable-setuid-sandbox`.

## Project layout

```
agentshield-browser-security/
├── api/
│   ├── app/
│   │   ├── api/              HTTP routes
│   │   ├── clients/          Worker client and search provider clients
│   │   ├── interfaces/       PolicyEngine and ContentInspector contracts
│   │   ├── mocks/            Development-only implementations
│   │   ├── schemas/          Pydantic request/response models
│   │   ├── services/         Navigation, session, extraction, action, screenshot, and search orchestration
│   │   ├── config.py         Environment-driven settings
│   │   ├── logging_config.py Structured JSON logging and request ID context
│   │   ├── middleware.py     Request ID propagation
│   │   └── main.py           FastAPI application factory
│   ├── tests/
│   │   ├── e2e/              Real API + worker + proxy + Chromium demos and load test
│   │   ├── integration/      Real worker + FastAPI communication tests
│   │   └── *.py              Unit tests
│   ├── Dockerfile
│   ├── pyproject.toml
│   ├── requirements.txt
│   └── requirements-dev.txt
├── worker/
│   ├── src/
│   │   ├── lib/              Browser lifecycle, sessions, extraction, actions, screenshots, URL guard, logging
│   │   ├── routes/           Health, session, navigation, extraction, action, and screenshot routes
│   │   ├── app.js            Express application factory
│   │   ├── config.js         Environment-driven settings
│   │   └── index.js          Worker entrypoint and graceful shutdown
│   ├── Dockerfile
│   └── package.json
├── proxy/
│   ├── src/
│   │   ├── lib/              Egress policy, DNS pinning, HTTP/CONNECT/WebSocket proxy
│   │   ├── app.js            Proxy application factory
│   │   ├── config.js         Environment-driven settings
│   │   └── index.js          Proxy and health-server entrypoint
│   ├── Dockerfile
│   └── package.json
├── docs/                     Architecture, security, deployment, test, and acceptance reports
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

## Prerequisites

- Python 3.11 or newer
- Node.js 22 or newer
- npm
- Docker and Docker Compose for containerized startup
- Chromium/Chrome available to Puppeteer, either downloaded by Puppeteer during `npm install` or supplied through `BROWSER_EXECUTABLE_PATH`

## Local setup

```bash
cd agentshield-browser-security
cp .env.example .env

python3 -m venv .venv
source .venv/bin/activate
pip install -r api/requirements-dev.txt

cd worker
npm install
npm run browser:install
cd ..
```

`npm run browser:install` ensures Puppeteer has a Chromium build even when npm install scripts are blocked by a local npm security policy. If `BROWSER_EXECUTABLE_PATH` points to an existing Chrome/Chromium binary, this step can be skipped.

Start the worker in one terminal:

```bash
cd worker
npm start
```

Start the API in another terminal:

```bash
source .venv/bin/activate
cd api
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --no-proxy-headers
```

The API is available at `http://127.0.0.1:8000`. The worker is reachable at `http://127.0.0.1:8080` by default for local development. In Compose, the worker is not published to the host.

### Local health checks

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/health/ready
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/health/ready
```

The API readiness endpoint calls the worker readiness endpoint. The worker readiness endpoint launches Chromium on first use, so the first call can take longer.

### Example navigation request

```bash
curl -X POST http://127.0.0.1:8000/v1/browser/navigate \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: demo-request-1' \
  -d '{"url":"https://example.com/","wait_until":"load","timeout_ms":15000}'
```

The API forwards the request ID to the worker. Responses include `X-Request-ID`.

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

The API is published on `127.0.0.1:8000` only. The browser worker has no host port mapping. Compose uses:

- `edge`: API access network.
- `worker-net`: private API-to-worker network. The worker has no published port on this network.

The worker container runs as a non-root user. Chromium's sandbox remains enabled. Depending on the host and container runtime, the sandbox may require a compatible seccomp or user-namespace configuration. Do not use `--no-sandbox` as a workaround.

## Configuration

All service URLs and runtime settings come from environment variables. See `.env.example`.

| Variable | Service | Default | Purpose |
| --- | --- | --- | --- |
| `ENVIRONMENT` | API | `development` | Deployment environment label |
| `LOG_LEVEL` | Both | `INFO` / `info` | Log verbosity |
| `API_HOST` | API | `0.0.0.0` | API bind host |
| `API_PORT` | API | `8000` | API bind port and Compose host port |
| `API_AUTH_TOKEN` | API | empty | Optional Bearer token for API callers; required in production |
| `BROWSER_WORKER_URL` | API | `http://127.0.0.1:8080` | Internal worker base URL |
| `BROWSER_WORKER_TIMEOUT_SECONDS` | API | `30` | Worker request timeout |
| `BROWSER_WORKER_HEALTH_TIMEOUT_SECONDS` | API | `3` | Worker health timeout |
| `WORKER_AUTH_TOKEN` | Both | empty | Optional shared bearer token for API-to-worker requests |
| `POLICY_BACKEND` | API | `mock` | Policy engine selection |
| `INSPECTION_BACKEND` | API | `mock` | Content inspector selection |
| `ALLOWED_DOMAINS` | Both | empty | Comma-separated hostname allowlist; wildcards use `*.example.com` |
| `BLOCKED_DOMAINS` | Both | empty | Comma-separated hostname denylist |
| `DEFAULT_DOMAIN_POLICY` | Both | `deny` | `allow` or `deny` when a hostname matches no list entry |
| `ALLOWED_PORTS` | Both | `80,443` | Allowed destination ports or ranges |
| `MAX_REDIRECTS` | Worker | `5` | Maximum redirect chain length |
| `BLOCK_HTTPS_DOWNGRADE` | Worker | `true` | Block HTTPS-to-HTTP redirects |
| `ALLOW_PRIVATE_NETWORKS` | API | `false` | Allow private/reserved DNS targets |
| `DNS_PREFLIGHT_ENABLED` | API | `true` | Resolve and validate DNS before navigation |
| `WORKER_HOST` | Worker | `127.0.0.1` | Worker bind host (Compose overrides to `0.0.0.0`) |
| `WORKER_PORT` | Worker | `8080` | Worker bind port |
| `BROWSER_HEADLESS` | Worker | `true` | Headless Chromium |
| `BROWSER_EXECUTABLE_PATH` | Worker | Puppeteer-managed | Chromium executable |
| `BROWSER_NAVIGATION_TIMEOUT_MS` | Worker | `20000` | Default navigation timeout |
| `BROWSER_MAX_CONTENT_BYTES` | Worker | `524288` | Returned HTML size limit |
| `BROWSER_ALLOW_PRIVATE_NETWORKS` | Worker | `false` | Allow private/reserved targets |
| `BROWSER_SESSION_IDLE_TIMEOUT_MS` | Worker | `300000` | Reap a released session after this idle period |
| `BROWSER_SESSION_MAX_LEASE_MS` | Worker | `120000` | Ceiling on one request's hold on a session context |
| `BROWSER_SESSION_MAX_AGE_MS` | Worker | `900000` | Absolute session lifetime |
| `BROWSER_MAX_SESSIONS` | Worker | `5` | Concurrent persistent sessions |
| `BROWSER_MAX_EXTRACTION_TEXT_BYTES` | Worker | `131072` | Maximum extracted plain-text bytes |
| `BROWSER_MAX_EXTRACTION_LINKS` | Worker | `100` | Maximum extracted link records |
| `BROWSER_ACTION_TIMEOUT_MS` | Worker | `10000` | Default browser action timeout (`1000`-`60000`) |
| `BROWSER_ACTION_MAX_TYPE_BYTES` | Worker | `4000` | Maximum UTF-8 bytes per type action |
| `BROWSER_ACTION_MAX_SCROLL_PX` | Worker | `5000` | Maximum scroll distance per action |
| `BROWSER_ACTION_MAX_TEXT_BYTES` | Worker | `8192` | Maximum page text returned with an action |
| `BROWSER_SCREENSHOT_TIMEOUT_MS` | Worker | `10000` | Default screenshot timeout (`1000`-`60000`) |
| `BROWSER_SCREENSHOT_MAX_WIDTH` | Worker | `2048` | Maximum screenshot width |
| `BROWSER_SCREENSHOT_MAX_HEIGHT` | Worker | `2048` | Maximum viewport/clip screenshot height |
| `BROWSER_SCREENSHOT_MAX_FULL_PAGE_HEIGHT` | Worker | `12000` | Maximum full-page screenshot height |
| `BROWSER_SCREENSHOT_MAX_BYTES` | Worker | `5242880` | Maximum PNG size (5 MiB) |
| `BROWSER_SCREENSHOT_MAX_CONCURRENT` | Worker | `2` | Maximum concurrent screenshot captures |
| `BROWSER_SCREENSHOT_RATE_LIMIT_PER_MINUTE` | Worker | `20` | Per-session screenshot rate limit |
| `BROWSER_SCREENSHOT_MAX_PER_SESSION` | Worker | `100` | Lifetime screenshots per session |
| `RATE_LIMIT_ENABLED` | API | `true` | Enable per-identity and per-category limits |
| `RATE_LIMIT_BACKEND` | API | `memory` | `memory` (dev/test only) or `redis` (required in production) |
| `RATE_LIMIT_PER_MINUTE` | API | `60` | API-wide per-identity limit |
| `RATE_LIMIT_NAVIGATION_PER_MINUTE` | API | `30` | Navigation category limit |
| `RATE_LIMIT_SEARCH_PER_MINUTE` | API | `20` | Search category limit |
| `RATE_LIMIT_SESSION_CREATE_PER_MINUTE` | API | `10` | Session creation category limit |
| `RATE_LIMIT_ACTION_PER_MINUTE` | API | `60` | Action category limit |
| `RATE_LIMIT_EXTRACT_PER_MINUTE` | API | `30` | Extraction category limit |
| `RATE_LIMIT_SCREENSHOT_PER_MINUTE` | API | `20` | Screenshot category limit |
| `RATE_LIMIT_WINDOW_SECONDS` | API | `60` | Fixed-window duration |
| `RATE_LIMIT_FAIL_OPEN` | API | `false` | Keep `false`; `true` is an explicit degraded mode |
| `RATE_LIMIT_TRUSTED_PROXIES` | API | empty | IPs/CIDRs whose `X-Forwarded-For` is trusted |
| `RATE_LIMIT_TRUSTED_PROXY_MAX_HOPS` | API | `10` | Maximum forwarded-chain length |
| `REDIS_URL` | API | empty | Required when `RATE_LIMIT_BACKEND=redis` |
| `REDIS_TIMEOUT_SECONDS` | API | `1.0` | Redis connect/read timeout |
| `SEARCH_PROVIDER` | API | `brave` | `brave` or `duckduckgo` (limited keyless fallback) |
| `SEARCH_API_KEY` | API | empty | Brave API key; required when provider is `brave` |
| `SEARCH_TIMEOUT_MS` | API | `5000` | Search provider request timeout |
| `SEARCH_MAX_RESULTS` | API | `5` | Operator ceiling on returned search results |
| `EGRESS_PROXY_URL` | Worker | empty | Enforcing outbound proxy used by Chromium |
| `PROXY_AUTH_TOKEN` | Worker | empty | Password for the outbound proxy |
| `REQUIRE_EGRESS_PROXY` | Worker | `false` | Fail navigation when no egress proxy is configured |

`BROWSER_ALLOW_PRIVATE_NETWORKS` defaults to `false`. It exists for local integration testing against a loopback fixture server. Keep it `false` outside isolated development.

The example `.env` allows only `example.com` so the documented navigation demo works with the default-deny domain policy. Add the domains your agents may reach to `ALLOWED_DOMAINS`; use `BLOCKED_DOMAINS` for explicit denials.

## HTTP API

### FastAPI service

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Alias for `/health/ready` |
| `GET` | `/health/live` | API process liveness |
| `GET` | `/health/ready` | API readiness, including worker readiness |
| `POST` | `/v1/browser/navigate` | Authorize, navigate, and inspect a page |
| `POST` | `/v1/browser/session` | Create an owner-bound persistent browser session |
| `GET` | `/v1/browser/session/{session_id}` | Read session lifecycle metadata |
| `DELETE` | `/v1/browser/session/{session_id}` | Close a session |
| `POST` | `/v1/browser/extract` | Extract bounded text from an owned session |
| `POST` | `/v1/browser/action` | Run a guarded action inside an owned session |
| `POST` | `/v1/browser/screenshot` | Capture a bounded PNG from an owned session |
| `POST` | `/v1/browser/search` | Run a provider search and pre-validate result URLs |

Session, extraction, action, and screenshot endpoints require `X-Agent-ID`. The identity is not a credential; API authentication still applies when `API_AUTH_TOKEN` is configured.

`POST /v1/browser/navigate` body:

```json
{
  "url": "https://example.com/",
  "wait_until": "networkidle2",
  "timeout_ms": 15000
}
```

`wait_until` accepts `load`, `domcontentloaded`, `networkidle0`, or `networkidle2`. `timeout_ms` must be between `1000` and `60000`.

Example persistent session flow:

```bash
curl -X POST http://127.0.0.1:8000/v1/browser/session \
  -H 'X-Agent-ID: agent-42'

curl -X POST http://127.0.0.1:8000/v1/browser/navigate \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-ID: agent-42' \
  -d '{"url":"https://example.com/","session_id":"<session_id>"}'

curl -X POST http://127.0.0.1:8000/v1/browser/extract \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-ID: agent-42' \
  -d '{"session_id":"<session_id>"}'

curl -X DELETE http://127.0.0.1:8000/v1/browser/session/<session_id> \
  -H 'X-Agent-ID: agent-42'
```

Example browser action and screenshot:

```bash
curl -X POST http://127.0.0.1:8000/v1/browser/action \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-ID: agent-42' \
  -d '{"session_id":"<session_id>","action":"click","target":{"role":"button","name":"Continue"}}'

curl -X POST http://127.0.0.1:8000/v1/browser/action \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-ID: agent-42' \
  -d '{"session_id":"<session_id>","action":"type","target":{"selector":"#search"},"text":"query"}'

curl -X POST http://127.0.0.1:8000/v1/browser/screenshot \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-ID: agent-42' \
  -d '{"session_id":"<session_id>","full_page":true}' \
  -o screenshot.png
```

Actions return structured results with the resulting URL, title, bounded page text, security warnings, and an explicit `trust_label: "untrusted"`. Click targets may use a plain CSS selector or an accessible role/name; ambiguous matches require an index. Submit controls, file inputs, and download links are rejected by `click`; use guarded `submit_form`, which validates the form destination through the existing URL policy and requires `confirm: true` for cross-origin, sensitive-field, destructive, or payment submissions. Typed values are never logged and are redacted or withheld from returned page text.

Screenshots support viewport, full-page, and clipped captures. The response is `image/png` with `Cache-Control: no-store`, fixed `Content-Disposition`, and `X-Screenshot-*` metadata headers. Images are held in memory only; no filesystem path is returned.

Example search request:

```bash
curl -X POST http://127.0.0.1:8000/v1/browser/search \
  -H 'Content-Type: application/json' \
  -d '{"query":"example domain","max_results":5}'
```

Search responses carry `provider_mode` (`full` or `limited_fallback`), an explicit `provider_notice` when the DuckDuckGo fallback is used, and `trust_label: "untrusted"` on every result. A result whose URL fails preflight or policy is omitted and counted in `filtered_count`.

### Browser worker

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Alias for `/health/live` |
| `GET` | `/health/live` | Worker process liveness |
| `GET` | `/health/ready` | Worker and Chromium readiness |
| `POST` | `/v1/session` | Create an owner-bound session |
| `GET` | `/v1/session/{session_id}` | Read session status |
| `DELETE` | `/v1/session/{session_id}` | Close a session |
| `POST` | `/v1/navigate` | Constrained navigation for the API |
| `POST` | `/v1/extract` | Bounded text extraction from an owned session |
| `POST` | `/v1/action` | Guarded browser action inside an owned session |
| `POST` | `/v1/screenshot` | Bounded PNG screenshot from an owned session |

The worker endpoints are intended only for the API. They are not AI-agent-facing APIs and must not be exposed publicly.

## Security boundaries and current behavior

Implemented now:

- URL scheme allowlist (`http` and `https` only).
- Rejection of embedded URL credentials and ambiguous numeric hostnames.
- URL, port, and domain allowlist/denylist policy in both the API and worker.
- DNS resolution and rejection of loopback, private, link-local, multicast, reserved, and similar address ranges by default.
- Worker request interception that validates subresources and redirect destinations.
- Redirect limits, redirect-loop detection, and HTTPS-downgrade blocking.
- Optional enforcing egress proxy support (`EGRESS_PROXY_URL`).
- Optional Bearer-token authentication for API callers (`API_AUTH_TOKEN`) and between the API and worker (`WORKER_AUTH_TOKEN`).
- Fixed-window rate limiting by API identity, category, agent identity, session, and client IP.
- Trusted-proxy-aware client identity: `X-Forwarded-For` is ignored unless the direct peer is configured in `RATE_LIMIT_TRUSTED_PROXIES`; malformed trusted chains return `400 INVALID_FORWARDED_FOR`.
- Atomic Redis rate-limit counters shared across API replicas; production startup rejects the process-local memory backend.
- Uvicorn's own proxy-header handling is disabled (`--no-proxy-headers`) so the application's trusted-proxy logic is authoritative.
- Request ID validation and propagation across both services.
- JSON structured logging in both services.
- Ephemeral Chromium profile; no host profile or cookie reuse.
- Popup suppression and service-worker bypass for navigated pages.
- Content size limit before returning HTML to the API.
- Replaceable policy and inspection interfaces with explicit mock implementations.
- Worker has no published port in Compose.
- API binds to loopback by default in Compose.
- Worker error isolation and API error mapping (`403`, `409`, `429`, `502`, `503`, `504`).
- Persistent browser sessions with server-generated IDs, owner binding, idle/max-age expiry, and lease protection.
- Bounded text extraction with hidden-content exclusion and explicit untrusted labeling.
- Real search providers: Brave full web search and a clearly labeled DuckDuckGo Instant Answer fallback.
- Search result URL preflight and policy validation before results are returned.
- Search API keys held in `SecretStr` and excluded from logs and responses.
- Guarded browser actions that reuse persistent sessions, URL policy, and owner checks.
- Guarded form submission with destination validation, cross-origin/sensitive-field/destructive/payment confirmation, and audit logging.
- In-memory screenshots with strict dimension, byte, rate, concurrency, timeout, and per-session limits.

Not implemented in this foundation:

- Production policy authorization.
- Production content sanitization or detection.
- JavaScript execution API.
- PDF or file download endpoints.
- Full tenant isolation beyond owner-bound sessions and API authentication.
- Persistent audit storage.
- Secret management beyond environment variables.
- Enforced network-level destination pinning; use the egress proxy for production.

Known limitations:

- The mock policy engine allows any HTTP(S) URL without credentials. It is not an authorization control.
- The mock content inspector uses simple pattern matching and is not a security scanner.
- Worker-side URL and DNS validation still occur before Chromium connects, so DNS rebinding is not fully mitigated. Set `REQUIRE_EGRESS_PROXY=true` and supply an enforcing proxy for production.
- Worker request interception is a defense-in-depth control, not a substitute for network-level egress enforcement.
- The worker shares one Chromium process across contexts. Each request gets an isolated browser context; persistent sessions reuse only their own context. Full multi-tenant isolation remains a deployment concern.
- Navigation responses include untrusted HTML for API inspection; extraction responses include untrusted plain text and structured records. Callers must treat all page-derived content as untrusted.
- The DuckDuckGo fallback is not full web search and must not be presented as such.
- The Compose Chromium sandbox configuration may need host-specific seccomp or user-namespace support. Sandbox disabling is intentionally not provided.
- Docker was not available in the environment used to build this foundation, so Compose startup is documented but not executed there.
- The default `RATE_LIMIT_BACKEND=memory` is process-local and development-only. Production requires Redis and a reachable `REDIS_URL`.
- E2E DEMO 1 and DEMO 5 depend on external services (`example.com` and DuckDuckGo); they skip or fail if the network is unavailable.
- The API must be started with `--no-proxy-headers` (or with an equivalent ASGI-server setting). Otherwise uvicorn trusts `X-Forwarded-For` from `127.0.0.1` by default and bypasses the application's trusted-proxy control.

## Tests

Run all tests from `api/`:

```bash
source ../.venv/bin/activate
python -m pytest
```

Run only unit tests:

```bash
python -m pytest -m "not integration"
```

Run the full end-to-end demo suite (requires `worker/node_modules`, Chromium, network access to `example.com` and DuckDuckGo, and `redis-server` for DEMO 9):

```bash
RUN_E2E=1 python -m pytest tests/e2e -v -s
```

The E2E suite starts real API, worker, proxy, Redis, and Chromium processes. It is skipped by default so ordinary unit and integration runs stay fast and offline-safe.

Run integration tests (requires `worker/node_modules` and a working Chromium):

```bash
python -m pytest -m integration
```

Integration tests start the real Node.js worker, launch Chromium, start a local HTTP fixture, and exercise the FastAPI client through real session, navigation, extraction, action, and screenshot requests. They set `BROWSER_ALLOW_PRIVATE_NETWORKS=true` for the loopback fixture only.

Run worker tests (real Chromium):

```bash
cd worker
npm test
```

Run proxy tests:

```bash
cd proxy
npm test
```

## Documentation

- `docs/ARCHITECTURE.md`
- `docs/API_REFERENCE.md`
- `docs/SECURITY_MATRIX.md`
- `docs/THREAT_MODEL.md`
- `docs/DEPLOYMENT_GUIDE.md`
- `docs/ENVIRONMENT_REFERENCE.md`
- `docs/DEMO_GUIDE.md`
- `docs/TEST_REPORT.md`
- `docs/PERFORMANCE_REPORT.md`
- `docs/FINAL_VERIFICATION.md`
- `docs/FINAL_ACCEPTANCE_REPORT.md`

## Merging into the main AgentShield repository

The project is intentionally split into `api/` and `worker/` with explicit contracts:

- `api/app/interfaces/policy.py`
- `api/app/interfaces/inspection.py`
- `api/app/clients/browser_worker.py`

To merge, keep the API routes and worker client as the browser-security boundary, replace the mock factories with production implementations, and preserve the deployment rule that the worker has no public ingress.
