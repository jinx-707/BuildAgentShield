# Environment Reference

**Date:** 2026-10-31  
**Source of truth:** `api/app/config.py`, `worker/src/config.js`, `proxy/src/config.js`, `.env.example`, `docker-compose.yml`.

## General

| Variable | Service | Default | Notes |
| --- | --- | --- | --- |
| `ENVIRONMENT` | API, worker | `development` | Use `production` to enable production guards |
| `NODE_ENV` | Worker | `development` | Worker falls back to `ENVIRONMENT` |
| `LOG_LEVEL` | API, worker, proxy | `INFO` / `info` | Standard level or pino level |
| `API_HOST` | API | `0.0.0.0` | API bind host |
| `API_PORT` | API | `8000` | API bind port / Compose host port |
| `WORKER_HOST` | Worker | `127.0.0.1` | Compose overrides to `0.0.0.0` |
| `WORKER_PORT` | Worker | `8080` | Worker bind port |
| `PROXY_HOST` | Proxy | `0.0.0.0` | Proxy bind host |
| `PROXY_PORT` | Proxy | `3128` | Proxy port |
| `PROXY_HEALTH_HOST` | Proxy | `0.0.0.0` | Health bind host |
| `PROXY_HEALTH_PORT` | Proxy | `9090` | Health port |

## API authentication and worker connection

| Variable | Default | Notes |
| --- | --- | --- |
| `API_AUTH_TOKEN` | empty | Optional in development; required in production |
| `WORKER_AUTH_TOKEN` | empty | Optional in development; worker production startup fails if empty |
| `BROWSER_WORKER_URL` | `http://127.0.0.1:8080` | Internal worker base URL |
| `BROWSER_WORKER_TIMEOUT_SECONDS` | `30` | Worker request timeout |
| `BROWSER_WORKER_HEALTH_TIMEOUT_SECONDS` | `3` | Worker health timeout |

## Policy and inspection

| Variable | Default | Notes |
| --- | --- | --- |
| `POLICY_BACKEND` | `mock` | `mock` (dev only) or `egress-policy` |
| `INSPECTION_BACKEND` | `mock` | `mock` (dev only) or `prompt-injection` |
| `ALLOWED_DOMAINS` | empty | Comma-separated; `*.example.com` wildcard |
| `BLOCKED_DOMAINS` | empty | Comma-separated; takes precedence |
| `DEFAULT_DOMAIN_POLICY` | `deny` | `allow` or `deny` |
| `ALLOWED_PORTS` | `80,443` | Comma-separated ports/ranges |
| `MAX_REDIRECTS` | `5` | `0`–`20` |
| `BLOCK_HTTPS_DOWNGRADE` | `true` | Worker redirect control |
| `ALLOW_PRIVATE_NETWORKS` | `false` | API; never `true` in production |
| `DNS_PREFLIGHT_ENABLED` | `true` | API DNS preflight |

## Rate limiting

| Variable | Default | Notes |
| --- | --- | --- |
| `RATE_LIMIT_ENABLED` | `true` | Must be `true` in production |
| `RATE_LIMIT_BACKEND` | `memory` | `memory` (dev/test only) or `redis` |
| `RATE_LIMIT_PER_MINUTE` | `60` | API-wide per-identity limit |
| `RATE_LIMIT_BURST` | `10` | Defined but currently unused; reserved |
| `RATE_LIMIT_NAVIGATION_PER_MINUTE` | `30` | Navigation category |
| `RATE_LIMIT_SEARCH_PER_MINUTE` | `20` | Search category |
| `RATE_LIMIT_SESSION_CREATE_PER_MINUTE` | `10` | Session creation category |
| `RATE_LIMIT_ACTION_PER_MINUTE` | `60` | Action category |
| `RATE_LIMIT_EXTRACT_PER_MINUTE` | `30` | Extraction category |
| `RATE_LIMIT_SCREENSHOT_PER_MINUTE` | `20` | Screenshot category |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Fixed-window duration (`10`–`3600`) |
| `RATE_LIMIT_FAIL_OPEN` | `false` | Keep `false`; `true` is an explicit degraded mode |
| `RATE_LIMIT_TRUSTED_PROXIES` | empty | Comma-separated IPs/CIDRs; empty ignores XFF |
| `RATE_LIMIT_TRUSTED_PROXY_MAX_HOPS` | `10` | `1`–`20` |
| `REDIS_URL` | empty | Required when backend is `redis` |
| `REDIS_TIMEOUT_SECONDS` | `1.0` | Redis connect/read timeout |

Production rules:

- `RATE_LIMIT_ENABLED=true`
- `RATE_LIMIT_BACKEND=redis`
- `REDIS_URL` must be an absolute `redis://` or `rediss://` URL
- `RATE_LIMIT_FAIL_OPEN=false` unless a documented degraded mode is approved
- Run the ASGI server with `--no-proxy-headers`

## Search

| Variable | Default | Notes |
| --- | --- | --- |
| `SEARCH_PROVIDER` | `brave` | `brave` or `duckduckgo` |
| `SEARCH_API_KEY` | empty | Required for Brave; held as `SecretStr` |
| `SEARCH_TIMEOUT_MS` | `5000` | `500`–`30000` |
| `SEARCH_MAX_RESULTS` | `5` | `1`–`20` operator ceiling |

## Worker browser and URL policy

| Variable | Default | Notes |
| --- | --- | --- |
| `BROWSER_HEADLESS` | `true` | Headless Chromium |
| `BROWSER_EXECUTABLE_PATH` | empty | Empty means Puppeteer-managed Chromium |
| `BROWSER_NAVIGATION_TIMEOUT_MS` | `20000` | Default navigation timeout |
| `BROWSER_MAX_CONTENT_BYTES` | `524288` | Returned content limit |
| `BROWSER_ALLOW_PRIVATE_NETWORKS` | `false` | Never `true` in production |
| `ALLOWED_DOMAINS` / `BLOCKED_DOMAINS` | empty | Worker policy; should match API/proxy |
| `DEFAULT_DOMAIN_POLICY` | `deny` | Worker policy |
| `ALLOWED_PORTS` | `80,443` | Worker policy |
| `MAX_REDIRECTS` | `5` | Worker redirect limit |
| `BLOCK_HTTPS_DOWNGRADE` | `true` | Worker redirect control |
| `BROWSER_ALLOW_WEBRTC` | `false` | `true` causes launch failure |
| `BROWSER_MAX_CONCURRENT_CONTEXTS` | `10` | Concurrent browser contexts |

## Worker sessions

| Variable | Default | Notes |
| --- | --- | --- |
| `BROWSER_SESSION_IDLE_TIMEOUT_MS` | `300000` | Released session idle lifetime |
| `BROWSER_SESSION_CLEANUP_INTERVAL_MS` | `30000` | Sweep cadence; clamped to idle timeout |
| `BROWSER_SESSION_MAX_LEASE_MS` | `120000` | Stranded-lease ceiling; floored above max request timeout |
| `BROWSER_SESSION_MAX_AGE_MS` | `900000` | Absolute session lifetime |
| `BROWSER_MAX_SESSIONS` | `5` | Concurrent persistent sessions |

## Worker extraction, actions, screenshots

| Variable | Default | Notes |
| --- | --- | --- |
| `BROWSER_MAX_EXTRACTION_TEXT_BYTES` | `131072` | Plain-text byte limit |
| `BROWSER_MAX_EXTRACTION_LINKS` | `100` | Link record limit |
| `BROWSER_ACTION_TIMEOUT_MS` | `10000` | Default action timeout |
| `BROWSER_ACTION_MAX_TYPE_BYTES` | `4000` | Per type action |
| `BROWSER_ACTION_MAX_SCROLL_PX` | `5000` | Per scroll action |
| `BROWSER_ACTION_MAX_TEXT_BYTES` | `8192` | Page text returned with action |
| `BROWSER_SCREENSHOT_TIMEOUT_MS` | `10000` | Default screenshot timeout |
| `BROWSER_SCREENSHOT_MAX_WIDTH` | `2048` | Maximum width |
| `BROWSER_SCREENSHOT_MAX_HEIGHT` | `2048` | Maximum viewport/clip height |
| `BROWSER_SCREENSHOT_MAX_FULL_PAGE_HEIGHT` | `12000` | Maximum full-page height |
| `BROWSER_SCREENSHOT_MAX_BYTES` | `5242880` | 5 MiB |
| `BROWSER_SCREENSHOT_MAX_CONCURRENT` | `2` | Concurrent captures |
| `BROWSER_SCREENSHOT_RATE_LIMIT_PER_MINUTE` | `20` | Per-session rate |
| `BROWSER_SCREENSHOT_MAX_PER_SESSION` | `100` | Lifetime per session |

## Egress proxy

| Variable | Default | Notes |
| --- | --- | --- |
| `EGRESS_PROXY_URL` | empty | Worker proxy URL |
| `EGRESS_PROXY_HEALTH_URL` | empty | Worker/API proxy health URL |
| `EGRESS_PROXY_HEALTH_TIMEOUT_MS` | `3000` | Health timeout |
| `EGRESS_PROXY_HEALTH_CACHE_MS` | `5000` | Health cache |
| `PROXY_AUTH_TOKEN` | empty | Worker and proxy shared Basic-auth password |
| `REQUIRE_EGRESS_PROXY` | `true` | Fail closed without a proxy |
| `PROXY_ALLOWED_DOMAINS` | empty | Falls back to `ALLOWED_DOMAINS` |
| `PROXY_BLOCKED_DOMAINS` | empty | Falls back to `BLOCKED_DOMAINS` |
| `PROXY_DEFAULT_DOMAIN_POLICY` | `deny` | Falls back to `DEFAULT_DOMAIN_POLICY` |
| `PROXY_ALLOWED_PORTS` | `80,443` | Falls back to `ALLOWED_PORTS` |
| `PROXY_ALLOW_PRIVATE_NETWORKS` | `false` | Never `true` in production |
| `PROXY_DNS_TIMEOUT_MS` | `5000` | DNS resolution timeout |
| `PROXY_CONNECT_TIMEOUT_MS` | `10000` | Upstream connect timeout |
| `PROXY_DNS_SERVER` | `1.1.1.1` (Compose) | Compose DNS setting only |
| `PROXY_LOG_LEVEL` | `LOG_LEVEL` | Proxy-specific log level |

## Production minimum

At minimum, a shared or production-like deployment must set:

```dotenv
ENVIRONMENT=production
API_AUTH_TOKEN=<strong secret>
WORKER_AUTH_TOKEN=<strong secret>
PROXY_AUTH_TOKEN=<strong secret>
POLICY_BACKEND=egress-policy
INSPECTION_BACKEND=prompt-injection
ALLOWED_DOMAINS=<explicit allowlist>
DEFAULT_DOMAIN_POLICY=deny
ALLOW_PRIVATE_NETWORKS=false
BROWSER_ALLOW_PRIVATE_NETWORKS=false
PROXY_ALLOW_PRIVATE_NETWORKS=false
REQUIRE_EGRESS_PROXY=true
RATE_LIMIT_ENABLED=true
RATE_LIMIT_BACKEND=redis
REDIS_URL=<redis or rediss URL>
RATE_LIMIT_FAIL_OPEN=false
RATE_LIMIT_TRUSTED_PROXIES=<reverse proxy CIDRs>
```

Do not deploy with `POLICY_BACKEND=mock`, `INSPECTION_BACKEND=mock`, `RATE_LIMIT_BACKEND=memory`, an empty API token, an empty worker token, or private networking enabled.
