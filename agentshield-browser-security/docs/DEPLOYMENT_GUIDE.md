# Deployment Guide

**Date:** 2026-10-31

## Supported deployment shapes

| Shape | Status | Notes |
| --- | --- | --- |
| Local development | Supported | Real Chromium, mock policy/inspection by default |
| Controlled demo / isolated staging | Supported with conditions | Real backends, auth, Redis, proxy, network isolation |
| Production with untrusted agents | Not yet accepted | See `FINAL_ACCEPTANCE_REPORT.md` |

## Prerequisites

- Python 3.11+
- Node.js 22+
- npm
- Chromium/Chrome for Puppeteer, or `BROWSER_EXECUTABLE_PATH`
- Redis for production rate limiting
- Docker and Docker Compose for containerized deployment
- TLS-terminating reverse proxy or load balancer for production

## Local development

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

Start the worker:

```bash
cd worker
npm start
```

Start the API with proxy headers disabled:

```bash
source .venv/bin/activate
cd api
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --no-proxy-headers
```

The `--no-proxy-headers` flag is mandatory when using the application's trusted-proxy logic. Uvicorn otherwise trusts `X-Forwarded-For` from `127.0.0.1` by default and rewrites `request.client.host` before `RateLimitMiddleware` sees it.

Start Redis if testing DEMO 9 or production-like rate limiting:

```bash
redis-server --port 6379
```

## Docker Compose

```bash
cp .env.example .env
# Edit .env before starting. Do not use mock backends for a shared deployment.
docker compose up --build
```

The API is published on `127.0.0.1:${API_PORT:-8000}`. The worker and proxy have no host ports. `worker-net` is internal; only the proxy is attached to `egress-net`.

Docker Compose was **not runtime-tested** in the environment used to build this repository. Review the Compose file and validate container startup, Chromium sandbox compatibility, and network isolation in your target environment.

## Production configuration checklist

### Authentication and secrets

- Set a strong `API_AUTH_TOKEN`.
- Set a strong `WORKER_AUTH_TOKEN`; production worker startup fails without it.
- Set a strong `PROXY_AUTH_TOKEN` and configure the worker with the same value.
- Use a secret manager rather than a committed `.env`.
- Rotate tokens on a defined schedule and after any suspected exposure.
- Never log tokens, search keys, cookies, or typed values.

### Rate limiting

- Set `RATE_LIMIT_ENABLED=true`.
- Set `RATE_LIMIT_BACKEND=redis`.
- Set `REDIS_URL=redis://...` or `rediss://...`.
- Keep `RATE_LIMIT_FAIL_OPEN=false`.
- Set `RATE_LIMIT_TRUSTED_PROXIES` to only the reverse proxies that append the observed client address.
- Keep `RATE_LIMIT_TRUSTED_PROXY_MAX_HOPS` small.
- Do not rely on `RATE_LIMIT_BURST`; it is defined but currently unused.

Example:

```dotenv
ENVIRONMENT=production
API_AUTH_TOKEN=<secret>
WORKER_AUTH_TOKEN=<secret>
PROXY_AUTH_TOKEN=<secret>
RATE_LIMIT_ENABLED=true
RATE_LIMIT_BACKEND=redis
REDIS_URL=rediss://redis.example.internal:6379/0
RATE_LIMIT_FAIL_OPEN=false
RATE_LIMIT_TRUSTED_PROXIES=10.0.0.10/32,10.0.0.11/32
RATE_LIMIT_TRUSTED_PROXY_MAX_HOPS=3
```

### Reverse proxy and client identity

- Terminate TLS at a trusted reverse proxy.
- The reverse proxy must **append** the address it observed, not pass a caller-supplied `X-Forwarded-For` unchanged.
- Configure only that proxy's address/CIDR in `RATE_LIMIT_TRUSTED_PROXIES`.
- Run the ASGI server with `--no-proxy-headers` or equivalent. Do not let both the ASGI server and the application interpret forwarding headers independently.
- Reject or normalize malformed forwarding chains at the edge where possible; the API also returns `400 INVALID_FORWARDED_FOR`.

### Network isolation

- Keep the worker and proxy off public networks.
- Keep `worker-net` internal.
- Permit only the proxy to reach the internet.
- Set `REQUIRE_EGRESS_PROXY=true`.
- Keep `ALLOW_PRIVATE_NETWORKS=false`, `BROWSER_ALLOW_PRIVATE_NETWORKS=false`, and `PROXY_ALLOW_PRIVATE_NETWORKS=false`.
- Keep `DEFAULT_DOMAIN_POLICY=deny` with an explicit allowlist.
- Set consistent domain/port policy in API, worker, and proxy; compare startup policy fingerprints.

### Real backends

- Set `POLICY_BACKEND=egress-policy`.
- Set `INSPECTION_BACKEND=prompt-injection` (or a stronger approved inspector).
- Production startup rejects `mock` for either backend.
- Set `ALLOWED_DOMAINS`; production startup rejects an empty allowlist with default-deny.

### Search

- Prefer `SEARCH_PROVIDER=brave` with `SEARCH_API_KEY` for full web search.
- `duckduckgo` is a limited keyless fallback and must be labeled as such.
- Keep `SEARCH_MAX_RESULTS` at an operationally safe ceiling.

### Browser and resource limits

- Tune `BROWSER_MAX_SESSIONS`, `BROWSER_MAX_CONCURRENT_CONTEXTS`, and timeout values to host capacity.
- Keep Chromium sandbox enabled. Do not add `--no-sandbox` as a workaround.
- Size container memory for Chromium child processes, not just the worker RSS.
- Keep `BROWSER_ALLOW_WEBRTC=false`.
- Keep `BROWSER_SCREENSHOT_MAX_CONCURRENT`, byte, dimension, rate, and per-session limits conservative.

### Observability

- Collect JSON logs from API, worker, and proxy.
- Alert on `rate_limit_backend_unavailable`, `browser_worker_failure`, `egress_policy_violation`, `proxy_auth_failed`, and repeated `invalid_forwarded_for`.
- Compare the API, worker, and proxy policy fingerprints at startup.
- Monitor Redis availability and latency.
- Monitor worker process-tree RSS and Chromium process count.

## Health checks

| Endpoint | Purpose |
| --- | --- |
| `GET /health/live` | Process liveness |
| `GET /health/ready` | Worker and optional proxy readiness |
| Worker `/health/live` | Worker process liveness |
| Worker `/health/ready` | Worker/Chromium/proxy readiness |
| Proxy `/health/ready` | Proxy mode and readiness |

## Scaling notes

- Multiple API replicas require Redis-backed rate limiting.
- Persistent sessions live in one worker's memory. If you run multiple workers, route each session consistently to its owning worker; the current single `BROWSER_WORKER_URL` configuration does not provide multi-worker session routing.
- Redis must be reachable from every API replica with low latency.
- The proxy is a shared egress choke point; scale it deliberately and keep its policy identical to the API/worker.
- Do not scale the worker horizontally without solving session affinity and per-session cleanup.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| API fails at startup in production | Missing `API_AUTH_TOKEN`, empty allowlist, mock backend, or memory rate limiter | Fix the reported configuration error |
| Every request returns `503` rate-limit error | Redis unreachable and fail-closed | Restore Redis or explicitly accept degraded mode |
| Spoofed `X-Forwarded-For` changes buckets | Uvicorn proxy headers still enabled, or trusted proxy list too broad | Add `--no-proxy-headers`; narrow trusted proxies |
| `403 PRIVATE_IP_BLOCKED` for a local fixture | Private networking disabled | Use an isolated test config with `ALLOW_PRIVATE_NETWORKS=true`; never in production |
| Worker readiness fails | Egress proxy missing/unhealthy, or Chromium launch failure | Check `REQUIRE_EGRESS_PROXY`, proxy health, Chromium binary |
| `429` from search | Provider or API category limit | Inspect `Retry-After`, provider quota, and `RATE_LIMIT_SEARCH_PER_MINUTE` |
| Sessions disappear | Idle/max-age/lease expiry | Inspect session timing configuration and worker logs |
| Screenshot `413` | Clip/full-page exceeds configured dimensions | Reduce clip/viewport or raise limits deliberately |
