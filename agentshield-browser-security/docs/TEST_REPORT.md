# Test Report

**Date:** 2026-10-31  
**Environment:** macOS on Apple hardware, Python 3.15.0 in `api/.venv`, Node.js v26.12.1, Puppeteer Chromium, Redis 5.3.1 client, `redis-server` available.

## Summary

| Suite | Command | Result |
| --- | --- | --- |
| API default (unit + integration; E2E skipped) | `cd api && .venv/bin/python -m pytest -q` | **228 passed, 34 skipped, 1 warning** |
| API full E2E | `cd api && RUN_E2E=1 .venv/bin/python -m pytest -q` | **262 passed, 1 warning** |
| Worker | `cd worker && npm test` | **131 passed, 0 failed** |
| Proxy | `cd proxy && npm test` | **53 passed, 0 failed** |

The warning is a Starlette/httpx `TestClient` deprecation warning. It is non-blocking.

The 34 skipped tests are the opt-in E2E suite: 11 functional, 8 SSRF, 4 rate-limit, 10 failure, and 1 load test.

## Baseline and current counts

- Baseline before this pass: **226 API tests passed**.
- Current default API suite: **228 passed** (the two new unit tests are the DuckDuckGo 202 contract and the worker navigation-timeout mapping).
- Full E2E: **34 additional tests passed**.

## E2E suite inventory

### `test_demo_functional.py` — 11 passed

- DEMO 1: allowed HTTPS site.
- DEMO 3: destination outside allowlist denied.
- DEMO 4: prompt-injection page flagged.
- DEMO 5: real DuckDuckGo provider normalized results.
- DEMO 6: redirect chain followed; redirect to metadata blocked.
- DEMO 7: disallowed form method refused.
- DEMO 8: oversized action payload refused.
- Persistent session extraction/action/screenshot.
- Session owner binding.
- Health readiness reports worker and proxy.

### `test_demo_ssrf.py` — 8 passed

- Literal loopback, RFC1918, metadata, and Alibaba metadata addresses.
- Hostname resolving to a private address.
- API-side rejection proof and fixture hit-counter non-increase.

### `test_demo_rate_limit.py` — 4 passed

- Redis counter shared across two API replicas.
- Trusted `X-Forwarded-For` gets independent buckets.
- Untrusted peer cannot spoof a new bucket.
- Malformed trusted forwarding chain returns `400 INVALID_FORWARDED_FOR`.

### `test_demo_failures.py` — 10 passed

- Worker unavailable.
- Redis failure fail-closed.
- Redis failure fail-open only when explicitly configured.
- Search timeout.
- Search outage.
- Broken browser launch.
- Session expiration during action.
- Invalid URL and unsupported action.
- Wrong API token.
- Oversized screenshot clip.

### `test_load.py` — 1 passed

- 100 real navigations at concurrency 10, with latency, throughput, status, and RSS reporting.

## Bugs found and fixed during verification

1. **DuckDuckGo HTTP 202 was treated as failure.** Live DuckDuckGo returned `202`; the client accepted only `200`. Fixed to accept `{200, 202}` and added a parameterized contract test.
2. **Uvicorn proxy-header bypass.** Uvicorn trusts `X-Forwarded-For` from `127.0.0.1` by default, rewriting `request.client.host` before the application's trusted-proxy logic. The failing E2E test exposed this. Fixed by adding `--no-proxy-headers` to the E2E harness, Dockerfile, and README; documented as a deployment requirement.
3. **Missing extract rate-limit category.** Added `RATE_LIMIT_EXTRACT_PER_MINUTE` (default 30), policy registration, and enforcement on `/v1/browser/extract`.
4. **Worker navigation timeout collapsed to 403.** Worker `504 NAVIGATION_TIMEOUT` was not preserved by the API status mapping. Added the status map, including `504` and `502`, and a unit test.
5. **E2E contract assumptions corrected.** Demo 3 accepts `DOMAIN_BLOCKED`; session creation no longer sends an invalid `max_age_ms`; oversized type expects `INPUT_LENGTH_EXCEEDED`/400; extract title corrected; oversized screenshot clip expects `SCREENSHOT_DIMENSIONS_EXCEEDED`.

## Test design

- E2E tests launch real proxy, worker, and API processes with `start_new_session=True` and clean them up by process group.
- The API is started with `sys.executable -m uvicorn app.main:app ... --no-proxy-headers`.
- The functional stack uses `ALLOW_PRIVATE_NETWORKS=true` only for the loopback fixture and keeps domain policy default-deny with an explicit allowlist.
- The strict SSRF stack keeps private networking disabled while allowlisting the names under test, isolating the address-level control.
- The rate-limit stack uses real Redis and three API replicas with a dead worker URL so the limiter is reached without requiring a live browser.
- Failure tests use a blackhole proxy for search timeouts, a dead port for outages, and a nonexistent Chromium path for launch failure.
- Tests are opt-in via `RUN_E2E=1` and marked `e2e`/`load`.

## Coverage gaps

- Docker Compose was not runtime-tested; no container startup or sandbox test was executed.
- Screenshot timeout is covered at the API contract level and worker unit level, but not by a deterministic E2E browser hang.
- DEMO 1 and DEMO 5 depend on external services.
- No long-duration soak test, multi-worker session-affinity test, or distributed Redis failover test was run.
- No fuzzing or dependency-vulnerability scan is included.
- No production load test beyond 100 requests/10 concurrency was run.

## Reproduce

```bash
cd api
.venv/bin/python -m pytest -q

RUN_E2E=1 .venv/bin/python -m pytest -q

cd ../worker
npm test

cd ../proxy
npm test
```
