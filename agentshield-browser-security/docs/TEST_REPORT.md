# Test Report

**Date:** 2026-10-31  
**Environment:** macOS on Apple hardware, Python 3.15.0 in `api/.venv`, Node.js v26.12.1, Puppeteer Chromium, Redis 5.3.1 client, `redis-server` available.

## Summary

| Suite | Command | Result |
| --- | --- | --- |
| API default (unit tests) | `cd api && .venv/bin/python -m pytest -q` | **239 passed, 0 failed** |
| API integration tests (no Chromium) | `cd api && .venv/bin/python -m pytest tests/integration/test_full_request_path.py -q` | **19 passed, 0 failed** |
| Worker | `cd worker && npm test` | **131 passed, 0 failed** |
| Proxy | `cd proxy && npm test` | **53 passed, 0 failed** |
| **Total** | | **442 passed, 0 failed** |

No warnings are blocking. The Starlette/httpx `TestClient` deprecation warning is non-blocking.

The API default suite excludes the Chromium-dependent integration tests in `tests/integration/` (which require Puppeteer + real Chromium) and the opt-in E2E suite (marked `e2e`/`load`, run with `RUN_E2E=1`).

## Test results by suite

### API unit tests (239 passed)

All tests in `api/tests/` except `tests/e2e/` and `tests/integration/` (which need a real browser worker process and Chromium). Includes session ownership, navigation policy, rate limiting, search, health, and security hardening tests.

### API integration tests — full request path (19 passed)

New tests in `api/tests/integration/test_full_request_path.py` verifying the real enforcement path without requiring Chromium:

- Successful navigation through full path (policy → worker → response)
- Blocked destinations (denylist, default-deny)
- Private IP and metadata IP blocking before the worker
- Session ownership (cross-agent read/navigate/close rejected)
- Session lifecycle (create → get → close → deleted session cannot be reused)
- Worker timeout → HTTP 504
- Worker unavailable → HTTP 502
- Worker bad response → HTTP 502
- Worker policy error (SESSION_FORBIDDEN) propagated
- Missing/invalid agent identity rejected
- Invalid URL scheme and embedded credentials rejected
- Redirect destination blocked by API re-check
- No silent direct-egress fallback

### Worker tests (131 passed)

Real Chromium-based tests covering session lifecycle, session cleanup, session ownership, navigation security, URL validation, actions, extraction, screenshots, and worker auth.

### Proxy tests (53 passed)

Real Node.js tests covering HTTP/CONNECT/WebSocket proxying, domain/port/IP policy, DNS rebinding protection, metadata IP blocking, proxy authentication, and health endpoint enforcement mode.

## Coverage gaps

- Docker Compose was not runtime-tested; no container startup or sandbox test was executed.
- Chromium-dependent integration tests cannot run without Puppeteer-installed Chromium.
- DEMO 1 and DEMO 5 depend on external services (example.com, DuckDuckGo).
- No long-duration soak test, multi-worker session-affinity test, or distributed Redis failover test was run.
- No fuzzing or dependency-vulnerability scan is included.
- No production load test beyond 100 requests/10 concurrency was run.

## Reproduce

```bash
cd api
.venv/bin/python -m pytest -q

# New integration tests (no Chromium required):
.venv/bin/python -m pytest tests/integration/test_full_request_path.py -q

cd ../worker
npm test

cd ../proxy
npm test
```
