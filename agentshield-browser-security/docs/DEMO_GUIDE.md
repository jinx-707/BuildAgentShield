# Demo Guide

**Date:** 2026-10-31  
**Purpose:** Reproduce DEMO 1–10 and the bounded load test with real processes.

## What is real in the demo

- FastAPI API served by uvicorn over TCP.
- Node.js browser worker.
- Node.js enforcing egress proxy.
- Real Chromium launched by Puppeteer.
- Redis for the multi-replica rate-limit demo.
- Controlled local HTTP fixture for functional and SSRF tests.

Nothing in the demo stack is mocked. The fixture origin exists only to avoid depending on third-party sites for most functional checks.

## Run the whole E2E suite

```bash
cd api
RUN_E2E=1 .venv/bin/python -m pytest tests/e2e -v -s
```

Requirements:

- `worker/node_modules` installed and Chromium available.
- `redis-server` on `PATH` for DEMO 9.
- Network access to `example.com` for DEMO 1 and DuckDuckGo for DEMO 5.

The suite starts processes on free loopback ports and cleans them up afterward. E2E tests are skipped unless `RUN_E2E=1`.

## Demo 1 — Allowed HTTPS site

**Test:** `test_demo1_allowed_https_site`

```bash
RUN_E2E=1 .venv/bin/python -m pytest tests/e2e/test_demo_functional.py::test_demo1_allowed_https_site -v -s
```

Expected: `200`; `final_url` starts with `https://example.com/`; title/content contains `Example Domain`; policy allowed; inspection trust label `untrusted`; zero blocked requests.

If external network is unavailable, the test skips.

## Demo 2 — SSRF attempts are rejected

**Tests:** `tests/e2e/test_demo_ssrf.py`

```bash
RUN_E2E=1 .venv/bin/python -m pytest tests/e2e/test_demo_ssrf.py -v -s
```

Cases:

- `127.0.0.1`
- `10.0.0.1`
- `172.16.0.1`
- `192.168.1.1`
- `169.254.169.254`
- `100.100.100.200`
- `localtest.me` resolving to a private address

Expected: `403` with `PRIVATE_IP_BLOCKED`, `DNS_RESOLUTION_FAILED`, or `DOMAIN_BLOCKED`; fixture hit counter does not increase; API log shows the rejection and the worker never receives the private destination.

The strict stack deliberately allowlists the names under test while keeping private networking disabled, so a rejection proves the address guard fired rather than an allowlist coincidence.

## Demo 3 — Destination outside the allowlist is denied

**Test:** `test_demo3_destination_outside_allowlist_is_denied`

Expected: `403` with `policy_denied`, `DOMAIN_NOT_ALLOWED`, or `DOMAIN_BLOCKED`.

## Demo 4 — Prompt-injection page is flagged

**Test:** `test_demo4_prompt_injection_page_is_flagged`

The fixture `/inject` contains suspicious instructions.

Expected: `200`; inspection trust label `untrusted`; classification `suspicious`; findings present; highest severity `high` or `critical`; at least one finding mentions instructions.

## Demo 5 — Real search provider

**Test:** `test_demo5_real_search_provider_returns_normalized_results`

```bash
RUN_E2E=1 .venv/bin/python -m pytest tests/e2e/test_demo_functional.py::test_demo5_real_search_provider_returns_normalized_results -v -s
```

The E2E stack uses `SEARCH_PROVIDER=duckduckgo`.

Expected: `200`; provider `duckduckgo-instant-answer`; mode `limited_fallback`; explicit notice; normalized HTTPS result; every result untrusted.

DuckDuckGo returned HTTP `202` in live testing; the client now accepts `200` and `202`. This is not full web search.

## Demo 6 — Redirect policy

**Tests:** `test_demo6_redirect_chain_is_followed_within_policy`, `test_demo6_redirect_to_metadata_address_is_blocked`

Expected:

- Allowed chain: `200`; final URL `/page`; redirect count at least 1; fixture content present.
- Redirect to `169.254.169.254`: `403` with `REDIRECT_DESTINATION_BLOCKED`, `URL_ADDRESS_BLOCKED`, `PRIVATE_ADDRESS_BLOCKED`, or `EGRESS_DESTINATION_BLOCKED`.

## Demo 7 — Disallowed form method refused

**Test:** `test_demo7_disallowed_form_method_is_refused`

The fixture `/form-put` contains a form using a method other than GET/POST.

Expected: navigation succeeds, then `submit_form` returns `403 FORM_METHOD_NOT_ALLOWED`.

## Demo 8 — Oversized action payload refused

**Test:** `test_demo8_oversized_action_payload_is_refused`

A type action sends 5,000 characters against a 4,000-byte limit.

Expected: `400` or `413` with `INPUT_LENGTH_EXCEEDED` or `PAYLOAD_TOO_LARGE`.

## Demo 9 — Shared rate limiting and XFF spoofing

**Test:** `tests/e2e/test_demo_rate_limit.py`

```bash
RUN_E2E=1 .venv/bin/python -m pytest tests/e2e/test_demo_rate_limit.py -v -s
```

The test starts Redis and three API replicas with a dead worker URL, so navigation reaches the limiter and then fails with `502`. The limiter is set to `2` navigation requests per minute.

Expected:

1. Two requests through replica A succeed past the limiter; the third through replica B returns `429 RATE_LIMIT_EXCEEDED`.
2. Trusted `X-Forwarded-For` values get separate buckets.
3. An untrusted peer cannot change buckets by spoofing `X-Forwarded-For`; the third request returns `429`.
4. A malformed chain from a trusted peer returns `400 INVALID_FORWARDED_FOR`.

Critical deployment requirement: run uvicorn with `--no-proxy-headers`. Without it, uvicorn trusts `X-Forwarded-For` from `127.0.0.1` by default and the application's trusted-proxy control is bypassed. The E2E harness starts uvicorn with this flag.

## Demo 10 — Failure handling

**Test:** `tests/e2e/test_demo_failures.py`

```bash
RUN_E2E=1 .venv/bin/python -m pytest tests/e2e/test_demo_failures.py -v -s
```

Cases and expected results:

| Case | Expected |
| --- | --- |
| Worker unavailable | `502 browser_worker_failure` |
| Redis unavailable, fail closed | `503 RATE_LIMIT_BACKEND_UNAVAILABLE` with `Retry-After: 1` |
| Redis unavailable, fail open explicitly | Limiter bypassed; request reaches dead worker and returns `502` |
| Search provider timeout | `504 SEARCH_PROVIDER_TIMEOUT` |
| Search provider outage | `503 SEARCH_PROVIDER_UNAVAILABLE` |
| Broken Chromium executable | `502 browser_worker_failure` |
| Session expires during action | `404 SESSION_NOT_FOUND` after idle expiry |
| Invalid URL or unsupported action | `422` |
| Wrong API token | `401` |
| Oversized screenshot clip | `413 SCREENSHOT_DIMENSIONS_EXCEEDED` |

## Bounded load test

**Test:** `tests/e2e/test_load.py`

```bash
RUN_E2E=1 .venv/bin/python -m pytest tests/e2e/test_load.py -v -s
```

The test runs 100 real navigations at concurrency 10 against the local fixture and prints a `LOAD_REPORT` JSON line. See `PERFORMANCE_REPORT.md` for measured results.

## Fixture endpoints

The local fixture serves:

- `/page`
- `/linked`
- `/inject`
- `/redirect`
- `/redirect-chain`
- `/slow`
- `/ssrf-target`
- `/form-get`
- `/form-put`
- `/submitted`
- `/large`
- `/favicon.ico`

It includes hidden text `HIDDEN_E2E_SECRET` to prove hidden-content exclusion and hit counters to prove blocked requests never reached the destination.

## Troubleshooting

- If E2E tests are skipped, set `RUN_E2E=1`.
- If DEMO 1 skips, external network access to `example.com` is unavailable.
- If DEMO 5 fails, check DuckDuckGo reachability and provider response shape.
- If DEMO 9 skips, install `redis-server`.
- If Chromium fails to launch, run `npm run browser:install` in `worker/` or set `BROWSER_EXECUTABLE_PATH`.
- If rate-limit spoofing behaves unexpectedly, confirm uvicorn was started with `--no-proxy-headers`.
