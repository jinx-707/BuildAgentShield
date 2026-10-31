# Test Report

## Environment

| Item | Value |
|---|---|
| OS | macOS (darwin), arm64 |
| Python | 3.15.0 (project requires ≥ 3.11) |
| pytest | 9.2.0 (`asyncio_mode=auto`) |
| httpx | 0.28.1 |
| FastAPI | 0.162.0 |
| Pydantic | 2.14.2 |
| SQLAlchemy | 2.1.6 |
| pypdf | 6.21.4 |
| Alembic | 1.20.1 |
| ClamAV | not installed; port 3310 closed |

Command: `.venv/bin/pytest -q` from `secure-downloads/`.

## Exact result (default suite)

```
628 passed, 3 skipped, 1 warning in 66.85s
```

- **Collected:** 631
- **Passed:** 628
- **Failed:** 0
- **Errors:** 0
- **Skipped:** 3
- **Deselected:** 0
- **Warnings:** 1 — `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead` (third-party; no action taken)

## Non-overlapping test partition

The suite is partitioned by primary category. These numbers sum to 631 and do
not double-count.

| Category | Count | Result | Definition |
|---|---|---|---|
| Unit | 516 | 516 passed | `tests/unit/`, no real sockets |
| Integration (non-E2E) | 83 | 83 passed | `tests/integration/`, marker `integration`, real loopback servers/app/DB |
| End-to-end | 29 | 29 passed | marker `e2e`, real local HTTPS origin, full app |
| Real ClamAV (opt-in) | 3 | 3 **skipped** | marker `real_clamav` |
| Real provider | 0 | — | no vendor integrated |
| **Total** | **631** | **628 passed, 3 skipped** | |

## Cross-cutting subsets (do not add these to the total)

| Subset | Count | Notes |
|---|---|---|
| Tests using a real local HTTP/TLS socket | 98 | 69 integration transport tests + 29 E2E; overlaps the partition above |
| Tests using the local fake analysis provider | 16 + analysis steps in E2E | **Not** a real provider integration |
| Tests using a simulated scanner | unit scanner/lifecycle/scan-concurrency + E2E demo 4 | **Not** real ClamAV |
| Tests using real ClamAV | 3 | Skipped: no clamd/EICAR in this environment |
| Load measurement | separate harness | `scripts/load_test.py`, not pytest |

## Suite inventory

### Unit (516)

| Area | Files (count) |
|---|---|
| Configuration / environment | `test_environment_classification.py` (41), `test_settings_fail_closed.py` (9), `test_analysis_settings.py` (18) |
| URL / domain / IP policy | `test_url_validation.py` (34), `test_domain_policy.py` (16), `test_ip_policy.py` (29), `test_ssrf_protection.py` (10), `test_dns_revalidation.py` (19) |
| Transport / proxy / framing | `test_proxy_enforcement.py` (23), `test_proxy_auth_config.py` (16), `test_response_framing.py` (13), `test_policy_consistency.py` (8) |
| Download lifecycle / scanner | `test_download_lifecycle.py` (22), `test_scan_concurrency.py` (11), `test_scanner.py` (15), `test_orchestrator_resilience.py` (8) |
| Storage | `test_storage_isolation.py` (22), `test_storage_hardening.py` (27) |
| MIME / PDF / handoff | `test_mime_validation.py` (15), `test_document_processor.py` (13), `test_handoff.py` (11) |
| Analysis | `test_analysis_models.py` (23), `test_analysis_egress.py` (12), `test_analysis_repository.py` (13), `test_analysis_service.py` (18), `test_analysis_api.py` (12) |
| API / observability / readiness | `test_api_auth.py` (10), `test_observability_and_rates.py` (11), `test_logging_setup.py` (5), `test_startup_readiness.py` (20) |
| Persistence | `test_repository.py` (12) |

### Integration, non-E2E (83 passed)

| File | Count |
|---|---|
| `test_downloader_http.py` | 20 |
| `test_analysis_adapter_http.py` | 16 |
| `test_auth_tenant_matrix.py` | 14 |
| `test_response_acceptance.py` | 11 |
| `test_proxy_auth_http.py` | 8 |
| `test_download_timeouts.py` | 7 |
| `test_redirect_smuggling.py` | 7 |

These use real loopback sockets and, for the tenant matrix, the real app with a
file-backed SQLite database.

### E2E (29 passed)

`tests/integration/test_e2e_demos.py` — demos 1–10, real local TLS origin.
See [E2E_DEMOS.md](E2E_DEMOS.md).

### Skipped (3)

`tests/integration/test_clamav_optional.py`:

1. EICAR sample is reported `INFECTED` by a real clamd.
2. A benign PDF is reported `CLEAN` by a real clamd.
3. `is_available()` returns true against the real daemon.

Skip conditions: `SECURE_DOWNLOADS_CLAMAV_EICAR_TEST=1` not set and no clamd
reachable at `CLAMAV_HOST:CLAMAV_PORT`. These are the only real-ClamAV tests;
the default suite's scanner coverage is simulated.

## Marker runs

| Command | Collected | Result |
|---|---|---|
| `pytest -m e2e` | 29 | 29 passed |
| `pytest -m integration` | 83 | 83 passed |
| `pytest -m real_clamav` | 3 | 3 skipped |
| `pytest -m real_provider` | 0 | no tests |
| `pytest tests/unit` | 516 | 516 passed |
| `pytest tests/integration` | 115 | 112 passed, 3 skipped |

Marker-based runs deselect the complement by design; they are not additional
tests.

## What is covered

- SSRF policy, DNS re-validation, redirect and smuggling defenses, strict
  framing, truncation, oversize, timeouts.
- Proxy attestation, cache behavior, oversized/redirecting health responses,
  proxy auth failure.
- MIME detection and archive rejection; PDF bounds, encryption, malformed input.
- Storage traversal, symlinks, permissions, atomic moves, concurrent writes,
  failed moves, cleanup, checksum access.
- ClamAV fail-closed verdicts, timeout, unavailable, odd daemon responses,
  scan serialization.
- Tenant isolation across every resource route, including guessed IDs and
  cross-tenant retry/scan.
- Analysis egress policy, response validation/sanitization, job lifecycle,
  retries, cancellation, restart recovery.
- Startup fail-closed configuration, readiness gates, structured logging,
  request IDs, rate-limit budgets.
- End-to-end demos 1–10 over real TLS.

## What is not covered / not run

- **Real provider integration:** no vendor, no credentials, 0 tests. The local
  server implements contract v1 but is a fake.
- **Real ClamAV:** 3 opt-in tests skipped here.
- **Real egress proxy:** tests use local health/mock servers; no production
  proxy conformance test.
- **Multi-replica behavior:** no coordination tests because the design is
  single-process.
- **PostgreSQL:** no tests; `asyncpg` not installed.
- **Long-running soak / memory leak testing.**
- **Browser/front-end:** no UI exists.
- **Prompt-injection resistance of a provider:** out of scope.

## Test integrity notes

- No tests were deleted, skipped, or weakened to obtain a green run. The three
  skips require external infrastructure that is absent here.
- Simulated components are labelled in test docstrings and in this report;
  simulated scanner behavior is never described as real ClamAV, and the local
  provider is never described as a real integration.
- The full suite was re-run after the last code change (structured logging and
  the Alembic logging fix) with the result above.

## Load test

See [PERFORMANCE.md](PERFORMANCE.md). The harness is not part of pytest and its
results are local measurements, not capacity claims.
