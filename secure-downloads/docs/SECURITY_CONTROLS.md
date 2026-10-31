# Security Controls Matrix

Each control lists where it is enforced, which tests exercise it, its known
limitations, and its status for production use.

Status values: **Enforced** (implemented and tested), **Enforced with
limitations**, **Operator-dependent**, **Not production-ready**.

## Authentication and tenancy

| Control | Enforcement | Tests | Limitations | Status |
|---|---|---|---|---|
| Bearer token on every non-health endpoint | `api/middleware.py` (`ApiAuthMiddleware`), `hmac.compare_digest` | `test_api_auth.py` (10), `test_auth_tenant_matrix.py` (14), E2E demo 6 | One shared service token; no per-caller identity or scopes | Enforced with limitations |
| Tenant scoping of every read/write | `services/repository.py`, `services/analysis_repository.py`, routes; queries filter `tenant_id` | `test_auth_tenant_matrix.py`: cross-tenant 404 on status/metadata/scan/analysis/result/retry | Caller asserts `X-Tenant-ID`; it is trusted after token auth and is not an independently verifiable identity | Enforced with limitations |
| Unknown and foreign IDs indistinguishable | Same; `NOT_FOUND` 404 with no metadata | `test_auth_tenant_matrix.py` (guessed-ID and foreign-tenant 404s) | — | Enforced |
| Manual scan requires ownership | `orchestrator.request_scan` re-reads under the per-download lock | `test_auth_tenant_matrix.py`, `test_scan_concurrency.py` | — | Enforced |
| Health endpoints exempt from auth/rate limit | `api/middleware.py`, `api/app.py` | `test_api_auth.py`, `test_startup_readiness.py`, `test_observability_and_rates.py` | Anyone who can reach the port can read readiness state (no secrets in payload) | Enforced with limitations |
| Rate limiting per IP and per tenant | `RateLimitMiddleware`: sliding window, both budgets checked | `test_observability_and_rates.py` (11) | In-memory, per process — not shared across replicas; resets on restart | Enforced with limitations |
| Tenant header validated | FastAPI `Header(min_length=1, max_length=128)` | `test_auth_tenant_matrix.py` (422 without header) | Any shape within length is accepted as a tenant key | Enforced |

## SSRF and egress

| Control | Enforcement | Tests | Limitations | Status |
|---|---|---|---|---|
| HTTPS-only URL validation | `security/url_validator.py` (`https_only=True` in app) | `test_url_validation.py` (34) | — | Enforced |
| Domain allow/block and default-deny policy | `security/domain_policy.py` | `test_domain_policy.py` (16) | Must match proxy configuration; no wildcard guarantees beyond implemented suffix rules | Enforced |
| Port policy | `security/domain_policy.py`, `allowed_ports` | `test_domain_policy.py`, E2E demo 2 | Must be configured identically on the proxy | Enforced |
| IP policy (private, loopback, link-local, metadata) | `security/ip_policy.py` | `test_ip_policy.py` (29), `test_ssrf_protection.py` (10) | IPv4-mapped IPv6 and special ranges are handled explicitly; new IANA special-purpose ranges require review | Enforced |
| Preflight DNS validation of every answer | `security/ssrf.py` | `test_ssrf_protection.py`, `test_dns_revalidation.py` (19) | One lookup before connection; not pinning | Enforced with limitations |
| Connection-time DNS re-validation | `security/dns_revalidation.py` | `test_dns_revalidation.py`, E2E demo 2 (rebinding) | Gate check, not IP pinning; rebinding window remains (R2) | Enforced with limitations |
| Egress proxy required in production | `config/settings.py`, `api/app.py`, downloader | `test_settings_fail_closed.py` (9), `test_startup_readiness.py` | Proxy policy must mirror this service's | Enforced with limitations |
| Proxy attestation before every request | `security/proxy_enforcement.py`; 5 s success cache | `test_proxy_enforcement.py` (23), E2E demos 2/10 | Self-reported; a lying proxy is undetectable (R3) | Enforced with limitations |
| Proxy credentials | `security/proxy_auth.py`; userinfo, never logged | `test_proxy_auth_config.py` (16), `test_proxy_auth_http.py` (8) | Static shared password; no rotation support | Enforced with limitations |
| No environment proxy inheritance | `trust_env=False` on every egress client | `test_downloader_http.py`, `test_analysis_adapter_http.py` | — | Enforced |
| Redirect re-validation and hop isolation | `services/downloader.py` | `test_redirect_smuggling.py` (7), `test_response_acceptance.py` (11) | Max redirects bounds loops | Enforced |
| Provider endpoint fixed and checked | `security/analysis_egress.py` | `test_analysis_egress.py` (12) | — | Enforced |
| Analysis redirects blocked | `integrations/analysis_adapter.py` | `test_analysis_adapter_http.py` (16) | — | Enforced |

## Download integrity

| Control | Enforcement | Tests | Limitations | Status |
|---|---|---|---|---|
| Streaming byte counter enforces size limit | `services/downloader.py` | `test_downloader_http.py`, E2E demo 3 | — | Enforced |
| Strict HTTP framing, truncation rejection | `services/downloader.py` | `test_response_acceptance.py` (11) | Extra bytes beyond a short declared length are discarded but not detectable client-side (R11) | Enforced with limitations |
| Magic-byte MIME detection; archives rejected | `security/mime_validator.py` | `test_mime_validation.py` (15) | `python-magic` requires `libmagic` in the image | Enforced |
| SHA-256 of received bytes | `services/downloader.py`, orchestrator | `test_download_lifecycle.py` (22), storage tests | Computed during streaming; storage re-read verifies before analysis | Enforced |
| Timeouts (connect/read/total) | `services/downloader.py` | `test_download_timeouts.py` (7) | Total deadline is wall-clock | Enforced |
| Cancellation cleans temp file | `services/downloader.py`, orchestrator shielded recovery | `test_orchestrator_resilience.py` (8) | — | Enforced |
| One scan per file under a per-download lock | `services/orchestrator.py` | `test_scan_concurrency.py` (11) | Lock is in-process; multi-process deployments are unsupported | Enforced |
| Quarantine on non-clean verdict | `services/orchestrator.py` | `test_download_lifecycle.py`, E2E demo 4 (simulated scanner) | Real ClamAV path tested only opt-in | Enforced with limitations |

## ClamAV

| Control | Enforcement | Tests | Limitations | Status |
|---|---|---|---|---|
| Fail-closed verdicts | `services/scanner.py` | `test_scanner.py` (15) | Simulated daemon in default suite | Enforced |
| Bounded scan time | `CLAMAV_TIMEOUT_SECONDS`, `asyncio.wait_for` | `test_scanner.py` | Worker thread may outlive the timeout until socket timeout | Enforced with limitations |
| Availability probe | `is_available()` (PING, 5 s) | scanner and readiness tests | — | Enforced |
| Infected never approved | Orchestrator verdict branch | `test_download_lifecycle.py`, E2E demo 4 | EICAR never used by default | Enforced |
| Result tied to scanned file | Orchestrator locks and checksum re-read | `test_scan_concurrency.py`, handoff tests | — | Enforced |
| Real clamd integration | `tests/integration/test_clamav_optional.py` | 3 opt-in tests (**skipped** here: no clamd, no EICAR) | Not executed in this environment; see [TEST_REPORT.md](TEST_REPORT.md) | Not verified here |

## Storage

| Control | Enforcement | Tests | Limitations | Status |
|---|---|---|---|---|
| Zone isolation | `storage/manager.py` | `test_storage_isolation.py` (22), `test_storage_hardening.py` (27) | Zones share a filesystem; operator must protect the volume | Enforced |
| Path traversal prevention | Resolve + `relative_to` check | storage tests (traversal-shaped names, symlinks) | — | Enforced |
| Generated filenames | UUID v4; UUID never used as authorization | storage tests (500 unique allocations) | — | Enforced |
| Permissions | 0700 dirs, 0600 files after move | storage tests | umask/ACL interactions depend on host | Enforced |
| Atomic moves | `os.replace` | storage tests (interrupted/replace failures) | Same filesystem required | Enforced |
| Approved-only accessor | `get_approved_path` | `test_handoff.py` (11), storage tests | — | Enforced |
| Temp cleanup / orphan sweep | Orchestrator, startup sweep, TTL sweeper | lifecycle, storage, resilience tests | — | Enforced |
| Quarantine retention | Files deliberately retained | — | Deletion is an operator/forensics decision; no automatic TTL (R12) | Operator-dependent |
| No paths in API | Schemas exclude `storage_ref`; tenant matrix asserts path-free 404/metadata | `test_auth_tenant_matrix.py` | — | Enforced |

## Analysis pipeline

| Control | Enforcement | Tests | Limitations | Status |
|---|---|---|---|---|
| Approved-only handoff | `integrations/handoff.py` re-checks state, zone, existence, SHA-256 | `test_handoff.py` (11), `test_analysis_service.py` (18) | — | Enforced |
| Bounded PDF processing | `services/document_processor.py` | `test_document_processor.py` (13) | CPU deadline is not thread pre-emption (R9) | Enforced with limitations |
| Provider payload/response bounds | adapter and settings | `test_analysis_adapter_http.py`, `test_analysis_models.py` | — | Enforced |
| Response schema validation and sanitization | `integrations/analysis_models.py` | `test_analysis_models.py` (23) | Provider content is untrusted; semantic quality is out of scope | Enforced |
| Durable job lifecycle and retries | `services/analysis_service.py`, repository | analysis service/repository tests, E2E demos 5/8 | In-process queue; single-writer model | Enforced with limitations |
| Cancellation requeues safely | shielded transition | `test_analysis_service.py`, resilience tests | — | Enforced |
| No document content in job/result status | schemas, fixed error text | `test_analysis_api.py` (12) | Extracted text appears only in the stored normalized result returned by `/result`, by design | Enforced |

## Observability and operations

| Control | Enforcement | Tests | Limitations | Status |
|---|---|---|---|---|
| Request IDs on every response | `RequestContextMiddleware` | `test_observability_and_rates.py` | Client-supplied IDs are accepted if they match a safe pattern | Enforced |
| Structured JSON logs with extra fields | `config/logging_setup.py` | `test_logging_setup.py` (5) | Installed only when the host has no root handler; uvicorn access logs stay plain | Enforced |
| No secrets/content in logs | Code discipline; fixed error text; tests | `test_observability_and_rates.py`, `test_scanner.py`, readiness tests | Tracebacks (`exc_info`) may include exception text; review before sharing logs | Enforced with limitations |
| Startup does not clobber logging | Programmatic Alembic config; `disable_existing_loggers=False` | `test_startup_readiness.py` (regression tests) | — | Enforced |
| Distinct liveness/readiness/security gates | `api/app.py` | `test_startup_readiness.py` (20) | Readiness probes dependencies, so a dependency outage removes ready pods (R13) | Enforced with limitations |
| Fail-closed production configuration | `config/settings.py`, lifespan safety net | `test_settings_fail_closed.py`, `test_environment_classification.py` (41), E2E demo 10 | — | Enforced |

## Not production-ready

| Item | Why |
|---|---|
| Real provider integration | No vendor selected; only contract v1, adapter, and a local fake provider are tested |
| Real ClamAV verification in this environment | No clamd/EICAR available; the 3 real-ClamAV tests are skipped |
| Multi-replica correctness | Rate limits, scan locks, analysis queue, and startup recovery assume one process |
| Independent tenant identity | Tenant is a trusted header after shared-token auth |
