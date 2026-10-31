# AgentShield Secure File Downloads

Module 3 — Secure file-download subsystem for AgentShield Browser Security.

## Overview

Secure File Downloads allows agents to retrieve external documents without
introducing malware, malicious documents, SSRF vulnerabilities, or unauthorized
files into the browser-security environment. It is an independent Python
module with its own configuration, database, storage, and test suite.

## Architecture

```
secure-downloads/
├── pyproject.toml              # Project metadata + dependencies
├── alembic.ini                 # Alembic configuration
├── .env.example                # Environment variable documentation
├── config/
│   ├── __init__.py
│   └── settings.py             # Pydantic settings, production fail-closed
├── models/
│   ├── __init__.py
│   ├── database.py             # SQLAlchemy async engine + session factory
│   ├── download.py             # Download ORM model + state machine
│   └── analysis.py             # DocumentAnalysis ORM model + job state machine
├── security/
│   ├── __init__.py
│   ├── errors.py               # Error codes
│   ├── ip_policy.py            # SSRF IP blocking (private, metadata, etc.)
│   ├── domain_policy.py        # Domain allow/block list + port policy
│   ├── url_validator.py        # HTTPS-only URL validation
│   ├── ssrf.py                 # DNS resolution + SSRF preflight guard
│   ├── dns_revalidation.py     # Connection-time DNS re-validation (not pinning)
│   ├── proxy_enforcement.py    # Egress-proxy enforcement attestation
│   ├── proxy_auth.py           # Proxy-Authorization credential construction
│   ├── analysis_egress.py      # Second egress path: analysis transport + endpoint policy
│   ├── mime_validator.py       # Magic-byte MIME detection, archive rejection
│   └── preflight.py            # Combined URL + SSRF pre-flight check
├── services/
│   ├── __init__.py
│   ├── scanner.py              # ClamAV integration (fail-closed)
│   ├── downloader.py          # Proxy-enforced streaming downloader
│   ├── repository.py           # Download metadata persistence (tenant-scoped)
│   ├── orchestrator.py         # Full download lifecycle state machine
│   ├── document_processor.py   # Bounded, non-executing PDF inspection (pypdf)
│   ├── analysis_repository.py  # Analysis job persistence (tenant-scoped)
│   └── analysis_service.py     # Analysis pipeline + fixed worker pool (AnalysisRunner)
├── storage/
│   ├── __init__.py
│   └── manager.py              # Zone-isolated storage (temp/quarantine/approved)
├── integrations/
│   ├── __init__.py
│   ├── handoff.py              # Approved-only handoff gate + adapter interface + mock
│   ├── analysis_models.py      # Provider contract v1 + normalized result schema
│   └── analysis_adapter.py     # Hardened HTTP adapter, retries, response validation
├── api/
│   ├── __init__.py
│   ├── app.py                  # FastAPI application factory
│   ├── schemas.py              # Request/response Pydantic models
│   ├── middleware.py           # Auth, rate limit, request ID
│   └── routes.py               # /online/downloads endpoints (download + analysis)
├── migrations/
│   ├── env.py                  # Alembic async migration environment
│   ├── script.py.mako
│   └── versions/
│       ├── 0001_create_downloads_table.py
│       └── 0002_create_document_analyses_table.py
└── tests/
    ├── conftest.py             # Shared fixtures (fake/sequenced DNS, fake scanner)
    ├── pdf_fixtures.py         # Hand-built valid/corrupt/encrypted PDFs
    ├── unit/
    │   ├── test_download_lifecycle.py
    │   ├── test_url_validation.py
    │   ├── test_ssrf_protection.py
    │   ├── test_dns_revalidation.py     # connection-time re-validation
    │   ├── test_proxy_enforcement.py    # proxy attestation + downloader wiring
    │   ├── test_settings_fail_closed.py # production config refusals
    │   ├── test_environment_classification.py
    │   ├── test_mime_validation.py
    │   ├── test_storage_isolation.py
    │   ├── test_scanner.py
    │   ├── test_repository.py
    │   ├── test_handoff.py              # approved-only handoff gate
    │   ├── test_document_processor.py   # PDF bounds, encryption, malformed input
    │   ├── test_analysis_models.py      # provider schema + response sanitization
    │   ├── test_analysis_settings.py
    │   ├── test_analysis_egress.py      # analysis endpoint + destination checks
    │   ├── test_analysis_repository.py  # job uniqueness, transitions, recovery
    │   ├── test_analysis_service.py     # pipeline, retry, cancel, restart recovery
    │   ├── test_analysis_api.py         # analysis endpoints, tenant isolation
    │   ├── test_ip_policy.py
    │   ├── test_domain_policy.py
    │   ├── test_api_auth.py
    │   └── test_policy_consistency.py
    └── integration/
        ├── test_downloader_http.py      # real sockets against a local HTTP server
        └── test_analysis_adapter_http.py # adapter against a real local HTTP provider
```

## Quick Start

```bash
cd secure-downloads
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests (unit + real-socket integration, including the local provider server)
python -m pytest

# Unit tests only
python -m pytest tests/unit/ -v

# Real-HTTP analysis adapter tests only (local provider, no external network)
python -m pytest tests/integration/test_analysis_adapter_http.py -v -m integration
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/online/downloads` | Initiate a new download (async) |
| GET | `/online/downloads/{id}/status` | Get lifecycle state |
| GET | `/online/downloads/{id}/metadata` | Get full metadata (includes analysis fields) |
| POST | `/online/downloads/{id}/scan` | Trigger scan (idempotent) |
| POST | `/online/downloads/{id}/analysis` | Initiate analysis (`202`; idempotent per download) |
| GET | `/online/downloads/{id}/analysis` | Get analysis job status |
| GET | `/online/downloads/{id}/analysis/result` | Get normalized result (`409` until completed) |
| POST | `/online/downloads/{id}/analysis/retry` | Retry a retryable `FAILED` job (`202`) |
| GET | `/health/live` | Process liveness only (`200` whenever the loop answers) |
| GET | `/health/ready` | Dependency + security-configuration readiness (`200`/`503`) |

All `/online/*` endpoints require `X-Tenant-ID` header and Bearer token auth
(`API_AUTH_TOKEN`). Health endpoints are exempt from both auth and rate limiting.

Analysis API behaviour:

- **Initiate** requires the download to be `APPROVED`; anything else is `409`
  `INVALID_STATE`. The operation is idempotent: one job row per download (DB
  unique index), so repeated requests return the existing job and never create
  a second provider submission.
- **Status** returns the job's state, attempts, retryability, safe error
  code/detail, provider name, correlation ID and timestamps. It never returns
  document content, storage references or provider payloads.
- **Result** returns only the stored normalized result, and only when the job is
  `COMPLETED`; otherwise `409 ANALYSIS_NOT_COMPLETED`. Quarantined, rejected and
  unapproved documents have no result and cannot be analyzed.
- **Retry** only accepts `FAILED` jobs that are marked retryable and still have
  attempts left; otherwise `409 ANALYSIS_NOT_RETRYABLE`.
- When the provider mode is `disabled`, all four endpoints return
  `409 ANALYSIS_DISABLED`.
- Every endpoint enforces bearer auth and `X-Tenant-ID`; a download owned by a
  different tenant is `404`, indistinguishable from a nonexistent one.
- `/metadata` adds `analysis_id`, `analysis_state` and `analysis_provider`
  (`null` when no analysis exists) alongside the download fields. It never
  includes an approved-zone filesystem path or the temp/quarantine location.

## Health and readiness

The three signals are deliberately distinct:

- **Liveness** (`/health/live`) reports that the process and event loop are up.
  It ignores configuration and dependencies, so an unsafe config or a downed
  dependency never causes a supervisor to restart a healthy process.
- **Dependency + security readiness** (`/health/ready`) answers `200` only when
  all of these hold, and `503` otherwise:
  - `security_configuration` — no outstanding issues from `security_issues()`
    (e.g. empty `API_AUTH_TOKEN`, `REQUIRE_EGRESS_PROXY` without a proxy,
    `DNS_PREFLIGHT_ENABLED=false`, `ALLOW_PRIVATE_NETWORKS=true`, a mock or
    missing analysis provider, a non-HTTPS analysis endpoint, a missing
    analysis token, or analysis traffic configured to bypass the proxy);
  - `egress_proxy` — `enforcing` when a proxy is configured; `unattestable`
    when it has no health URL; `not_configured` when required but unset;
    `not_required` otherwise;
  - `database` — a `SELECT 1` against the configured engine (3 s timeout);
  - `storage` — the temporary zone accepts a probe write;
  - `scanner` — ClamAV is reachable (fail-closed scanning makes this gating).

  The payload lists check states and configuration-variable *names* only — never
  values — so no token, password or endpoint URL is exposed.
- **Startup fail-closed** — a production-like environment (`production`,
  `staging`) refuses to start when Settings validation or the lifespan safety
  net (`security_issues()`) reports an unsafe configuration.

## Download Lifecycle

```
PENDING → VALIDATING → DOWNLOADING → DOWNLOADED → VERIFYING → SCANNING → APPROVED
                ↓           ↓            ↓             ↓           ↓          ↓
            REJECTED     FAILED      FAILED        REJECTED    FAILED   QUARANTINED

APPROVED → EXPIRED (TTL cleanup)
QUARANTINED → EXPIRED
```

## Document Analysis

Analysis is a separate, post-approval stage. Nothing is sent to a provider
until the download has passed the full download pipeline and is `APPROVED`.

### Pipeline sequence

```
download → completeness (RESPONSE_INCOMPLETE) → size limit → SHA-256
        → MIME/signature → ClamAV → APPROVED | QUARANTINED | REJECTED | FAILED

APPROVED ──POST /analysis──→ job PENDING ──worker──→ RUNNING
  RUNNING: re-read download, must still be APPROVED
         → approved-zone gate (record + zone + existence + SHA-256)
         → read bytes from the approved zone only, re-hash what was read
         → payload-size cap
         → local bounded PDF processing (signature, structure, pages, text)
         → provider analysis (hardened egress, bounded retries/deadline)
         → validate + sanitize provider response
         → persist normalized result → mark handoff complete → COMPLETED
```

There is no path from `QUARANTINED`, `REJECTED`, `FAILED`, `EXPIRED` or any
in-flight download state into analysis. The service checks the download state
before creating a job and again inside the worker; the handoff gate also
requires the storage reference to be inside the approved zone and re-verifies
the SHA-256 of the bytes actually read.

### Analysis job state machine

```
PENDING ──claim──→ RUNNING ──→ COMPLETED   (terminal)
   ↑                  │
   │                  ├──→ FAILED ──retry──→ PENDING
   │                  ├──→ PENDING  (cancellation / worker shutdown)
   │                  └──→ CANCELLED
   └── retry (FAILED → PENDING)
```

- One job per download, enforced by a UNIQUE index on `download_id`. A second
  initiation returns the existing job and does not submit again.
- Execution is additionally serialized by a reference-counted per-download
  `asyncio.Lock`; under the lock anything not `PENDING` is a no-op. Different
  downloads analyze concurrently — there is no global lock.
- Work runs on a fixed worker pool (`ANALYSIS_WORKER_CONCURRENCY`) over an
  in-process queue; jobs are persisted before enqueue, and startup recovery
  re-enqueues `PENDING` and resets `RUNNING` to `PENDING` (single-writer SQLite
  deployment model).
- A job has a wall-clock deadline (`ANALYSIS_JOB_TIMEOUT_SECONDS`) and a bounded
  attempt count (`ANALYSIS_MAX_ATTEMPTS`). Cancellation requeues the job to
  `PENDING` under a shielded task.

### Provider modes

| `ANALYSIS_PROVIDER` | Behaviour |
|---|---|
| `disabled` | Feature off; analysis endpoints return `409 ANALYSIS_DISABLED`. |
| `local_mock` | In-process fake for local testing; results carry a `MOCK_ANALYSIS_PROVIDER` warning. **Refused in production/staging.** |
| `http` | Real provider adapter implementing contract v1. The only mode accepted in production. |

Selection is explicit and has no fallback. If the HTTP adapter cannot be
constructed (e.g. invalid endpoint) startup fails; it never degrades to the
mock. Production additionally requires: `https` endpoint, a non-empty
`ANALYSIS_API_TOKEN`, `ANALYSIS_USE_EGRESS_PROXY=true`, and both
`ANALYSIS_ALLOW_INSECURE_LOCAL`/`ANALYSIS_ALLOW_PRIVATE_ENDPOINTS` false.

### Provider contract v1

No external vendor has been selected for this deployment. `integrations/analysis_models.py`
defines the versioned contract a concrete provider implements; the local
integration test server implements the same contract.

```
POST <ANALYSIS_ENDPOINT_URL>
Authorization: Bearer <ANALYSIS_API_TOKEN>
Content-Type: application/json
Accept: application/json
X-Correlation-ID: <uuid>
Idempotency-Key: "<download_id>:<sha256>"

{
  "schema_version": "1",
  "correlation_id": "<uuid>",
  "document": {
    "download_id": "...", "tenant_id": "...", "agent_id": "...",
    "sha256": "...", "mime_type": "application/pdf", "size_bytes": 1234,
    "page_count": 3, "text_truncated": false,
    "extracted_text": "...", "warnings": ["..."]
  },
  "content_base64": "<approved file bytes>"
}
```

Success is `200 application/json`:

```
{
  "schema_version": "1",
  "analysis_id": "...", "correlation_id": "...",
  "status": "completed" | "failed",
  "document": {"document_type": "pdf", "page_count": 3},
  "summary": "..." | null,
  "findings": [{"id": "...", "severity": "info|low|medium|high|critical",
                "title": "...", "detail": "..."}],
  "confidence": {"overall": 0.8} | null,
  "metadata": {"key": "scalar"},
  "warnings": ["..."],
  "processed_at": "2026-01-01T00:00:00Z",
  "error": {"code": "...", "message": "...", "retryable": false}
}
```

Response handling is fail-closed: non-JSON content types, malformed JSON,
schema mismatches, an unsupported `schema_version`, `status="failed"` without an
error object, and responses exceeding `ANALYSIS_MAX_RESPONSE_BYTES` are rejected
whole (`ANALYSIS_INVALID_RESPONSE` / `ANALYSIS_RESPONSE_TOO_LARGE`). Unknown
fields are ignored; strings have control characters stripped and are
length-capped; findings/warnings/metadata/confidence collections are
count-capped; nothing is partially stored. `confidence` is stored only when the
provider supplies it — this service never computes or defaults a score.

### Integration setup

1. Set `ANALYSIS_PROVIDER=http`.
2. Set `ANALYSIS_ENDPOINT_URL` to the provider's HTTPS endpoint (port 443) and
   `ANALYSIS_API_TOKEN` to its bearer credential. Do not put credentials in the
   URL.
3. Keep `ANALYSIS_USE_EGRESS_PROXY=true` and configure `EGRESS_PROXY_URL` /
   `EGRESS_PROXY_HEALTH_URL`; production refuses analysis egress that bypasses
   the attested proxy.
4. Tune `ANALYSIS_*_TIMEOUT_SECONDS`, `ANALYSIS_MAX_ATTEMPTS`,
   `ANALYSIS_MAX_PAYLOAD_BYTES`, `ANALYSIS_MAX_RESPONSE_BYTES` and the local PDF
   caps to the provider's limits.
5. Verify locally with the real-HTTP test server:
   `pytest tests/integration/test_analysis_adapter_http.py -m integration`.
   That server implements contract v1 and uses the same transport chain; it is
   a local fake provider, not a production integration test.
6. Once a vendor is selected, run a controlled test against its staging
   endpoint with real credentials before treating production integration as
   complete. No vendor is selected in this repository today.

### Normalized result

`GET /analysis/result` returns the stored `NormalizedAnalysisResult`, which
keeps locally derived facts and provider-supplied fields separate:

- locally derived (trusted, bounded): `document_type`, `page_count`,
  `extracted_text`, `text_truncated`;
- provider-supplied (validated and sanitized): `summary`, `findings`,
  `confidence`, `provider_metadata`, `provider_document_type`,
  `provider_analysis_id`, `provider_correlation_id`;
- provenance/timestamps: `download_id`, `analysis_id`, `provider`,
  `schema_version`, `sha256`, `processed_at`, `created_at`, `warnings`.

It never contains storage paths, document bytes, credentials or raw provider
responses.

### Safe document processing (PDF)

`PdfDocumentProcessor` runs on approved bytes only and:

- requires the `%PDF-` signature and a trailing `%%EOF` marker;
- parses with `pypdf` in a worker thread — nothing in the document is executed
  (JavaScript, launch actions, embedded files and macros are never run; active
  content markers are reported as a warning);
- rejects encrypted/password-protected PDFs (`DOCUMENT_ENCRYPTED`);
- rejects zero-page PDFs (`DOCUMENT_EMPTY`) and PDFs over `ANALYSIS_MAX_PAGES`
  (`DOCUMENT_TOO_MANY_PAGES`);
- caps extracted text at `ANALYSIS_MAX_EXTRACTED_CHARS`, stripping control
  characters and flagging truncation;
- bounds total processing time with `ANALYSIS_PROCESSING_TIMEOUT_SECONDS`;
- treats extracted text strictly as untrusted data: it is length-bounded and
  placed in a dedicated `extracted_text` field of the provider contract, which
  defines it as untrusted input, never as instructions to the provider.

Archives are rejected earlier by the download pipeline's MIME validator, so
they never reach analysis.

### Analysis egress path

The analysis adapter is a **second egress path** and does not inherit the
downloader's transport implicitly. `security/analysis_egress.py` builds its
own chain for every request:

```
AsyncHTTPTransport(proxy=<authorized proxy> or direct, verify=True)
  DnsRevalidatingTransport        per-request DNS + IP policy re-check
  EnforcingProxyTransport         per-request proxy attestation          [proxy set]
  DestinationCheckTransport       target still equals the configured endpoint
```

- Endpoint validated at construction: HTTPS (port 443) or, only with
  `ANALYSIS_ALLOW_INSECURE_LOCAL`, plain HTTP on a loopback host; no credentials
  in the URL.
- Private/loopback/link-local/metadata destinations are rejected at dispatch
  unless `ANALYSIS_ALLOW_PRIVATE_ENDPOINTS` is set (local testing only).
- `trust_env=False`: `HTTP(S)_PROXY` and similar environment variables are
  never honoured.
- `follow_redirects=False`; a 3xx is an error (`ANALYSIS_REDIRECT_BLOCKED`) so
  the bearer token is never replayed to another destination.
- Bounded connect/read/total timeouts, bounded request payload
  (`ANALYSIS_MAX_PAYLOAD_BYTES`) and bounded response (`ANALYSIS_MAX_RESPONSE_BYTES`).
- The bearer token and document content are never logged; error messages carry
  fixed text and structural fields only.

External egress paths in this service, enumerated:

| Path | Code | Enforcement |
|---|---|---|
| Download of the source document | `services/downloader.py` | proxy (if configured) + preflight + per-hop DNS revalidation |
| Analysis provider call | `integrations/analysis_adapter.py` via `security/analysis_egress.py` | proxy (required in production) + endpoint policy + per-request DNS revalidation |
| Egress-proxy health probes | `security/proxy_enforcement.py` | direct to the configured health URL, no redirects, short timeout |

No other outbound connections are made.

### Failure handling

| Failure | Code | Retriable |
|---|---|---|
| Provider timeout (connect/read/total) | `ANALYSIS_TIMEOUT` | yes |
| Provider unreachable / connection failure / proxy error | `ANALYSIS_UNAVAILABLE` | yes |
| Provider 429 | `ANALYSIS_PROVIDER_RATE_LIMITED` | yes (honours `Retry-After`, capped) |
| Provider 5xx or `status="failed"` with `retryable=true` | `ANALYSIS_PROVIDER_ERROR` | yes |
| Provider 401/403 | `ANALYSIS_AUTH_FAILED` | no |
| Provider 3xx | `ANALYSIS_REDIRECT_BLOCKED` | no |
| Invalid/oversized provider response | `ANALYSIS_INVALID_RESPONSE` / `ANALYSIS_RESPONSE_TOO_LARGE` | no |
| Invalid PDF / encrypted / empty / too many pages | `DOCUMENT_*` | no |
| Approved bytes changed | `CHECKSUM_MISMATCH` | no |
| Download left `APPROVED` / storage ref invalid / file missing | `INVALID_STATE` / `HANDOFF_ERROR` | no |
| Job deadline exceeded | `ANALYSIS_JOB_TIMEOUT` | yes |
| Document larger than payload cap | `ANALYSIS_PAYLOAD_TOO_LARGE` | no |

Retries are bounded by attempts, exponential delay and the total deadline; only
transient outcomes are retried. A failed job records a fixed, content-free
`error_detail`; provider response bodies are never persisted or returned.

### Known limitations (analysis)

1. **Production provider integration is not verified.** No vendor or
   credentials are available in this environment. The adapter, provider
   contract and local real-HTTP test server are implemented and tested; a
   controlled test against a real provider remains to be run once a vendor is
   selected.
2. **Document text remains untrusted input to the provider.** This service
   treats it as data (bounded, sanitized, structurally separated) and never
   interprets it; whether the provider resists prompt injection is outside this
   module's control and must be part of provider acceptance testing.
3. **Processing timeout is not a hard CPU pre-emption.** The PDF parse runs in
   a thread; on deadline the waiting coroutine fails the job, but the thread may
   run to completion. Input-size and page caps are the hard bounds.
4. **Encrypted PDFs are rejected, not decrypted.** There is no password
   handling.
5. **Per-request DNS revalidation is a gate, not IP pinning** — the same
   rebinding caveat as the download path applies (see "Connection security
   model").

## Security Controls

- **Environment classification (fail-closed)**: `ENVIRONMENT` has no default.
  Missing, empty or unrecognized values are rejected; input is case- and
  whitespace-normalized onto `development`/`test`/`staging`/`production`
  (`prod`→production, `stage`/`preprod`/`pre-production`→staging, `dev`/`local`→
  development, `tests`→test). `staging` enforces the **same** policy as
  production.
- **HTTPS-only** URL validation (`https_only=True` in the app pipeline)
- **SSRF preflight**: URL/hostname policy, then one DNS lookup validating every
  A/AAAA record before any connection is attempted
- **Connection-time DNS re-validation**: every request (including each redirect
  hop) re-resolves and re-checks the destination before it is dispatched.  This
  narrows the rebinding window; it does not pin the connection — see
  "Connection security model" below.
- **Egress proxy**: outbound connections use `EGRESS_PROXY_URL` when configured;
  `EnforcingProxyTransport` re-attests the proxy's `mode="enforcing"` before
  every request (successful results cached for `proxy_health_cache_ttl`, default
  5s) rather than only once per download
- **Proxy authentication**: when `PROXY_AUTH_TOKEN` is set, every proxied
  request carries `Proxy-Authorization: Basic base64("agentshield:<token>")`.
  The token is percent-encoded into the proxy URL userinfo and is never logged,
  never included in error messages, and never echoed by `/health/ready`. The
  token without a proxy URL is rejected at startup. Failed proxy auth — HTTP
  407 or a connection rejected by the proxy — fails the download with
  `PROXY_AUTH_FAILED`.
- **Fail-closed proxy configuration**: the health endpoint must answer 200 with
  `{"status": "ok", "mode": "enforcing"}`.  A configured proxy without a health
  endpoint, an unreachable or non-200 endpoint, non-JSON, a degraded status, a
  payload without a `mode` field, or any mode other than `enforcing` blocks the
  download.  In production, startup additionally refuses `REQUIRE_EGRESS_PROXY=false`,
  an empty `EGRESS_PROXY_URL`, an empty `EGRESS_PROXY_HEALTH_URL`,
  `DNS_PREFLIGHT_ENABLED=false` and `ALLOW_PRIVATE_NETWORKS=true`.
- **Streaming downloads**: the response body is streamed to disk; a 16 MiB
  response against a 1 MiB limit aborts mid-transfer.  Content-Length is never
  trusted — the byte counter enforces the limit.
- **Strict response acceptance**: each hop must be a complete, unambiguous
  HTTP response. Multiple/conflicting `Content-Length` headers, `Content-Length`
  together with `Transfer-Encoding: chunked`, a non-integer or negative length,
  a body truncated below the declared length, broken chunk framing, or an
  unparseable response are rejected with `RESPONSE_INCOMPLETE` — nothing from
  that transfer is accepted, and the file never reaches the approved zone. The
  stored size and SHA-256 always describe the bytes actually received.
- **Per-hop connection isolation**: every request (first and each redirect hop)
  builds a fresh `httpx.AsyncClient` and transport, and the previous hop's
  connection is closed before the next begins. A response smuggled behind a
  short `Content-Length` on one hop therefore has no connection to be read from
  on the next; `Connection: close` is sent only as a courtesy and is not the
  mechanism.
- **MIME detection**: magic-byte inspection (Content-Type treated as untrusted);
  archives rejected
- **ClamAV scanning**: fail-closed; unknown verdicts never become APPROVED
- **Scan serialization**: the automatic lifecycle and manual `POST /scan` share
  a reference-counted per-download `asyncio.Lock`. Under the lock the record is
  re-read; anything past `DOWNLOADED` makes the caller a no-op. One file is
  therefore scanned, moved and transitioned at most once, duplicate manual
  requests cannot double-scan, different downloads still scan concurrently
  (there is no global lock), and a cancelled scan is recovered to `FAILED` with
  its temporary file removed via a shielded transition.
- **Bounded transfers**: connect, per-read and total-deadline timeouts are all
  enforced; a cancelled download deletes its temporary file before propagating
- **Storage isolation**: temporary/quarantine/approved zones with path traversal
  protection; temp files deleted on failure
- **Tenant isolation**: all download and analysis queries are scoped by
  tenant_id; every analysis endpoint requires bearer auth plus `X-Tenant-ID`,
  and a cross-tenant download is reported as `404`
- **Approved-only handoff**: only APPROVED files can be handed off to document
  analysis. The download state is checked when the job is created and again in
  the worker, and the handoff gate requires the storage reference to resolve
  inside the approved zone with a matching SHA-256. Quarantined, rejected,
  unscanned and temporary files are unreachable.
- **Analysis is a second, hardened egress path**: dedicated transport chain,
  HTTPS/port policy, per-request DNS/IP revalidation, redirects disabled,
  endpoint identity check, bounded payload/response/timeouts, no environment
  proxy inheritance, and the attested egress proxy required in production. See
  "Analysis egress path".
- **Untrusted provider responses**: schema-validated and sanitized (control
  characters stripped, lengths/counts capped, unknown fields ignored); invalid
  responses are rejected whole and never partially stored. Confidence is only
  recorded when the provider supplies it.
- **No sensitive logging**: document content, document bytes, bearer tokens and
  raw provider responses are never logged or returned in errors.

## Connection security model

Request path for one download (`services/downloader.py`):

```
assert_proxy_available()            proxy required + attested enforcing
DownloadPreflight.validate()        URL policy → one DNS lookup → IP policy
transport chain (per request):
  EnforcingProxyTransport           re-attest proxy mode (cached TTL)   [proxy set]
    DnsRevalidatingTransport        re-resolve host, re-check IP policy
      httpx.AsyncHTTPTransport      socket → egress proxy, or direct
  redirect hop → full preflight again → repeat
stream to temp zone → SHA-256 → magic-byte MIME check → ClamAV → approve/quarantine
```

Each hop uses its own `httpx.AsyncClient` and transport. The client and
transport for a redirect response are closed before the next hop's request is
dispatched, so protocol state (including unread bytes from a short
`Content-Length`) cannot carry over between hops.

Where the authoritative boundary sits:

| Configuration | Who decides the IP actually contacted | In-process checks |
|---|---|---|
| `EGRESS_PROXY_URL` set | the proxy (it opens the TCP connection and resolves the name) | defence-in-depth |
| no proxy (development) | this process, via the OS resolver at `connect()` time | preflight + re-validation |

### Known limitations (not controls — do not rely on them)

1. **Re-validation is not DNS pinning.** `DnsRevalidatingTransport` discards the
   addresses it validates; the wrapped transport resolves the hostname again.
   An attacker-controlled nameserver that answers differently per query can land
   the connection on an address no check ever approved. The integration test
   `test_validated_address_is_not_the_connection_target` demonstrates this.
   Shortening the window from "preflight → connect" to "lookup → connect" is the
   entire mitigation; the window is milliseconds, not zero.
2. **Proxy attestation is self-reported.** The health endpoint says whether the
   proxy believes it is enforcing. A proxy that lies, or whose policy differs
   from this module's, is not detectable from here. Domain/IP policy must be
   configured identically on both sides.
3. **No proxy means no TCP-layer enforcement.** With `EGRESS_PROXY_URL` empty the
   in-process checks are all that stands between a download and internal
   addresses; production configuration refuses this (see below).
4. **Redirect destinations inherit the same limits.** They are re-validated, not
   pinned.
5. **A declared length smaller than the real body is not rejected.** Bytes past
   the declared `Content-Length` are discarded by the HTTP parser together with
   the dedicated per-hop connection; they are never stored, never hashed and
   never fed to the next hop. Detecting the surplus server-side is not possible
   from the client. Truncation in the other direction (`declared > actual`) and
   ambiguous framing are rejected (`RESPONSE_INCOMPLETE`).

### Feasibility of true IP pinning

Assessed during Phase 1 remediation; **not implemented**. httpcore connects to
`origin.host` (`httpcore/_async/connection.py:117`) and takes the TLS hostname
from the request extension `sni_hostname` when present
(`httpcore/_async/connection.py:151`), so a chain that connects to a validated
IP while still verifying the certificate for the original hostname is
technically reachable by:

- rewriting the request host to the validated IP, restoring the `Host` header,
  and setting `extensions["sni_hostname"]` to the original hostname; or
- supplying a custom `httpcore.AsyncNetworkBackend` that substitutes the connect
  target while leaving the origin (and therefore SNI) intact.

Costs and risks to weigh before doing it: `httpx.AsyncHTTPTransport` has no
public `network_backend` parameter, so either route means building the
httpcore pool ourselves or touching httpx internals; per-family behaviour
(IPv6/`Happy Eyeballs`, multi-homed names where only one address was validated)
has to be defined; and on the proxied path pinning is meaningless — the proxy
resolves the name, and rewriting the host would break the CONNECT target, the
proxy's own domain policy, and certificate verification. It is also a
TLS-sensitive change that cannot be validated here without an HTTPS test server
with a trusted certificate. Recommendation: keep re-validation plus proxy
enforcement, and revisit pinning as a separate, explicitly scoped change.
