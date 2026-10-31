# Architecture

AgentShield Secure File Downloads is a standalone Python service that fetches
external documents for agents without introducing malware, malicious documents,
SSRF, or unauthorized files into the browser-security environment.

## Process model

One FastAPI application process (`api.app:create_app`) owns:

- an async SQLAlchemy engine (SQLite by default; PostgreSQL is documented but
  the driver is not in the dependency set — see [ENVIRONMENT.md](ENVIRONMENT.md));
- three filesystem zones under `STORAGE_ROOT`:
  `temporary/`, `quarantine/`, `approved/`;
- a fixed download-concurrency budget per tenant, enforced with asyncio
  semaphores;
- a fixed analysis worker pool (`ANALYSIS_WORKER_CONCURRENCY`);
- a background TTL sweeper for approved files.

There is no message broker, no cache server, and no second process. The
analysis queue, rate-limit buckets, and per-download locks are in-process. The
deployment assumptions that follow from this are documented in
[RESIDUAL_RISK.md](RESIDUAL_RISK.md).

## Components

| Component | Module | Responsibility |
|---|---|---|
| API surface | `api/app.py`, `api/routes.py`, `api/schemas.py` | HTTP endpoints, validation, response filtering |
| Middleware | `api/middleware.py` | Bearer auth, per-IP and per-tenant rate limiting, request IDs |
| Configuration | `config/settings.py`, `config/logging_setup.py` | Fail-closed settings, environment classification, JSON logging |
| Orchestrator | `services/orchestrator.py` | Download lifecycle state machine, scan serialization, TTL, recovery |
| Downloader | `services/downloader.py` | Proxy-enforced streaming download, framing checks, hashing |
| Preflight / SSRF | `security/url_validator.py`, `security/domain_policy.py`, `security/ssrf.py`, `security/ip_policy.py`, `security/dns_revalidation.py` | URL policy, DNS checks, connection-time re-validation |
| Proxy enforcement | `security/proxy_enforcement.py`, `security/proxy_auth.py` | Proxy attestation per request, proxy credentials |
| Response validation | `security/mime_validator.py`, downloader framing logic | Magic-byte MIME, archive rejection, strict HTTP framing |
| Scanner | `services/scanner.py` | ClamAV INSTREAM scan, bounded timeout, fail-closed verdicts |
| Storage | `storage/manager.py` | Zone isolation, traversal-safe paths, atomic moves, permissions |
| Analysis handoff | `integrations/handoff.py` | Approved-only gate with checksum re-verification |
| PDF processing | `services/document_processor.py` | Bounded, non-executing PDF inspection |
| Provider adapter | `integrations/analysis_adapter.py`, `security/analysis_egress.py` | Provider contract v1 over a hardened egress chain |
| Analysis service | `services/analysis_service.py`, `services/analysis_repository.py` | Durable job lifecycle, retries, worker pool, recovery |
| Persistence | `models/`, `services/repository.py`, `migrations/` | Downloads and analysis jobs, tenant-scoped queries |

## Request flows

### Download

```
client ──POST /online/downloads──▶ API
  auth → tenant → rate limit → URL validation (HTTPS, domain, port, IP policy)
  → PENDING record → background task
  → VALIDATING → DOWNLOADING (proxy-enforced streaming, one connection per hop)
  → DOWNLOADED (size, SHA-256, MIME)
  → VERIFYING (scan serialization) → SCANNING (ClamAV)
  → APPROVED | QUARANTINED | REJECTED | FAILED
  → EXPIRED when the approved TTL passes
```

### Analysis

```
APPROVED download ──POST /analysis──▶ job row (unique per download)
  → worker pool → RUNNING
  → re-read download (must still be APPROVED)
  → approved-zone gate: zone, existence, SHA-256 of bytes read
  → payload cap → local PDF processing (bounded)
  → provider call over the analysis egress chain
  → validate/sanitize response → persist normalized result → COMPLETED
```

Quarantined, rejected, failed, expired, and in-flight downloads cannot enter
analysis.

## Trust boundaries

| Boundary | One side | Other side | Control |
|---|---|---|---|
| B1 | Caller | API | Bearer token, `X-Tenant-ID`, rate limits |
| B2 | API | Origin server | HTTPS-only policy, domain/port/IP policy, DNS re-validation, egress proxy |
| B3 | API | Analysis provider | Endpoint allow-at-construction, DNS/IP policy, destination check, attested proxy, bounded payloads |
| B4 | API | ClamAV daemon | Private-network TCP, bounded scan, fail-closed verdicts |
| B5 | API | Database | Credentials in `DATABASE_URL`; tenant-scoped queries |
| B6 | API | Storage | Zone isolation, generated filenames, 0700/0600 permissions |
| B7 | API | Logs | Structured fields only; no tokens, proxy credentials, document content, or extracted text |

The caller is trusted to identify its tenant (see risk R1). The egress proxy is
the authoritative IP-policy boundary on the proxied path; in-process checks are
defence-in-depth. The provider's internal security is outside this service.

## Persistence

- `downloads`: lifecycle state, tenant, agent, URL, checksum, size, MIME,
  scan verdict, storage reference (never exposed through the API), timestamps.
- `document_analyses`: one row per download (unique index), state, attempts,
  retryability, fixed error code/detail, normalized result JSON.
- Migrations run automatically at startup (Alembic `0001`, `0002`). The
  startup path deliberately does not load `alembic.ini` logging configuration,
  so the service's own logging setup survives startup.

## Failure and recovery model

- Startup fails closed in production-like environments when configuration is
  unsafe or the database is unreachable.
- Downloads abandoned by a previous process become `FAILED` at startup; orphan
  temporary files are removed (startup sweep, older-than-zero).
- Analysis jobs left `PENDING`/`RUNNING` are re-enqueued/reset at startup.
- A cancelled download or scan removes its temporary file; a cancelled
  analysis requeues the job under a shielded transition.
- The TTL sweeper expires approved files and quarantined records on its
  configured cadence; quarantine file deletion remains an operator policy.

See [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) for procedures.
