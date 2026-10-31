# Environment Configuration Reference

Settings are read from environment variables (case-insensitive) or `.env`
files by `config/settings.py`. `.env.example` documents the same variables.
Production/staging validation is fail-closed: unsafe values are rejected at
startup, before the app is built.

## Service identity

| Variable | Default | Production requirement | Notes |
|---|---|---|---|
| `ENVIRONMENT` | *(none — required)* | `production` or `staging` | Accepted aliases: `prod`→production; `stage`/`preprod`/`pre-production`→staging; `dev`/`local`→development; `tests`→test. Empty/unknown fails validation. |
| `LOG_LEVEL` | `INFO` | any standard level | Applied only when the process has no root logging handler (the service then installs a JSON handler). |
| `APP_NAME` | `agentshield-secure-downloads` | — | Used in readiness output and logs. |

## API authentication and limits

| Variable | Default | Production | Notes |
|---|---|---|---|
| `API_AUTH_TOKEN` | empty | **required** | Shared bearer token. Empty means all `/online/*` endpoints are unauthenticated (unsafe; readiness fails). |
| `RATE_LIMIT_ENABLED` | `true` | recommended | In-memory per-process limiter. |
| `RATE_LIMIT_PER_MINUTE` | `30` | tune | Per client IP and per tenant, sliding 60 s window. |

## Database

| Variable | Default | Production | Notes |
|---|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./secure_downloads.db` | PostgreSQL recommended for concurrency | Migrations run at startup. PostgreSQL requires installing `asyncpg` (not in the default dependency set) and a `postgresql+asyncpg://` URL. SQLite is single-writer. |

## Egress proxy

| Variable | Default | Production | Notes |
|---|---|---|---|
| `EGRESS_PROXY_URL` | empty | **required** | HTTP proxy used for downloads and (when enabled) analysis. No environment proxy is ever consulted. |
| `EGRESS_PROXY_HEALTH_URL` | empty | **required** | Must answer `200` with `{"status":"ok","mode":"enforcing"}`. |
| `REQUIRE_EGRESS_PROXY` | `true` | must remain `true` | Production refuses `false`. |
| `PROXY_AUTH_TOKEN` | empty | if proxy requires auth | Basic password for user `agentshield`; never logged. Setting it without a proxy URL is rejected. |

## Destination policy

| Variable | Default | Production | Notes |
|---|---|---|---|
| `ALLOWED_DOMAINS` | empty | **required** | Comma-separated allow list. |
| `BLOCKED_DOMAINS` | empty | optional | Comma-separated deny list. |
| `DEFAULT_DOMAIN_POLICY` | `deny` | `deny` recommended | `allow` or `deny` when a host is on neither list. |
| `ALLOWED_PORTS` | `80,443` | `443` recommended | App pipeline is HTTPS-only regardless. |
| `ALLOW_PRIVATE_NETWORKS` | `false` | must remain `false` | Production refuses `true`. |
| `DNS_PREFLIGHT_ENABLED` | `true` | must remain `true` | Production refuses `false`. |

## Download limits

| Variable | Default | Notes |
|---|---|---|
| `MAX_FILE_SIZE_BYTES` | `52428800` (50 MiB) | Enforced during streaming. |
| `DOWNLOAD_CONNECT_TIMEOUT_SECONDS` | `10.0` | TCP connect. |
| `DOWNLOAD_READ_TIMEOUT_SECONDS` | `30.0` | Per chunk read. |
| `DOWNLOAD_TOTAL_TIMEOUT_SECONDS` | `120.0` | Whole-download deadline. |
| `MAX_REDIRECTS` | `5` | Each hop revalidated. |
| `MAX_CONCURRENT_DOWNLOADS_PER_TENANT` | `5` | Exceeding returns `429 CONCURRENCY_LIMIT_EXCEEDED`. |

## ClamAV

| Variable | Default | Notes |
|---|---|---|
| `CLAMAV_HOST` | `127.0.0.1` | clamd TCP host. Keep on a private network. |
| `CLAMAV_PORT` | `3310` | clamd port. |
| `CLAMAV_TIMEOUT_SECONDS` | `60.0` | Scan deadline. |
| `CLAMAV_FAIL_CLOSED` | `true` | Do not disable in production; `false` still never maps errors to `CLEAN` (it only changes the recorded failure mode). |

## Storage

| Variable | Default | Notes |
|---|---|---|
| `STORAGE_ROOT` | `/var/secure-download-storage` | Created with `temporary/`, `quarantine/`, `approved/` (0700). |
| `APPROVED_FILE_TTL_SECONDS` | `3600` | Approved files expire after this. |
| `CLEANUP_INTERVAL_SECONDS` | `60` | TTL sweeper cadence (5–3600). |

Quarantined files are deliberately retained; deletion is an operator/forensics
decision (see [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md)).

## Document analysis

| Variable | Default | Production | Notes |
|---|---|---|---|
| `ANALYSIS_PROVIDER` | `disabled` | `http` | `disabled` → 409; `local_mock` → test only, refused in production; `http` → real adapter. |
| `ANALYSIS_ENDPOINT_URL` | empty | **required for http** | HTTPS port 443; no credentials in URL. |
| `ANALYSIS_API_TOKEN` | empty | **required for http** | Bearer credential; never logged. |
| `ANALYSIS_CONNECT_TIMEOUT_SECONDS` | `5.0` | — | 0 < x ≤ 60. |
| `ANALYSIS_READ_TIMEOUT_SECONDS` | `30.0` | — | 0 < x ≤ 300. |
| `ANALYSIS_TOTAL_TIMEOUT_SECONDS` | `60.0` | — | 0 < x ≤ 600. |
| `ANALYSIS_JOB_TIMEOUT_SECONDS` | `120.0` | — | Whole job including retries. |
| `ANALYSIS_MAX_ATTEMPTS` | `3` | — | 1–10. |
| `ANALYSIS_RETRY_BASE_DELAY_SECONDS` | `0.25` | — | Exponential backoff base. |
| `ANALYSIS_WORKER_CONCURRENCY` | `2` | — | Fixed worker pool. |
| `ANALYSIS_MAX_PAYLOAD_BYTES` | `10485760` | — | Request cap. |
| `ANALYSIS_MAX_RESPONSE_BYTES` | `2097152` | — | Response cap. |
| `ANALYSIS_MAX_PAGES` | `200` | — | PDF page cap. |
| `ANALYSIS_MAX_EXTRACTED_CHARS` | `200000` | — | Text cap. |
| `ANALYSIS_PROCESSING_TIMEOUT_SECONDS` | `20.0` | — | 0 < x ≤ 300. |
| `ANALYSIS_ALLOW_INSECURE_LOCAL` | `false` | must remain `false` | Allows plain HTTP on loopback. |
| `ANALYSIS_ALLOW_PRIVATE_ENDPOINTS` | `false` | must remain `false` | Allows loopback/private provider targets. |
| `ANALYSIS_USE_EGRESS_PROXY` | `true` | must remain `true` | Required in production. |

## Runtime-only variables

| Variable | Used by | Notes |
|---|---|---|
| `DATABASE_URL` (Alembic CLI) | `migrations/env.py` | Overrides `alembic.ini` for `alembic upgrade/downgrade`. |
| `SSL_CERT_FILE` | E2E tests | Points httpx/OpenSSL at the generated local CA bundle; not needed in production. |
| `SECURE_DOWNLOADS_CLAMAV_EICAR_TEST` | opt-in ClamAV test | Set to `1` **and** provide a reachable clamd to run real EICAR tests. |

## Secrets

Real credentials must never be committed. Inject `API_AUTH_TOKEN`,
`PROXY_AUTH_TOKEN`, `ANALYSIS_API_TOKEN`, and the database password through
your secret manager or environment. Logs, errors, and readiness never print
them.
