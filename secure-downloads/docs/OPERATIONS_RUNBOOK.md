# Operations Runbook

## Start / stop

- Start: run `uvicorn api.app:app --host <addr> --port <port>` (or the
  container). Startup creates storage zones, runs migrations, recovers
  interrupted downloads/jobs, sweeps orphan temp files, and starts the analysis
  workers and TTL sweeper.
- Stop: send `SIGTERM`. The lifespan cancels the TTL sweeper, cancels and
  awaits in-flight download tasks, stops the analysis runner, and disposes the
  engine. In-flight downloads fail their records and remove temp files;
  in-flight analysis jobs are requeued.
- Failure to start: check logs for `security_configuration_issues` or a
  `RuntimeError` from the production safety net. In production-like
  environments an unsafe configuration is a deliberate refusal to boot.

## Health triage

| Symptom | Likely cause | Action |
|---|---|---|
| `/health/live` fails | Process/event loop dead | Restart; inspect crash logs |
| `/health/ready` 503, `database: unreachable` | DB down / bad URL / lock | Check DB service, credentials, disk, connections |
| `storage: error` | Volume read-only/full/permissions | Check mount, free space, ownership; storage must permit writes to `temporary/` |
| `scanner: unavailable` | clamd down/unreachable | Start clamd; check `CLAMAV_HOST/PORT`; signatures |
| `egress_proxy: not_enforcing` | Proxy down, permissive, bad health payload | Fix proxy mode/health; downloads are blocked meanwhile |
| `egress_proxy: unattestable` | Proxy configured without health URL | Set `EGRESS_PROXY_HEALTH_URL` |
| `security_configuration: not_ready` | Unsafe config (see `issues`) | Fix the named variables; readiness lists names, not values |

## Common failures

### Downloads

| Code | Meaning | Operator action |
|---|---|---|
| `DOMAIN_BLOCKED` / `PORT_NOT_ALLOWED` / `URL_SCHEME_NOT_ALLOWED` | Policy rejection | Confirm the source is intended; update policy if so |
| `PRIVATE_IP_BLOCKED` / `SSRF_BLOCKED` | Destination resolves to a blocked range | Investigate the sender; never relax checks casually |
| `DNS_RESOLUTION_FAILED` | Resolver problem or bad host | Check DNS from the API host |
| `EGRESS_PROXY_UNAVAILABLE` | Attestation failed | Fix proxy; see readiness |
| `PROXY_AUTH_FAILED` | Proxy rejected credentials (407) | Verify `PROXY_AUTH_TOKEN` / proxy ACL |
| `DOWNLOAD_TIMEOUT` | Connect/read/total deadline | Check origin/proxy latency; adjust timeouts deliberately |
| `RESPONSE_INCOMPLETE` | Ambiguous/truncated HTTP framing | Treat as suspicious; inspect origin |
| `FILE_TOO_LARGE` | Exceeded cap | Raise cap only with storage review |
| `MIME_NOT_ALLOWED` / `ARCHIVE_REJECTED` | Content type not permitted | Expected for disallowed types |
| `SCANNER_UNAVAILABLE` | clamd unreachable with fail-closed | Restore clamd |
| `CONCURRENCY_LIMIT_EXCEEDED` | Per-tenant cap | Wait; raise `MAX_CONCURRENT_DOWNLOADS_PER_TENANT` only if capacity allows |

### Analysis

| Code | Retryable | Action |
|---|---|---|
| `ANALYSIS_TIMEOUT`, `ANALYSIS_UNAVAILABLE`, `ANALYSIS_PROVIDER_RATE_LIMITED`, `ANALYSIS_PROVIDER_ERROR`, `ANALYSIS_JOB_TIMEOUT` | Yes (bounded) | Check provider/network; client may POST `/retry` after failure |
| `ANALYSIS_AUTH_FAILED` | No | Fix `ANALYSIS_API_TOKEN`; restart to rebuild the adapter |
| `ANALYSIS_REDIRECT_BLOCKED`, `ANALYSIS_INVALID_RESPONSE`, `ANALYSIS_RESPONSE_TOO_LARGE` | No | Treat as provider/config defect; inspect provider |
| `DOCUMENT_*` | No | The document is invalid/encrypted/too large |
| `CHECKSUM_MISMATCH` | No | Approved file changed on disk — investigate storage integrity |
| `INVALID_STATE` / `HANDOFF_ERROR` | No | Download left APPROVED or storage ref invalid |
| `ANALYSIS_DISABLED` / `ANALYSIS_UNCONFIGURED` | — | Provider mode not enabled/configured |

Retries are bounded by `ANALYSIS_MAX_ATTEMPTS`, exponential backoff, and the
job deadline. Only transient codes are retryable.

## Log events

Logs are JSON objects (when the service installs the handler) with `timestamp`,
`level`, `logger`, `event`, and event-specific fields. Useful events include:

| Event | Key fields |
|---|---|
| `request_completed` | method, path, status_code, elapsed_ms, request_id |
| `secure_downloads_started` / `_stopped` | environment, proxy (redacted), provider mode |
| `security_configuration_issues` | environment, issue_count, issue names |
| `downloads_recovered`, `orphan_temp_files_removed`, `downloads_expired` | count |
| `download_approved`, `scan_skipped_not_downloaded` | download_id, tenant_id, size/state |
| `analysis_completed`, `analysis_job_failed`, `analysis_jobs_recovered` | download_id, tenant_id, provider/code |
| `clamav_unavailable`, `clamav_scan_timeout`, `clamav_scan_error` | host/port, timeout, error_type |
| `proxy_attestation_skipped` | reason |
| `temporary_sweep_failed` | error_type |
| `unhandled_exception`, `create_download_error` | error_type (traceback in log) |

Never log-inspect for tokens, proxy passwords, document content, or extracted
text; those are not emitted. Access to logs should still be restricted.

## Inspecting state

For SQLite (`sqlite3 secure_downloads.db`) or PostgreSQL, use read-only
queries:

```sql
-- Stuck or failed downloads
SELECT id, tenant_id, state, created_at, updated_at, failure_reason
FROM downloads
WHERE state IN ('PENDING','VALIDATING','DOWNLOADING','DOWNLOADED','VERIFYING','SCANNING');

-- Analysis failures awaiting triage
SELECT id, download_id, tenant_id, state, attempts, retryable, error_code, updated_at
FROM document_analyses
WHERE state = 'FAILED';

-- Approved files nearing expiry
SELECT id, tenant_id, expires_at FROM downloads
WHERE state = 'APPROVED' AND expires_at < datetime('now', '+1 hour');
```

Do not expose `storage_ref` from the database to callers.

## Storage and quarantine

- Inspect zone sizes: `du -sh "$STORAGE_ROOT"/*`.
- Temporary files are removed on failure, at shutdown, and at startup. If
  orphan files accumulate, look for repeated crashes; a manual sweep can be
  done only while the service is stopped (files in `temporary/` are not
  referenced by live records after recovery).
- Quarantined files are intentionally retained for forensics. Deleting them is
  an operator decision; there is no automatic quarantine TTL. Record tenant,
  download ID, verdict, and time before deletion.
- Approved files expire automatically. Never edit or replace files in the
  approved zone: checksums are verified before analysis and a mismatch fails
  the job.

## Restart and recovery semantics

- On startup, every non-terminal download is marked `FAILED` and its temp file
  swept; clients must resubmit. There is no download-idempotency key.
- Persisted `PENDING` analysis jobs are re-enqueued; `RUNNING` jobs are reset
  to `PENDING` and retried.
- Rate-limit buckets and in-flight concurrency counters reset.
- Multiple API replicas are not supported for correctness: locks, queue, and
  recovery are in-process.

## Backups

1. Stop writes (drain/stop the service) or snapshot consistently.
2. Back up the database (`sqlite3 .backup` or `pg_dump`).
3. Back up `approved/` and `quarantine/` as required by retention policy.
4. Restore: place database and zones, start the service, verify readiness and
   checksum-based analysis on a sample download.

No automated backup/restore is implemented; this is an operational
responsibility (R20).

## Incident response

- **Suspected SSRF/egress abuse:** disable downloads by removing the proxy
  attestation or stopping the service; preserve logs and DB rows for the
  affected `download_id`s; review proxy logs; do not relax IP policy.
- **Malware found:** keep the file in quarantine, record the ClamAV signature,
  trace the origin URL/tenant from metadata, and review other downloads from
  the same origin.
- **Credential exposure:** rotate `API_AUTH_TOKEN`, `PROXY_AUTH_TOKEN`,
  `ANALYSIS_API_TOKEN`, and the DB password; redeploy. Logs contain no
  credentials, but rotate regardless.
- **Storage integrity event (`CHECKSUM_MISMATCH`):** treat the approved zone as
  suspect; stop the service and verify volume integrity before resuming.

## Metrics and alerting gaps

The service emits structured logs and readiness states but no Prometheus
endpoint or histograms. Recommended external alerts: readiness failures,
`download_approved` rate, analysis failure rate by code, proxy attestation
failures, clamd unavailability, free disk on `STORAGE_ROOT`, and 5xx rate.
Adding a metrics exporter is future work.
