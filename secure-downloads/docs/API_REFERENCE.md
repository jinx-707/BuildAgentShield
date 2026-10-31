# API Reference

Base path: `/`. Content type: `application/json` unless noted.

## Common requirements

| Header | Required | Notes |
|---|---|---|
| `Authorization: Bearer <token>` | Yes for `/online/*` | `API_AUTH_TOKEN`; health endpoints are exempt |
| `X-Tenant-ID` | Yes for every `/online/*` endpoint | 1–128 characters; scopes every read and write |
| `X-Request-ID` | No | Echoed if it matches `^[A-Za-z0-9._:-]{1,128}$`; otherwise replaced |

Every response carries `X-Request-ID`. A request rejected by auth still gets
one and is still counted against the rate-limit budget.

Rate limiting (when enabled): `RATE_LIMIT_PER_MINUTE` per client IP **and** per
tenant. A `429` includes `Retry-After` (seconds) and body
`{"error":"rate_limit_exceeded","code":"RATE_LIMIT_EXCEEDED",...}`.

Errors from domain logic use:

```json
{
  "error": "download_error",
  "code": "INVALID_STATE",
  "message": "Only APPROVED downloads can be analyzed. Current state: SCANNING."
}
```

`message` is safe to surface. No storage paths, document bytes, extracted
text, tokens, proxy credentials, or raw provider responses appear in any
error. Foreign-tenant and unknown download IDs both return `404` with the
same shape.

## Endpoints

### POST /online/downloads

Start a download. Async; poll the status endpoint. Returns `202`.

Request:

```json
{
  "url": "https://files.example.com/report.pdf",
  "agent_id": "agent-42"
}
```

`url` must be HTTPS and satisfy the configured domain/port policy. `agent_id`
is 1–128 characters.

`202` response (`DownloadStatusResponse`):

```json
{
  "download_id": "5b1c…",
  "tenant_id": "tenant-a",
  "agent_id": "agent-42",
  "state": "PENDING",
  "created_at": "2026-10-31T10:00:00Z",
  "updated_at": "2026-10-31T10:00:00Z",
  "expires_at": null,
  "failure_reason": null
}
```

Errors: `401` auth; `422` missing tenant/invalid body; `403` with a URL policy
code (e.g. `DOMAIN_BLOCKED`, `PRIVATE_IP_BLOCKED`, `PORT_NOT_ALLOWED`);
`429` `CONCURRENCY_LIMIT_EXCEEDED` or rate limit; `500` internal error.

### GET /online/downloads/{download_id}/status

Returns `DownloadStatusResponse`. States: `PENDING`, `VALIDATING`,
`DOWNLOADING`, `DOWNLOADED`, `VERIFYING`, `SCANNING`, `APPROVED`,
`QUARANTINED`, `REJECTED`, `FAILED`, `EXPIRED`.

Errors: `404` if unknown or owned by another tenant.

### GET /online/downloads/{download_id}/metadata

Returns download metadata plus an analysis summary. Never includes
`storage_ref` or any filesystem path.

```json
{
  "download_id": "5b1c…",
  "tenant_id": "tenant-a",
  "agent_id": "agent-42",
  "original_url": "https://files.example.com/report.pdf",
  "state": "APPROVED",
  "original_filename": "report.pdf",
  "detected_mime_type": "application/pdf",
  "file_size": 12345,
  "file_sha256": "9f2c…",
  "scan_result": "CLEAN",
  "scan_detail": null,
  "created_at": "…",
  "updated_at": "…",
  "expires_at": "…",
  "failure_reason": null,
  "handoff_completed": false,
  "analysis_id": null,
  "analysis_state": null,
  "analysis_provider": null
}
```

Errors: `404` if unknown/foreign.

### POST /online/downloads/{download_id}/scan

Request a scan if the download is `DOWNLOADED`. Idempotent: if it has already
progressed, the current record is returned unchanged and no second scan runs.

```json
{
  "download_id": "5b1c…",
  "state": "DOWNLOADED",
  "scan_result": null,
  "scan_detail": null,
  "message": "Scan triggered."
}
```

Errors: `404`; `409 INVALID_STATE` when the record is not downloadable and not
yet scannable.

### POST /online/downloads/{download_id}/analysis

Create the analysis job. Requires `APPROVED`. Returns `202` and the job.
Idempotent per download: repeated calls return the existing job (a unique
index on `download_id` guarantees one row) and never resubmit.

`AnalysisJobResponse`:

```json
{
  "analysis_id": "…",
  "download_id": "5b1c…",
  "tenant_id": "tenant-a",
  "state": "PENDING",
  "provider": "http",
  "correlation_id": "…",
  "attempts": 0,
  "retryable": null,
  "error_code": null,
  "error_detail": null,
  "provider_analysis_id": null,
  "created_at": "…",
  "updated_at": "…",
  "completed_at": null
}
```

`error_detail` is fixed service text, never provider output.

Errors: `404`; `409 ANALYSIS_DISABLED` (provider mode `disabled`),
`409 INVALID_STATE` (not `APPROVED`).

### GET /online/downloads/{download_id}/analysis

Job status, same schema. States: `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`,
`CANCELLED`.

Errors: `404` if no job or foreign tenant.

### GET /online/downloads/{download_id}/analysis/result

Returns the stored normalized result only when the job is `COMPLETED`.
Otherwise `409 ANALYSIS_NOT_COMPLETED`.

The result separates locally derived facts (`document_type`, `page_count`,
`extracted_text`, `text_truncated`) from sanitized provider fields (`summary`,
`findings`, `confidence`, `provider_metadata`, `provider_document_type`,
`provider_analysis_id`, `provider_correlation_id`) and provenance
(`download_id`, `analysis_id`, `provider`, `schema_version`, `sha256`,
`processed_at`, `created_at`, `warnings`). It never contains storage paths,
document bytes, credentials, or raw provider payloads.

Note: `extracted_text` is document-derived content and is returned only from
this endpoint to the owning tenant. It is never logged.

### POST /online/downloads/{download_id}/analysis/retry

Re-enqueue a `FAILED`, retryable job with attempts remaining. Returns `202`.
Errors: `404`; `409 INVALID_STATE` (not failed), `409 ANALYSIS_NOT_RETRYABLE`
(non-retryable or attempts exhausted), `409 ANALYSIS_DISABLED`.

## Health

### GET /health/live

No auth. Always `200 {"status":"ok"}` while the event loop answers. Ignores
configuration and dependencies.

### GET /health/ready

No auth. `200` only when all checks pass; else `503`.

```json
{
  "status": "ready",
  "service": "agentshield-secure-downloads",
  "checks": {
    "security_configuration": "ok",
    "egress_proxy": "enforcing",
    "database": "ok",
    "storage": "ok",
    "scanner": "available"
  },
  "issues": []
}
```

`egress_proxy` values: `enforcing`, `unattestable`, `not_configured`,
`not_required`, `not_enforcing`. `scanner`: `available`/`unavailable`.
`storage`: `ok`/`error`. `database`: `ok`/`unreachable`.

`issues` lists configuration-variable names and dependency conditions only.

## Status codes

| Code | Meaning |
|---|---|
| `200` | Success |
| `202` | Accepted (async download/analysis/retry) |
| `401` | Missing/invalid bearer token |
| `403` | Domain/URL/SSRF/policy rejection |
| `404` | Unknown or foreign-tenant download/job |
| `409` | Invalid state, analysis disabled, not completed, not retryable |
| `422` | Missing/invalid request body or `X-Tenant-ID` |
| `429` | Rate limit or per-tenant concurrency limit |
| `500` | Internal error (fixed message) |
| `503` | Not ready |

## Not provided

- File retrieval/download of approved content.
- Download cancellation.
- Download idempotency keys.
- Listing endpoints.
- Analysis job cancellation API.
