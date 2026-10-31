# Bounded Load and Performance Report

## What was measured

`scripts/load_test.py` starts the real FastAPI app under uvicorn on loopback,
serves a small valid PDF from a **local TLS origin**, and submits a fixed
number of downloads with a fixed concurrency. It records submit latency,
end-to-end (submit → `APPROVED`) latency, throughput, process RSS, failures,
and storage cleanup.

**This is not a capacity model.** The origin, network, database (single-file
SQLite), scanner, and load generator share one machine. The scanner is a
scripted `CLEAN` stand-in — **not ClamAV**. Analysis is disabled. Results must
not be extrapolated to production.

## Harness configuration

| Item | Value |
|---|---|
| Host | macOS (darwin/arm64), local loopback |
| Python | 3.15.0 |
| API | uvicorn, one worker process, no reload |
| Database | SQLite file |
| Origin | Local TLS server, one small PDF |
| Scanner | `ScriptedCleanScanner` (always CLEAN) |
| Analysis | Disabled |
| Rate limiting | Disabled (to measure pipeline, not the limiter) |
| Download concurrency cap | ≥ load concurrency |
| TLS | Self-signed certificate trusted via `SSL_CERT_FILE` |

Run:

```bash
.venv/bin/python scripts/load_test.py --requests 40 --concurrency 8
.venv/bin/python scripts/load_test.py --requests 100 --concurrency 16
```

The script exits non-zero unless every request succeeds and storage ends
clean (temp files 0, approved files == successes). It prints a JSON summary.

## Results

### 40 requests / concurrency 8

| Metric | Value |
|---|---|
| Throughput | 22.4 requests/s |
| Submit latency p50 | 30.07 ms |
| Submit latency p95 | 173.84 ms |
| End-to-end p50 | 256.41 ms |
| End-to-end p95 | 1134.8 ms |
| Failures | 0 / 40 |
| RSS before → after | 92.6 MB → 117.8 MB |
| Temp files after | 0 |
| Approved files after | 40 (all successes) |

### 100 requests / concurrency 16

| Metric | Value |
|---|---|
| Throughput | 26.43 requests/s |
| Submit latency p50 | 132.65 ms |
| Submit latency p95 | 405.71 ms |
| End-to-end p50 | 502.23 ms |
| End-to-end p95 | 1063.04 ms |
| End-to-end max | 2004.3 ms |
| Failures | 0 / 100 |
| RSS before → after | 91.5 MB → 117.3 MB |
| Temp files after | 0 |
| Approved files after | 100 |

## Interpretation

- The pipeline is stable at these bounded loads: no failures, no leaked temp
  files, and all successes ended in the approved zone.
- Latency grows with concurrency, consistent with a single event loop, SQLite
  writes, and per-download background tasks.
- Memory growth is modest (tens of MB) at these volumes; this says nothing
  about long-running multi-tenant behavior.
- The scripted scanner is effectively instantaneous. **A real ClamAV scan adds
  latency and CPU that these numbers do not include.**
- Local TLS and loopback eliminate real network latency, proxy hops, and
  provider calls.

## Not measured

- Real ClamAV throughput or signature-load impact.
- A real egress proxy hop.
- A real analysis provider (latency, rate limits, retries).
- PostgreSQL behavior, multi-process/multi-replica behavior.
- Sustained load, soak tests, memory leaks over hours.
- Disk exhaustion, quarantine growth, or database growth.
- Rate-limiter behavior under attack (measured separately in unit tests).

## Recommended next measurements (staging)

1. Repeat with real clamd and realistic document sizes.
2. Add one proxy hop and measure attestation cache effectiveness.
3. Run against PostgreSQL with the intended worker count.
4. Soak at expected steady-state plus headroom for ≥ 1 hour; watch RSS, DB
   size, temp/approved/quarantine growth.
5. Measure analysis-provider latency and retry behavior separately
   (provider-bound, not download-bound).
