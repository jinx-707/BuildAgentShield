# Performance Report

**Date:** 2026-10-31  
**Scope:** Bounded local load test, not a production capacity benchmark.

## Method

`api/tests/e2e/test_load.py` starts the real functional stack and issues:

- **100** navigations to the local fixture `/page`
- **Concurrency 10**
- `wait_until=domcontentloaded`
- 30-second per-request client timeout
- Real Chromium, worker, proxy, API, and fixture origin

The test asserts:

- all requests return `200`
- error rate is zero
- p95 latency is below 30 seconds
- a JSON `LOAD_REPORT` is printed

Run:

```bash
cd api
RUN_E2E=1 .venv/bin/python -m pytest tests/e2e/test_load.py -v -s
```

## Latest result

```json
{
  "concurrency": 10,
  "total_requests": 100,
  "successes": 100,
  "status_counts": {"200": 100},
  "error_rate": 0.0,
  "wall_seconds": 19.749,
  "throughput_rps": 5.063,
  "latency_ms": {
    "min": 455.58,
    "mean": 1942.46,
    "p50": 1842.91,
    "p95": 2912.98,
    "p99": 2941.29,
    "max": 2941.3
  },
  "rss_kib": {
    "api_before": 40384,
    "api_after": 33984,
    "worker_before": 40464,
    "worker_after": 56432,
    "worker_tree_before": 480608,
    "worker_tree_after": 551792,
    "worker_tree_processes_before": 6,
    "worker_tree_processes_after": 8
  }
}
```

## Earlier run

A prior run of the same test produced:

- Wall time: **17.32 s**
- Throughput: **5.774 rps**
- p50: **1461.07 ms**
- p95: **3321.3 ms**
- p99: **3400.58 ms**
- max: **3402.34 ms**
- Error rate: **0.0**

The variance between runs is consistent with local Chromium startup, page settling, and host scheduling noise.

## Interpretation

- The stack sustained 10 concurrent real browser navigations with no errors.
- Observed throughput was roughly **5 rps** on this local machine for this fixture.
- p95 was approximately **2.9–3.3 s**; p99 was approximately **2.9–3.4 s**.
- API RSS did not grow in the latest run (it decreased from about 39.5 MiB to 33.2 MiB).
- Worker process RSS grew from about 39.5 MiB to 55.1 MiB.
- The worker **process tree** grew from about 469 MiB to about 539 MiB and from 6 to 8 processes. Chromium children dominate memory; worker RSS alone understates resource use.

## Limitations

- This is a local macOS run against a loopback fixture, not a production network or container run.
- It is a short burst, not a soak or endurance test.
- It does not test Redis contention, multiple API replicas under load, multiple workers, or session affinity.
- It does not establish a production SLA or capacity limit.
- The test does not force garbage collection or measure long-term leak behavior.
- Docker/Compose runtime behavior was not measured.

## Recommendations

1. Size containers for the full Chromium process tree, not just the Node worker process.
2. Run a longer soak test with session create/use/close cycles before production.
3. Load-test Redis with the expected number of API replicas and realistic category limits.
4. Measure with production TLS termination, reverse proxy, and network latency.
5. Add process-tree memory and Chromium child-count metrics to monitoring.
6. Re-run after Chromium or Puppeteer upgrades; browser memory behavior changes across versions.
