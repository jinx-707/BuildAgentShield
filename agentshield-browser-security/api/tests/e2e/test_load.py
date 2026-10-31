"""Bounded load test: 100 navigations, 10 concurrent, real Chromium."""

from __future__ import annotations

import json
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from .helpers import API_TOKEN, ApiClient, FixtureSite, Stack

pytestmark = [pytest.mark.e2e, pytest.mark.load]

TOTAL_REQUESTS = 100
CONCURRENCY = 10


def _rss_kib(pid: int) -> int | None:
    try:
        output = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(pid)], text=True
        ).strip()
        return int(output) if output else None
    except (subprocess.SubprocessError, ValueError):
        return None


def _process_tree(pid: int) -> tuple[int, int]:
    try:
        output = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,rss="], text=True
        )
    except subprocess.SubprocessError:
        return 0, 0
    rows: dict[int, tuple[int, int]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        try:
            child, parent, rss = (int(part) for part in parts)
        except ValueError:
            continue
        rows[child] = (parent, rss)
    total = 0
    count = 0
    pending = [pid]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current != pid and current in rows:
            total += rows[current][1]
            count += 1
        for child, (parent, _) in rows.items():
            if parent == current and child not in seen:
                pending.append(child)
    return total, count


def test_bounded_navigation_load(
    functional_stack: Stack, fixture_site: FixtureSite
) -> None:
    url = fixture_site.url("/page")

    def one(index: int) -> tuple[bool, float, int]:
        started = time.perf_counter()
        try:
            with httpx.Client(timeout=httpx.Timeout(60.0)) as client:
                response = client.post(
                    f"{functional_stack.api_url}/v1/browser/navigate",
                    json={
                        "url": url,
                        "wait_until": "domcontentloaded",
                        "timeout_ms": 30000,
                    },
                    headers={
                        "Authorization": f"Bearer {API_TOKEN}",
                        "X-Agent-ID": f"load-agent-{index % 5}",
                    },
                )
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return response.status_code == 200, elapsed_ms, response.status_code
        except httpx.HTTPError:
            return False, (time.perf_counter() - started) * 1000.0, 0

    api_pid = functional_stack.apis[0].service.process.pid
    worker_pid = functional_stack.worker.service.process.pid
    before_api = _rss_kib(api_pid)
    before_worker = _rss_kib(worker_pid)
    before_tree, before_tree_count = _process_tree(worker_pid)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        results = list(pool.map(one, range(TOTAL_REQUESTS)))
    wall_seconds = time.perf_counter() - started

    after_api = _rss_kib(api_pid)
    after_worker = _rss_kib(worker_pid)
    after_tree, after_tree_count = _process_tree(worker_pid)

    latencies = sorted(latency for _, latency, _ in results)
    successes = sum(1 for ok, _, _ in results if ok)
    status_counts: dict[str, int] = {}
    for _, _, status in results:
        status_counts[str(status)] = status_counts.get(str(status), 0) + 1

    def percentile(value: float) -> float:
        index = min(len(latencies) - 1, int(round(value * (len(latencies) - 1))))
        return latencies[index]

    report = {
        "total_requests": TOTAL_REQUESTS,
        "concurrency": CONCURRENCY,
        "successes": successes,
        "error_rate": round((TOTAL_REQUESTS - successes) / TOTAL_REQUESTS, 4),
        "status_counts": status_counts,
        "wall_seconds": round(wall_seconds, 3),
        "throughput_rps": round(TOTAL_REQUESTS / wall_seconds, 3),
        "latency_ms": {
            "min": round(latencies[0], 2),
            "p50": round(percentile(0.50), 2),
            "p95": round(percentile(0.95), 2),
            "p99": round(percentile(0.99), 2),
            "max": round(latencies[-1], 2),
            "mean": round(statistics.mean(latencies), 2),
        },
        "rss_kib": {
            "api_before": before_api,
            "api_after": after_api,
            "worker_before": before_worker,
            "worker_after": after_worker,
            "worker_tree_before": before_tree,
            "worker_tree_after": after_tree,
            "worker_tree_processes_before": before_tree_count,
            "worker_tree_processes_after": after_tree_count,
        },
    }
    print("LOAD_REPORT " + json.dumps(report, sort_keys=True))

    assert successes == TOTAL_REQUESTS, report
    assert report["latency_ms"]["p95"] < 30000, report
