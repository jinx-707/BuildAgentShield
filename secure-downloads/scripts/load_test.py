#!/usr/bin/env python3
"""
Bounded local load measurement for the secure-download API.

This is a LOCAL measurement tool, not a capacity model.  It runs uvicorn on
loopback, downloads a small valid PDF from a local TLS origin, and records
latency, throughput, failures, peak RSS and storage cleanup for a fixed,
small number of requests.  Results must not be extrapolated to production:
the origin, database (SQLite file), scanner (scripted stand-in) and network
are all local, and the API process and load generator share one machine.

Usage:
    .venv/bin/python scripts/load_test.py --requests 40 --concurrency 8

The scanner is a scripted clean verdict, clearly distinct from a real ClamAV
integration.  The analysis provider is disabled.  Nothing leaves the machine.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import resource
import shutil
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Must be set before importing api.app, whose module-level factory constructs
# settings from the environment.
os.environ.setdefault("ENVIRONMENT", "test")

import httpx  # noqa: E402
import uvicorn  # noqa: E402

from api.app import create_app  # noqa: E402
from config.settings import Settings  # noqa: E402
from tests.integration.raw_http import closed_port  # noqa: E402
from tests.integration.tls_http import TlsRawServer, generate_self_signed_cert  # noqa: E402
from tests.pdf_fixtures import make_pdf  # noqa: E402

API_TOKEN = "load-test-token"
TENANT = "tenant-load"
PDF_BYTES = make_pdf(("Load test document",))


class ScriptedCleanScanner:
    """Stand-in scanner: always CLEAN.  NOT a real ClamAV integration."""

    async def scan(self, file_path: Path):
        from services.scanner import ScanResult, ScanVerdict

        return ScanResult(verdict=ScanVerdict.CLEAN)

    async def is_available(self) -> bool:
        return True


def _serve_pdf(handler) -> None:
    handler.write_raw(
        "200 OK",
        [
            ("Content-Type", "application/pdf"),
            ("Content-Length", str(len(PDF_BYTES))),
            ("Content-Disposition", 'attachment; filename="load.pdf"'),
        ],
        PDF_BYTES,
        close=True,
    )


def _rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes; Linux reports KiB.
    return value if value > 10_000_000 else value * 1024


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def _zone_files(storage_root: Path, zone: str) -> list[Path]:
    directory = storage_root / zone
    return sorted(p for p in directory.iterdir() if p.is_file()) if directory.is_dir() else []


def start_api(settings: Settings) -> tuple[uvicorn.Server, threading.Thread, int]:
    app = create_app(settings)
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        log_level="warning",
        lifespan="on",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="load-api")
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    scanner = ScriptedCleanScanner()
    app.state.orchestrator._scanner = scanner  # type: ignore[attr-defined]
    app.state.scanner = scanner
    return server, thread, port


async def run_requests(base_url: str, origin_url: str, requests: int, concurrency: int) -> dict:
    headers = {"Authorization": f"Bearer {API_TOKEN}", "X-Tenant-ID": TENANT}
    submit_latencies: list[float] = []
    end_to_end: list[float] = []
    failures: list[dict] = []
    semaphore = asyncio.Semaphore(concurrency)
    client = httpx.AsyncClient(base_url=base_url, timeout=60.0, trust_env=False)

    async def one(index: int) -> None:
        async with semaphore:
            started = time.perf_counter()
            try:
                resp = await client.post(
                    "/online/downloads",
                    headers=headers,
                    json={"url": origin_url, "agent_id": f"load-{index}"},
                )
            except Exception as exc:
                failures.append({"stage": "submit", "error": type(exc).__name__})
                return
            submit_latencies.append(time.perf_counter() - started)
            if resp.status_code != 202:
                failures.append({"stage": "submit", "status": resp.status_code, "body": resp.text[:200]})
                return

            download_id = resp.json()["download_id"]
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                status = await client.get(
                    f"/online/downloads/{download_id}/status", headers=headers
                )
                state = status.json().get("state")
                if state == "APPROVED":
                    end_to_end.append(time.perf_counter() - started)
                    return
                if state in {"REJECTED", "FAILED", "QUARANTINED", "EXPIRED"}:
                    failures.append(
                        {
                            "stage": "lifecycle",
                            "state": state,
                            "reason": status.json().get("failure_reason"),
                        }
                    )
                    return
                await asyncio.sleep(0.02)
            failures.append({"stage": "poll", "error": "timeout"})

    started_all = time.perf_counter()
    try:
        await asyncio.gather(*(one(i) for i in range(requests)))
    finally:
        await client.aclose()
    wall = time.perf_counter() - started_all

    def summary(values: list[float]) -> dict:
        if not values:
            return {"count": 0}
        return {
            "count": len(values),
            "mean_ms": round(statistics.fmean(values) * 1000, 2),
            "p50_ms": round(_percentile(values, 0.50) * 1000, 2),
            "p95_ms": round(_percentile(values, 0.95) * 1000, 2),
            "max_ms": round(max(values) * 1000, 2),
        }

    return {
        "requests": requests,
        "concurrency": concurrency,
        "wall_seconds": round(wall, 3),
        "throughput_req_per_sec": round(requests / wall, 2) if wall else 0.0,
        "submit_latency": summary(submit_latencies),
        "end_to_end_latency": summary(end_to_end),
        "successes": len(end_to_end),
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=40)
    parser.add_argument("--concurrency", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.requests <= 500:
        parser.error("--requests must be between 1 and 500 (bounded local run)")
    if not 1 <= args.concurrency <= 32:
        parser.error("--concurrency must be between 1 and 32")

    workdir = Path(tempfile.mkdtemp(prefix="secure-downloads-load-"))
    certfile, keyfile = generate_self_signed_cert(workdir)
    origin = TlsRawServer({"/load.pdf": _serve_pdf}, certfile=certfile, keyfile=keyfile)
    origin.certfile = certfile  # type: ignore[attr-defined]
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    os.environ["SSL_CERT_FILE"] = str(certfile)
    origin_port = origin.server_address[1]
    settings = Settings(
        _env_file=None,
        environment="test",
        log_level="WARNING",
        api_auth_token=API_TOKEN,
        database_url=f"sqlite+aiosqlite:///{workdir / 'load.db'}",
        storage_root=str(workdir / "storage"),
        egress_proxy_url="",
        require_egress_proxy=False,
        allowed_domains="",
        default_domain_policy="allow",
        allowed_ports=f"443,{origin_port}",
        allow_private_networks=True,
        dns_preflight_enabled=True,
        clamav_host="127.0.0.1",
        clamav_port=closed_port(),
        rate_limit_enabled=False,
        max_concurrent_downloads_per_tenant=max(args.concurrency, 8),
        analysis_provider="disabled",
        max_file_size_bytes=1_000_000,
        download_connect_timeout_seconds=5.0,
        download_read_timeout_seconds=5.0,
        download_total_timeout_seconds=20.0,
    )

    rss_before = _rss_bytes()
    server, thread, api_port = start_api(settings)
    origin_url = f"https://127.0.0.1:{origin_port}/load.pdf"
    try:
        result = asyncio.run(
            run_requests(
                f"http://127.0.0.1:{api_port}",
                origin_url,
                args.requests,
                args.concurrency,
            )
        )
        result["rss_before_mb"] = round(rss_before / 1024 / 1024, 1)
        result["rss_peak_mb"] = round(_rss_bytes() / 1024 / 1024, 1)
        result["storage"] = {
            "temporary_files": len(_zone_files(Path(settings.storage_root), "temporary")),
            "approved_files": len(_zone_files(Path(settings.storage_root), "approved")),
            "quarantine_files": len(_zone_files(Path(settings.storage_root), "quarantine")),
        }
        result["scanner"] = "scripted clean stand-in (NOT real ClamAV)"
        result["analysis_provider"] = "disabled"
        result["note"] = (
            "Local loopback measurement only; origin, SQLite, scanner and load "
            "generator share one machine. Do not extrapolate to production."
        )
        print(json.dumps(result, indent=2))
        ok = (
            not result["failures"]
            and result["successes"] == args.requests
            and result["storage"]["temporary_files"] == 0
            and result["storage"]["approved_files"] == result["successes"]
        )
        return 0 if ok else 1
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=10)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
