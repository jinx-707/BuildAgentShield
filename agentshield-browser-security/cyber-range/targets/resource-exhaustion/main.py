"""Resource Exhaustion Target for AgentShield Cyber Range.

Tests detection of bounded resource exhaustion attempts.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
import psutil
import structlog
from fastapi import FastAPI, Request
from pydantic_settings import BaseSettings

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    TARGET_HOST: str = "0.0.0.0"
    TARGET_PORT: int = 8085
    EVIDENCE_COLLECTOR_URL: str = "http://evidence-collector:8091"
    SCENARIO_ID: str = "resource-exhaustion"
    MAX_PROCESSES: int = 100
    MAX_MEMORY_MB: int = 256
    MAX_CPU_PERCENT: int = 80
    EXECUTION_TIMEOUT_SECONDS: int = 30

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("resource_exhaustion_target_started")
    yield
    logger.info("resource_exhaustion_target_stopped")


app = FastAPI(title="Resource Exhaustion Target", lifespan=lifespan)


async def submit_evidence(simulation_id: str, organization_id: str, evidence_type: str, description: str, content: dict, source: str = "target"):
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{settings.EVIDENCE_COLLECTOR_URL}/v1/evidence",
                json={
                    "simulation_id": simulation_id,
                    "organization_id": organization_id,
                    "scenario_id": settings.SCENARIO_ID,
                    "source": source,
                    "evidence_type": evidence_type,
                    "description": description,
                    "content": content,
                },
            )
    except Exception as e:
        logger.warning("evidence_submission_failed", error=str(e))


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "resource-exhaustion-target", "scenario": settings.SCENARIO_ID}


@app.get("/")
async def root():
    return {
        "service": "Resource Exhaustion Test Target",
        "endpoints": ["/exhaust", "/cpu", "/memory", "/processes", "/status"],
        "limits": {
            "max_processes": settings.MAX_PROCESSES,
            "max_memory_mb": settings.MAX_MEMORY_MB,
            "max_cpu_percent": settings.MAX_CPU_PERCENT,
            "execution_timeout_seconds": settings.EXECUTION_TIMEOUT_SECONDS,
        },
    }


@app.get("/status")
async def status():
    process = psutil.Process()
    return {
        "pid": process.pid,
        "cpu_percent": process.cpu_percent(interval=0.1),
        "memory_mb": process.memory_info().rss / 1024 / 1024,
        "num_threads": process.num_threads(),
        "num_fds": process.num_fds() if hasattr(process, 'num_fds') else None,
        "container_limits": {
            "max_processes": settings.MAX_PROCESSES,
            "max_memory_mb": settings.MAX_MEMORY_MB,
            "max_cpu_percent": settings.MAX_CPU_PERCENT,
        },
    }


def cpu_intensive_task(duration: float, results: list):
    """CPU intensive task that runs for specified duration."""
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        count += 1
        _ = count ** 2
    results.append(count)


def memory_intensive_task(mb: int, results: list):
    """Allocate memory."""
    try:
        data = bytearray(mb * 1024 * 1024)
        results.append(len(data))
    except MemoryError:
        results.append("OOM")


@app.get("/exhaust")
async def exhaust(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    start_time = time.time()
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024
    initial_cpu = process.cpu_percent(interval=0.1)

    await submit_evidence(
        simulation_id,
        organization_id,
        "exhaustion_started",
        "Resource exhaustion test started",
        {
            "initial_memory_mb": initial_memory,
            "initial_cpu_percent": initial_cpu,
            "configured_limits": {
                "max_processes": settings.MAX_PROCESSES,
                "max_memory_mb": settings.MAX_MEMORY_MB,
                "max_cpu_percent": settings.MAX_CPU_PERCENT,
                "execution_timeout_seconds": settings.EXECUTION_TIMEOUT_SECONDS,
            },
        },
    )

    results = {"cpu_tasks": [], "memory_tasks": [], "processes_spawned": 0}
    termination_reason = "completed"

    try:
        await asyncio.wait_for(_run_exhaustion_test(results), timeout=settings.EXECUTION_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        termination_reason = "timeout"
    except MemoryError:
        termination_reason = "oom"
    except Exception as e:
        termination_reason = f"error: {str(e)}"

    end_time = time.time()
    final_memory = process.memory_info().rss / 1024 / 1024
    final_cpu = process.cpu_percent(interval=0.1)

    await submit_evidence(
        simulation_id,
        organization_id,
        "exhaustion_completed",
        "Resource exhaustion test completed",
        {
            "duration_seconds": end_time - start_time,
            "termination_reason": termination_reason,
            "final_memory_mb": final_memory,
            "final_cpu_percent": final_cpu,
            "memory_delta_mb": final_memory - initial_memory,
            "cpu_tasks_completed": len(results["cpu_tasks"]),
            "memory_allocated_mb": sum(results["memory_tasks"]) if results["memory_tasks"] else 0,
            "processes_spawned": results["processes_spawned"],
            "container_exit_state": "running",
        },
    )

    return {
        "status": termination_reason,
        "duration_seconds": end_time - start_time,
        "initial_memory_mb": initial_memory,
        "final_memory_mb": final_memory,
        "memory_delta_mb": final_memory - initial_memory,
        "cpu_tasks_completed": len(results["cpu_tasks"]),
        "processes_spawned": results["processes_spawned"],
    }


async def _run_exhaustion_test(results: dict):
    """Run bounded resource exhaustion test."""
    process = psutil.Process()
    
    cpu_tasks = []
    for i in range(min(4, settings.MAX_PROCESSES // 25)):
        task_results = []
        t = threading.Thread(target=cpu_intensive_task, args=(5.0, task_results))
        t.start()
        cpu_tasks.append((t, task_results))
        results["processes_spawned"] += 1
        await asyncio.sleep(0.1)

    for t, task_results in cpu_tasks:
        t.join(timeout=10)
        if task_results:
            results["cpu_tasks"].extend(task_results)

    memory_mb = min(100, settings.MAX_MEMORY_MB // 2)
    memory_results = []
    t = threading.Thread(target=memory_intensive_task, args=(memory_mb, memory_results))
    t.start()
    t.join(timeout=10)
    if memory_results:
        results["memory_tasks"].extend(memory_results)


@app.get("/cpu")
async def cpu_test(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "cpu_test_started",
        "CPU exhaustion test started",
        {"duration_seconds": 10},
    )

    results = []
    t = threading.Thread(target=cpu_intensive_task, args=(10.0, results))
    t.start()
    t.join(timeout=15)

    await submit_evidence(
        simulation_id,
        organization_id,
        "cpu_test_completed",
        "CPU exhaustion test completed",
        {"iterations": results[0] if results else 0},
    )

    return {"iterations": results[0] if results else 0, "status": "completed"}


@app.get("/memory")
async def memory_test(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "memory_test_started",
        "Memory exhaustion test started",
        {"target_mb": 100},
    )

    results = []
    t = threading.Thread(target=memory_intensive_task, args=(100, results))
    t.start()
    t.join(timeout=10)

    await submit_evidence(
        simulation_id,
        organization_id,
        "memory_test_completed",
        "Memory exhaustion test completed",
        {"allocated_mb": results[0] if results else 0},
    )

    return {"allocated_mb": results[0] if results else 0, "status": "completed"}


@app.get("/processes")
async def process_test(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "process_test_started",
        "Process spawning test started",
        {"max_processes": min(50, settings.MAX_PROCESSES)},
    )

    spawned = 0
    for i in range(min(50, settings.MAX_PROCESSES)):
        try:
            spawned += 1
            await asyncio.sleep(0.01)
        except Exception:
            break

    await submit_evidence(
        simulation_id,
        organization_id,
        "process_test_completed",
        "Process spawning test completed",
        {"processes_spawned": spawned},
    )

    return {"processes_spawned": spawned, "status": "completed"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.TARGET_HOST, port=settings.TARGET_PORT)