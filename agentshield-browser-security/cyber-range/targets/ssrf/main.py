"""SSRF Target for AgentShield Cyber Range.

Tests SSRF protection against mock internal metadata service.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pydantic_settings import BaseSettings

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    TARGET_HOST: str = "0.0.0.0"
    TARGET_PORT: int = 8083
    EVIDENCE_COLLECTOR_URL: str = "http://evidence-collector:8091"
    SCENARIO_ID: str = "ssrf"
    MOCK_METADATA_URL: str = "http://mock-metadata:8088"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ssrf_target_started")
    yield
    logger.info("ssrf_target_stopped")


app = FastAPI(title="SSRF Target", lifespan=lifespan)


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
    return {"status": "healthy", "service": "ssrf-target", "scenario": settings.SCENARIO_ID}


@app.get("/")
async def root():
    return {"service": "SSRF Test Target", "endpoints": ["/ssrf", "/redirect", "/fetch"]}


@app.get("/ssrf")
async def ssrf_endpoint(request: Request, target: str = Query(...)):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    resolved_ip = None
    try:
        import socket
        from urllib.parse import urlparse
        parsed = urlparse(target)
        if parsed.hostname:
            resolved_ip = socket.gethostbyname(parsed.hostname)
    except Exception:
        pass

    await submit_evidence(
        simulation_id,
        organization_id,
        "ssrf_attempt",
        "SSRF attempt received",
        {
            "requested_target": target,
            "resolved_ip": resolved_ip,
            "source_ip": request.client.host if request.client else None,
        },
    )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(target)
            return {"status": "fetched", "target": target, "resolved_ip": resolved_ip, "response_status": resp.status_code, "response_length": len(resp.text)}
    except Exception as e:
        return {"status": "error", "target": target, "resolved_ip": resolved_ip, "error": str(e)}


@app.get("/redirect")
async def redirect_endpoint(request: Request, to: str = Query(...)):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    resolved_ip = None
    try:
        import socket
        from urllib.parse import urlparse
        parsed = urlparse(to)
        if parsed.hostname:
            resolved_ip = socket.gethostbyname(parsed.hostname)
    except Exception:
        pass

    await submit_evidence(
        simulation_id,
        organization_id,
        "redirect_attempt",
        "Redirect-based SSRF attempt",
        {
            "redirect_target": to,
            "resolved_ip": resolved_ip,
            "initial_url": str(request.url),
        },
    )

    return {"redirect_to": to, "resolved_ip": resolved_ip, "note": "This is a redirect test; actual fetch would follow redirect"}


@app.get("/fetch")
async def fetch_endpoint(request: Request, url: str = Query(...)):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "fetch_attempt",
        "Direct fetch attempt",
        {"url": url},
    )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            return {"fetched": True, "url": url, "status": resp.status_code, "content_length": len(resp.content)}
    except Exception as e:
        return {"fetched": False, "url": url, "error": str(e)}


@app.get("/metadata")
async def mock_metadata(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "metadata_accessed",
        "Mock metadata endpoint accessed directly",
        {"endpoint": "/metadata", "source_ip": request.client.host if request.client else None},
    )

    return {
        "instance-id": "mock-i-0abcdef1234567890",
        "instance-type": "t3.micro",
        "ami-id": "ami-mock123456",
        "local-ipv4": "10.0.1.100",
        "public-ipv4": "203.0.113.50",
        "security-groups": ["sg-mock123"],
        "iam-role": "mock-role",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.TARGET_HOST, port=settings.TARGET_PORT)