"""Malicious Download Target for AgentShield Cyber Range.

Serves synthetic malicious files to test download inspection and quarantine.
"""

from __future__ import annotations

import os
import base64
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse
from pydantic_settings import BaseSettings

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    TARGET_HOST: str = "0.0.0.0"
    TARGET_PORT: int = 8084
    EVIDENCE_COLLECTOR_URL: str = "http://evidence-collector:8091"
    SCENARIO_ID: str = "malicious-download"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()


# EICAR test signature (harmless test string)
EICAR_SIGNATURE = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# Fake executable content
FAKE_EXE = b'MZ\x90\x00' + b'\x00' * 100 + b'This is a synthetic executable for testing'

# Oversized file (10MB)
OVERSIZED_CONTENT = b'X' * (10 * 1024 * 1024)

# Mismatched MIME: claims to be PDF but is executable
MISMATCHED_CONTENT = b'%PDF-1.4\n' + FAKE_EXE

# Suspicious archive with fake metadata
SUSPICIOUS_ZIP = b'PK\x03\x04' + b'\x00' * 50 + b'suspicious.exe'


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("malicious_download_target_started")
    yield
    logger.info("malicious_download_target_stopped")


app = FastAPI(title="Malicious Download Target", lifespan=lifespan)


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
    return {"status": "healthy", "service": "malicious-download-target", "scenario": settings.SCENARIO_ID}


@app.get("/")
async def root():
    return {
        "service": "Malicious Download Test Target",
        "files": [
            "/download/eicar.txt",
            "/download/fake.exe",
            "/download/oversized.bin",
            "/download/mismatched.pdf",
            "/download/suspicious.zip",
            "/download/benign.txt",
        ],
    }


@app.get("/download/eicar.txt")
async def download_eicar(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "eicar_downloaded",
        "EICAR test signature file downloaded",
        {
            "filename": "eicar.txt",
            "content_type": "text/plain",
            "size": len(EICAR_SIGNATURE),
            "signature": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            "harmless": True,
        },
    )

    return Response(
        content=EICAR_SIGNATURE,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="eicar.txt"'},
    )


@app.get("/download/fake.exe")
async def download_fake_exe(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "executable_downloaded",
        "Synthetic executable file downloaded",
        {
            "filename": "malware.exe",
            "content_type": "application/octet-stream",
            "size": len(FAKE_EXE),
            "mime_matches_extension": True,
            "has_mz_header": FAKE_EXE.startswith(b'MZ'),
        },
    )

    return Response(
        content=FAKE_EXE,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="malware.exe"'},
    )


@app.get("/download/oversized.bin")
async def download_oversized(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "oversized_downloaded",
        "Oversized test file downloaded",
        {
            "filename": "large.bin",
            "content_type": "application/octet-stream",
            "size": len(OVERSIZED_CONTENT),
            "exceeds_typical_limit_mb": 10,
        },
    )

    return Response(
        content=OVERSIZED_CONTENT,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="large.bin"'},
    )


@app.get("/download/mismatched.pdf")
async def download_mismatched(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "mime_mismatch_downloaded",
        "MIME type mismatch file downloaded",
        {
            "filename": "document.pdf",
            "declared_content_type": "application/pdf",
            "actual_content_type": "application/octet-stream",
            "size": len(MISMATCHED_CONTENT),
            "has_pdf_header": MISMATCHED_CONTENT.startswith(b'%PDF'),
            "has_exe_content": b'MZ' in MISMATCHED_CONTENT,
        },
    )

    return Response(
        content=MISMATCHED_CONTENT,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="document.pdf"'},
    )


@app.get("/download/suspicious.zip")
async def download_suspicious_zip(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "suspicious_archive_downloaded",
        "Suspicious archive with executable content downloaded",
        {
            "filename": "archive.zip",
            "content_type": "application/zip",
            "size": len(SUSPICIOUS_ZIP),
            "has_zip_header": SUSPICIOUS_ZIP.startswith(b'PK'),
            "contains_exe_name": "suspicious.exe" in SUSPICIOUS_ZIP.decode(errors='ignore'),
        },
    )

    return Response(
        content=SUSPICIOUS_ZIP,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="archive.zip"'},
    )


@app.get("/download/benign.txt")
async def download_benign(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    benign_content = b"This is a completely benign text file for testing allowed downloads."

    await submit_evidence(
        simulation_id,
        organization_id,
        "benign_downloaded",
        "Benign file downloaded",
        {
            "filename": "readme.txt",
            "content_type": "text/plain",
            "size": len(benign_content),
        },
    )

    return Response(
        content=benign_content,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="readme.txt"'},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.TARGET_HOST, port=settings.TARGET_PORT)