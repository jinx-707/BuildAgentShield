"""Mock Metadata Service for AgentShield Cyber Range.

Simulates cloud metadata endpoint (like 169.254.169.254) for SSRF testing.
"""

from __future__ import annotations

import os
import structlog
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from pydantic_settings import BaseSettings

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    MOCK_HOST: str = "0.0.0.0"
    MOCK_PORT: int = 8088

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("mock_metadata_started")
    yield
    logger.info("mock_metadata_stopped")


app = FastAPI(title="Mock Metadata Service", lifespan=lifespan)


METADATA = {
    "instance-id": "mock-i-0abcdef1234567890",
    "instance-type": "t3.micro",
    "ami-id": "ami-mock123456",
    "local-ipv4": "10.0.1.100",
    "public-ipv4": "203.0.113.50",
    "security-groups": ["sg-mock123"],
    "iam-role": "mock-role",
    "account-id": "123456789012",
    "region": "us-east-1",
    "availability-zone": "us-east-1a",
}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "mock-metadata"}


@app.get("/")
async def root():
    return METADATA


@app.get("/latest/meta-data/{path:path}")
async def metadata_path(path: str, request: Request):
    keys = path.split("/")
    data = METADATA
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return {"error": "Not found"}, 404
    return data


@app.get("/latest/user-data")
async def user_data():
    return "#cloud-config\npackages: []\nruncmd: []"


@app.get("/latest/dynamic/instance-identity/document")
async def identity_document():
    return {
        "instanceId": "mock-i-0abcdef1234567890",
        "instanceType": "t3.micro",
        "region": "us-east-1",
        "accountId": "123456789012",
        "architecture": "x86_64",
        "availabilityZone": "us-east-1a",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.MOCK_HOST, port=settings.MOCK_PORT)