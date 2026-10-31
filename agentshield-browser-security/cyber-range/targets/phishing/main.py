"""Phishing Target for AgentShield Cyber Range.

Serves synthetic phishing pages to test credential harvesting detection.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from pydantic_settings import BaseSettings

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    TARGET_HOST: str = "0.0.0.0"
    TARGET_PORT: int = 8082
    EVIDENCE_COLLECTOR_URL: str = "http://evidence-collector:8091"
    SCENARIO_ID: str = "phishing"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("phishing_target_started")
    yield
    logger.info("phishing_target_stopped")


app = FastAPI(title="Phishing Target", lifespan=lifespan)


PHISHING_LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login - AgentShield Services</title>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .login-form { background: #f5f5f5; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 500; }
        input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .security-notice { font-size: 12px; color: #666; text-align: center; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="login-form">
        <h1>🔐 Secure Portal</h1>
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Email Address</label>
                <input type="email" id="username" name="username" placeholder="user@company.com" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required autocomplete="current-password">
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div class="security-notice">
            This is a synthetic phishing page for security testing. No real credentials are collected.
        </div>
    </div>
</body>
</html>
"""

PHISHING_SUCCESS_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; text-align: center; }
        .success { background: #d4edda; padding: 30px; border-radius: 8px; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="success">
        <h1>✅ Login Successful</h1>
        <p>Welcome back! You have been logged in.</p>
        <p><small>This is a synthetic phishing page for security testing.</small></p>
    </div>
</body>
</html>
"""

PHISHING_MFA_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Two-Factor Authentication</title>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .mfa-form { background: #f5f5f5; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="mfa-form">
        <h1>📱 Two-Factor Authentication</h1>
        <form method="POST" action="/mfa">
            <div class="form-group">
                <label for="code">Enter 6-digit code</label>
                <input type="text" id="code" name="code" placeholder="123456" required maxlength="6" autocomplete="one-time-code">
            </div>
            <button type="submit">Verify</button>
        </form>
    </div>
</body>
</html>
"""


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
    return {"status": "healthy", "service": "phishing-target", "scenario": settings.SCENARIO_ID}


@app.get("/", response_class=HTMLResponse)
async def root():
    return PHISHING_LOGIN_PAGE


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "phishing_page_served",
        "Phishing login page served",
        {"url": str(request.url), "page_type": "credential_harvesting"},
    )

    return PHISHING_LOGIN_PAGE


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "credential_submission",
        "Synthetic credentials submitted to phishing page",
        {
            "username": username,
            "password": "[REDACTED]",
            "form_action": "/login",
            "destination": str(request.url),
            "synthetic": True,
        },
    )

    return RedirectResponse(url="/mfa", status_code=302)


@app.get("/mfa", response_class=HTMLResponse)
async def mfa_page(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "mfa_page_served",
        "Phishing MFA page served",
        {"url": str(request.url)},
    )

    return PHISHING_MFA_PAGE


@app.post("/mfa")
async def mfa_submit(request: Request, code: str = Form(...)):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "mfa_code_submission",
        "MFA code submitted to phishing page",
        {"code": code, "synthetic": True},
    )

    return PHISHING_SUCCESS_PAGE


@app.get("/credential-dump")
async def credential_dump(request: Request):
    simulation_id = request.headers.get("x-simulation-id", "unknown")
    organization_id = request.headers.get("x-organization-id", "unknown")

    await submit_evidence(
        simulation_id,
        organization_id,
        "credential_dump_accessed",
        "Credential dump endpoint accessed",
        {"note": "This would contain harvested credentials in a real attack"},
    )

    return {"credentials": [], "note": "No real credentials stored - synthetic test environment"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.TARGET_HOST, port=settings.TARGET_PORT)