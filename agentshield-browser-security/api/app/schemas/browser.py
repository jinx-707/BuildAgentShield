from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


WaitUntil = Literal["load", "domcontentloaded", "networkidle0", "networkidle2"]
Severity = Literal["low", "medium", "high", "critical"]

# Mirrors SESSION_ID_PATTERN in worker/src/lib/session_guard.js. The API is the
# trust boundary that faces the caller, so the worker must never disagree with
# it about what a legal identity looks like.
SESSION_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"


class BrowserNavigateRequest(BaseModel):
    url: HttpUrl
    wait_until: WaitUntil = "networkidle2"
    timeout_ms: int = Field(default=15000, ge=1000, le=60000)
    # Logical session identity only. It is forwarded verbatim to the worker as
    # request metadata and grants no access: authorization and the browser
    # security policy are decided without consulting it.
    session_id: str | None = Field(default=None, pattern=SESSION_ID_PATTERN)


class WorkerNavigateResponse(BaseModel):
    request_id: str
    requested_url: str
    final_url: str
    status_code: int | None = None
    title: str | None = None
    content: str
    content_truncated: bool
    elapsed_ms: int
    redirect_count: int = 0
    blocked_request_count: int = 0
    blocked_target_count: int = 0
    egress_proxy: dict | None = None


class PolicyRequest(BaseModel):
    request_id: str
    url: str
    organization_id: str | None = None
    agent_id: str | None = None


class PolicyDecision(BaseModel):
    allowed: bool
    policy_name: str
    reason: str


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    message: str
    location: dict | str | None = None


class InspectionResult(BaseModel):
    inspector_name: str
    findings: list[Finding] = Field(default_factory=list)
    trust_label: str = "untrusted"
    content_classification: str = "untrusted"
    highest_severity: str = "none"
    summary: str = ""


class BrowserNavigateResponse(BaseModel):
    request_id: str
    requested_url: str
    final_url: str
    status_code: int | None = None
    title: str | None = None
    content: str
    content_truncated: bool
    elapsed_ms: int
    redirect_count: int = 0
    blocked_request_count: int = 0
    blocked_target_count: int = 0
    policy: PolicyDecision
    inspection: InspectionResult
