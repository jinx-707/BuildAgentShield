from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select, text

from .auth import get_agent_auth, require_dashboard
from .contracts import (
    AuthContext,
    HealthResponse,
    SimulatorRunRequest,
    ToolRequest,
    ToolResponse,
)
from .db import Agent, Approval, AuditEvent, Tenant
from .gateway import GatewayError
from .registry import get_tool, list_tools
from .runtime import Runtime
from .simulator import CUSTOM_SCENARIOS, SCENARIOS

router = APIRouter(tags=["runtime"])


def _runtime(request: Request) -> Runtime:
    return request.app.state.runtime


@router.get("/health")
async def liveness(request: Request) -> dict:
    runtime = _runtime(request)
    return {
        "status": "ok",
        "version": runtime.settings.version,
        "environment": runtime.settings.environment,
        "mock": runtime.integrations.p1_status == "MOCK",
    }


@router.get("/ready", response_model=HealthResponse)
async def readiness(request: Request) -> HealthResponse:
    runtime = _runtime(request)
    components = await runtime.health_components()
    db_ok = True
    try:
        async with runtime.database.session() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    if not db_ok:
        components.append({"name": "database", "status": "UNHEALTHY", "detail": "query failed"})
    component_statuses = {item["status"] for item in components}
    if not db_ok or "UNAVAILABLE" in component_statuses:
        health = "unhealthy"
    elif "UNHEALTHY" in component_statuses:
        health = "degraded"
    else:
        health = "ok"
    return HealthResponse(
        status=health,
        version=runtime.settings.version,
        mode="mock" if runtime.integrations.p1_status == "MOCK" else "real",
        components=components,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/integrations/health")
async def integration_health(
    auth: AuthContext = Depends(require_dashboard("stats.read")),
    request: Request = None,
) -> dict:
    runtime = _runtime(request)
    await runtime.integrations.refresh_health()
    return {
        "items": await runtime.health_components(),
        "gateway": "available",
        "opa": "remote" if runtime.settings.opa_url else "local",
    }


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics(request: Request) -> str:
    runtime = _runtime(request)
    lines = [
        "# HELP agentshield_http_requests_total Total HTTP requests",
        "# TYPE agentshield_http_requests_total counter",
        f"agentshield_http_requests_total {runtime.metrics.requests}",
        "# HELP agentshield_http_errors_total HTTP 5xx responses",
        "# TYPE agentshield_http_errors_total counter",
        f"agentshield_http_errors_total {runtime.metrics.errors}",
        "# HELP agentshield_gateway_decisions_total Gateway decisions by decision",
        "# TYPE agentshield_gateway_decisions_total counter",
    ]
    for decision, count in sorted(runtime.metrics.decisions.items()):
        lines.append(f'agentshield_gateway_decisions_total{{decision="{decision}"}} {count}')
    lines.extend(
        [
            "# HELP agentshield_gateway_executions_total Adapter executions",
            "# TYPE agentshield_gateway_executions_total counter",
            f"agentshield_gateway_executions_total {runtime.metrics.executions}",
            "# HELP agentshield_gateway_latency_seconds_total Cumulative gateway latency",
            "# TYPE agentshield_gateway_latency_seconds_total counter",
            f"agentshield_gateway_latency_seconds_total {runtime.metrics.latency_total:.6f}",
        ]
    )
    for item in await runtime.health_components():
        lines.append(
            f'agentshield_component_up{{component="{item["name"]}"}} '
            f'{1 if item["status"] in {"REAL", "MOCK"} else 0}'
        )
    return "\n".join(lines) + "\n"


@router.get("/tools")
async def tools(
    auth: AuthContext = Depends(require_dashboard("tools.read")),
) -> dict:
    return {"items": [spec.model_dump(mode="json") for spec in list_tools()]}


@router.get("/tools/{tool_name}")
async def tool_detail(
    tool_name: str,
    auth: AuthContext = Depends(require_dashboard("tools.read")),
) -> dict:
    spec = get_tool(tool_name)
    if spec is None:
        raise HTTPException(404, "Tool not found")
    return spec.model_dump(mode="json")


@router.post("/gateway/execute", response_model=ToolResponse)
@router.post("/tools/execute", response_model=ToolResponse)
async def execute_tool(
    payload: ToolRequest,
    request: Request,
    auth: AuthContext = Depends(get_agent_auth),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    approval_token: str | None = Header(default=None, alias="X-Approval-Token"),
) -> ToolResponse:
    runtime = _runtime(request)
    started = time.perf_counter()
    try:
        response = await runtime.gateway.execute(
            auth,
            payload,
            approval_token=approval_token,
            idempotency_key=idempotency_key,
        )
    except GatewayError as exc:
        raise HTTPException(exc.status_code, str(exc))
    finally:
        runtime.metrics.latency_total += time.perf_counter() - started
    runtime.metrics.decisions[response.decision.value] += 1
    if response.executed:
        runtime.metrics.executions += 1
    if response.decision.value == "REQUIRE_APPROVAL":
        runtime.metrics.approvals += 1
    return response.model_copy(
        update={"tool": payload.tool_name, "execution_id": response.audit_id}
    )


@router.post("/gateway/propose", response_model=ToolResponse)
@router.post("/tools/propose", response_model=ToolResponse)
async def propose_tool(
    payload: ToolRequest,
    request: Request,
    auth: AuthContext = Depends(get_agent_auth),
) -> ToolResponse:
    runtime = _runtime(request)
    started = time.perf_counter()
    try:
        response = await runtime.gateway.propose(auth, payload)
    except GatewayError as exc:
        raise HTTPException(exc.status_code, str(exc))
    finally:
        runtime.metrics.latency_total += time.perf_counter() - started
    runtime.metrics.decisions[response.decision.value] += 1
    if response.decision.value == "REQUIRE_APPROVAL":
        runtime.metrics.approvals += 1
    return response


@router.get("/simulator/scenarios")
async def simulator_scenarios(
    auth: AuthContext = Depends(require_dashboard("simulator.run")),
) -> dict:
    items = [
        {
            "id": item["id"],
            "name": item["name"],
            "expected": item["expected"],
            "tool": item["tool"],
            "arguments": item["arguments"],
        }
        for item in SCENARIOS
    ]
    items.extend(
        {"id": key, "name": value, "expected": "Blocked", "tool": "approval_flow"}
        for key, value in CUSTOM_SCENARIOS.items()
    )
    return {"items": items}


@router.post("/simulator/run")
async def simulator_run(
    payload: SimulatorRunRequest,
    auth: AuthContext = Depends(require_dashboard("simulator.run")),
    request: Request = None,
) -> dict:
    runtime = _runtime(request)
    started = time.perf_counter()
    try:
        results = await runtime.simulator.run(auth.tenant_id, payload.scenario_ids)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    runtime.metrics.latency_total += time.perf_counter() - started
    for result in results:
        runtime.metrics.decisions[result.actual] += 1
    return {
        "items": [result.model_dump(mode="json") for result in results],
        "passed": sum(1 for result in results if result.passed),
        "total": len(results),
        "mode": "mock",
    }


@router.get("/stats/overview")
async def overview_stats(
    period: str = Query(default="24h", pattern="^(24h|7d|30d)$"),
    auth: AuthContext = Depends(require_dashboard("stats.read")),
    request: Request = None,
) -> dict:
    runtime = _runtime(request)
    now = datetime.now(timezone.utc)
    days = {"24h": 1, "7d": 7, "30d": 30}[period]
    since = now - timedelta(days=days)
    async with runtime.database.session() as session:
        events = (
            await session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.tenant_id == auth.tenant_id,
                    AuditEvent.created_at >= since,
                )
                .order_by(AuditEvent.created_at.asc())
            )
        ).all()
        pending = len(
            (
                await session.scalars(
                    select(Approval).where(
                        Approval.tenant_id == auth.tenant_id,
                        Approval.status == "Pending",
                    )
                )
            ).all()
        )
        agents = (
            await session.scalars(select(Agent).where(Agent.tenant_id == auth.tenant_id))
        ).all()
    total = len(events)
    allowed = sum(1 for event in events if event.decision in {"ALLOW", "REDACT"})
    blocked = sum(1 for event in events if event.decision in {"DENY", "QUARANTINE"})
    approvals = sum(1 for event in events if event.decision == "REQUIRE_APPROVAL")
    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for event in events:
        if event.risk_level in risk_distribution:
            risk_distribution[event.risk_level] += 1
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    if period == "24h":
        bucket_count = 24
        step = timedelta(hours=1)
        label_format = "%H:%M"
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    else:
        bucket_count = 7 if period == "7d" else 30
        step = timedelta(days=1)
        label_format = "%b %d"
        start = (now - timedelta(days=bucket_count - 1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
    labels = [start + step * index for index in range(bucket_count)]
    by_key = {label.strftime("%Y-%m-%d-%H" if period == "24h" else "%Y-%m-%d"): label for label in labels}
    for event in events:
        event_time = event.created_at
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        key = event_time.strftime("%Y-%m-%d-%H" if period == "24h" else "%Y-%m-%d")
        if key not in by_key:
            continue
        if event.decision in {"ALLOW", "REDACT"}:
            buckets[key]["allowed"] += 1
        elif event.decision in {"DENY", "QUARANTINE"}:
            buckets[key]["blocked"] += 1
    series = [
        {
            "time": label.isoformat(),
            "label": label.strftime(label_format),
            "allowed": buckets[key]["allowed"],
            "blocked": buckets[key]["blocked"],
        }
        for key, label in sorted(by_key.items())
    ]
    return {
        "period": period,
        "total_requests": total,
        "allowed_requests": allowed,
        "blocked_threats": blocked,
        "pending_approvals": pending,
        "approval_requests": approvals,
        "active_agents": sum(1 for agent in agents if agent.status == "Active"),
        "total_agents": len(agents),
        "series": series,
        "risk_distribution": risk_distribution,
        "integrations": await runtime.health_components(),
        "mode": "mock" if runtime.integrations.p1_status == "MOCK" else "real",
    }


@router.get("/stats/workspace")
async def workspace_stats(
    auth: AuthContext = Depends(require_dashboard("stats.read")),
    request: Request = None,
) -> dict:
    runtime = _runtime(request)
    async with runtime.database.session() as session:
        tenant = await session.get(Tenant, auth.tenant_id)
        agent_count = len(
            (
                await session.scalars(
                    select(Agent).where(Agent.tenant_id == auth.tenant_id)
                )
            ).all()
        )
    return {
        "workspace": {"id": tenant.id, "name": tenant.name, "slug": tenant.slug}
        if tenant
        else None,
        "agents": agent_count,
        "mode": "mock" if runtime.integrations.p1_status == "MOCK" else "real",
        "environment": runtime.settings.environment,
    }
