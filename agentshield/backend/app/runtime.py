from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditService
from .config import Settings
from .coordination import CoordinationStore
from .db import Database, configure_database
from .gateway import Gateway
from .integration import IntegrationManager
from .policy import OPANotAvailable, PolicyEngine
from .seed import seed_database
from .simulator import Simulator


@dataclass
class Metrics:
    started_at: float = field(default_factory=time.time)
    requests: int = 0
    errors: int = 0
    decisions: Counter = field(default_factory=Counter)
    executions: int = 0
    approvals: int = 0
    latency_total: float = 0.0

    def observe(self, status_code: int, duration: float) -> None:
        self.requests += 1
        self.latency_total += duration
        if status_code >= 500:
            self.errors += 1


@dataclass
class Runtime:
    settings: Settings
    database: Database
    integrations: IntegrationManager
    policy: PolicyEngine
    audit: AuditService
    gateway: Gateway
    simulator: Simulator
    coordination: CoordinationStore
    metrics: Metrics

    async def startup(self) -> None:
        await self.database.create()
        await seed_database(self.database, self.settings, self.audit)
        await self.integrations.refresh_health()
        await self.coordination.connect()

    async def shutdown(self) -> None:
        await self.coordination.close()
        await self.database.dispose()

    async def health_components(self) -> list[dict[str, Any]]:
        components = self.integrations.health()
        components.append(
            {
                "name": "database",
                "status": "REAL",
                "detail": self.database.engine.url.drivername if self.database.engine else "unconfigured",
            }
        )
        components.append(
            {
                "name": "coordination",
                "status": self.coordination.status,
                "detail": self.coordination.detail,
            }
        )
        if self.settings.opa_url:
            try:
                await self.policy.opa.probe()
            except OPANotAvailable as exc:
                opa_status = "UNAVAILABLE"
                opa_detail = f"opa probe failed: {exc}"
            except Exception:
                opa_status = "UNAVAILABLE"
                opa_detail = "opa probe failed"
            else:
                opa_status = "REAL"
                opa_detail = "opa policy evaluation succeeded"
            components.append(
                {"name": "opa", "status": opa_status, "detail": opa_detail}
            )
        else:
            components.append(
                {
                    "name": "opa",
                    "status": "MOCK",
                    "detail": "local policy evaluator; set AGENTSHIELD_OPA_URL for OPA",
                }
            )
        return components


def build_runtime(settings: Settings) -> Runtime:
    database = configure_database(settings)
    integrations = IntegrationManager(settings)
    integrations.load()
    policy = PolicyEngine(settings)
    audit = AuditService()
    gateway = Gateway(settings, database, integrations, policy, audit)
    simulator = Simulator(database, gateway, settings)
    coordination = CoordinationStore(settings.redis_url)
    metrics = Metrics()
    return Runtime(
        settings=settings,
        database=database,
        integrations=integrations,
        policy=policy,
        audit=audit,
        gateway=gateway,
        simulator=simulator,
        coordination=coordination,
        metrics=metrics,
    )
