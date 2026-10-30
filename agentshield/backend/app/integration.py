from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any

from .adapters import (
    Adapter,
    AdapterRegistry,
    UnavailableAdapter,
    mock_offline_registry,
    mock_online_registry,
)
from .config import Settings
from .p1 import MockSecurityEngine, SecurityEngine, UnavailableSecurityEngine


OFFLINE_TOOLS = {
    "read_document",
    "read_file",
    "read_system_file",
    "read_env_var",
    "run_command",
    "delete_file",
}
ONLINE_TOOLS = {
    "browse_url",
    "send_email",
    "export_data",
    "download_file",
    "initiate_payment",
    "call_external_api",
    "mcp_call",
}


@dataclass
class IntegrationManager:
    settings: Settings
    security_engine: SecurityEngine = field(default_factory=UnavailableSecurityEngine)
    p1_status: str = "UNAVAILABLE"
    p1_detail: str = "not initialized"
    offline: AdapterRegistry = field(default_factory=AdapterRegistry)
    online: AdapterRegistry = field(default_factory=AdapterRegistry)
    p2_status: str = "UNAVAILABLE"
    p2_detail: str = "not initialized"
    p3_status: str = "UNAVAILABLE"
    p3_detail: str = "not initialized"

    def load(self) -> None:
        self._load_p1()
        self._load_p2()
        self._load_p3()

    def _load_p1(self) -> None:
        value = (self.settings.p1_engine or "unavailable").strip()
        if value == "mock":
            self.security_engine = MockSecurityEngine()
            self.p1_status = "MOCK"
            self.p1_detail = "deterministic inspection engine; no external model calls"
            return
        if value == "unavailable":
            self.security_engine = UnavailableSecurityEngine()
            self.p1_status = "UNAVAILABLE"
            self.p1_detail = "P1 security engine is explicitly unavailable"
            return
        try:
            engine = _load_plugin(value)
            required = (
                "inspect_input",
                "inspect_output",
                "inspect_tool_call",
                "inspect_data",
                "calculate_risk",
            )
            if not all(hasattr(engine, method) for method in required):
                raise TypeError("P1 plugin does not implement the security engine contract")
            self.security_engine = engine
            self.p1_status = "REAL"
            self.p1_detail = value
        except Exception as exc:
            self.security_engine = UnavailableSecurityEngine()
            self.p1_status = "UNAVAILABLE"
            self.p1_detail = f"P1 plugin failed to load: {type(exc).__name__}"

    def _load_p2(self) -> None:
        value = (self.settings.p2_adapters or "unavailable").strip()
        if value == "mock":
            self.offline = mock_offline_registry()
            self.p2_status = "MOCK"
            self.p2_detail = self.offline.detail
            return
        if value == "unavailable":
            self.offline = AdapterRegistry()
            self.offline.register(UnavailableAdapter("p2_unavailable", OFFLINE_TOOLS))
            self.offline.status = "UNAVAILABLE"
            self.p2_status = "UNAVAILABLE"
            self.p2_detail = "P2 adapters are explicitly unavailable"
            return
        try:
            self.offline = _load_adapter_plugin(value, self.p2_status)
            self.p2_status = "REAL"
            self.p2_detail = value
        except Exception as exc:
            self.offline = AdapterRegistry()
            self.offline.register(UnavailableAdapter("p2_unavailable", OFFLINE_TOOLS))
            self.offline.status = "UNAVAILABLE"
            self.offline.detail = f"P2 plugin failed to load: {type(exc).__name__}"
            self.p2_status = "UNAVAILABLE"
            self.p2_detail = self.offline.detail

    def _load_p3(self) -> None:
        value = (self.settings.p3_adapters or "unavailable").strip()
        if value == "mock":
            self.online = mock_online_registry()
            self.p3_status = "MOCK"
            self.p3_detail = self.online.detail
            return
        if value == "unavailable":
            self.online = AdapterRegistry()
            self.online.register(UnavailableAdapter("p3_unavailable", ONLINE_TOOLS))
            self.online.status = "UNAVAILABLE"
            self.p3_status = "UNAVAILABLE"
            self.p3_detail = "P3 adapters are explicitly unavailable"
            return
        try:
            self.online = _load_adapter_plugin(value, self.p3_status)
            self.p3_status = "REAL"
            self.p3_detail = value
        except Exception as exc:
            self.online = AdapterRegistry()
            self.online.register(UnavailableAdapter("p3_unavailable", ONLINE_TOOLS))
            self.online.status = "UNAVAILABLE"
            self.online.detail = f"P3 plugin failed to load: {type(exc).__name__}"
            self.p3_status = "UNAVAILABLE"
            self.p3_detail = self.online.detail

    async def refresh_health(self) -> None:
        for registry, label in ((self.offline, "p2"), (self.online, "p3")):
            if registry.status not in {"MOCK", "REAL"}:
                continue
            healthy = True
            for adapter in registry.adapters.values():
                try:
                    healthy = healthy and await adapter.healthcheck()
                except Exception:
                    healthy = False
            if not healthy:
                registry.status = "UNHEALTHY"
                if label == "p2":
                    self.p2_status = "UNHEALTHY"
                else:
                    self.p3_status = "UNHEALTHY"

    def health(self) -> list[dict[str, str]]:
        return [
            {"name": "security_engine", "status": self.p1_status, "detail": self.p1_detail},
            {"name": "offline_adapters", "status": self.p2_status, "detail": self.p2_detail},
            {"name": "online_adapters", "status": self.p3_status, "detail": self.p3_detail},
        ]

    def adapter_for(self, tool_name: str) -> Adapter | None:
        if tool_name in OFFLINE_TOOLS:
            return self.offline.find(tool_name)
        if tool_name in ONLINE_TOOLS:
            return self.online.find(tool_name)
        return None


def _load_plugin(path: str) -> Any:
    if ":" not in path:
        raise ValueError("plugin path must be module:factory")
    module_name, factory_name = path.split(":", 1)
    module = importlib.import_module(module_name)
    factory = getattr(module, factory_name)
    return factory() if callable(factory) else factory


def _load_adapter_plugin(path: str, status: str) -> AdapterRegistry:
    loaded = _load_plugin(path)
    registry = AdapterRegistry()
    if isinstance(loaded, AdapterRegistry):
        return loaded
    if isinstance(loaded, dict):
        values = loaded.values()
    elif isinstance(loaded, (list, tuple, set)):
        values = loaded
    else:
        values = [loaded]
    for adapter in values:
        if not hasattr(adapter, "tool_names") or not hasattr(adapter, "execute"):
            raise TypeError("adapter plugin does not implement the adapter contract")
        registry.register(adapter)
    registry.status = "REAL"
    registry.detail = path
    return registry
