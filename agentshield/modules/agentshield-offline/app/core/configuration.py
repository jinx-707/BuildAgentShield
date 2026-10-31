"""
AgentShield Offline — Central configuration.

Settings are loaded from environment variables (with .env support) and
supplemented by YAML policy files under configs/.
Secrets and credentials are NEVER hardcoded here.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_BASE_DIR = Path(__file__).resolve().parent.parent.parent  # project root
_CONFIGS_DIR = _BASE_DIR / "configs"


class OfflineSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AGENTSHIELD_",
        case_sensitive=False,
    )

    # ---- Application ----
    app_name: str = "AgentShield Offline Security Module"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"  # development | staging | production

    # ---- API ----
    api_host: str = "0.0.0.0"
    api_port: int = 8001
    api_prefix: str = "/offline"
    # Development API key — NEVER use this value in production
    dev_api_key: str = Field(
        default="dev-offline-insecure-key-change-me",
        description="Development-only API key. Replace via env var in production.",
    )

    # ---- Document limits ----
    document_max_size_bytes: int = 50 * 1024 * 1024  # 50 MB
    document_max_pages: int = 500
    document_max_text_length: int = 5_000_000  # characters
    document_processing_timeout: int = 60  # seconds
    document_xml_entity_expansion_limit: int = 0  # 0 = disable

    # ---- Quarantine ----
    quarantine_dir: str = str(_BASE_DIR / "quarantine")

    # ---- Workspace ----
    default_workspace: str = "/workspace"

    # ---- ClamAV ----
    clamav_host: str = "localhost"
    clamav_port: int = 3310
    clamav_timeout: int = 30
    clamav_fail_closed: bool = True  # if scanner unavailable → deny

    # ---- Docker sandbox ----
    sandbox_image: str = "python:3.11-slim"
    sandbox_memory_limit: str = "256m"
    sandbox_cpu_period: int = 100_000
    sandbox_cpu_quota: int = 50_000  # 50% of one CPU
    sandbox_pids_limit: int = 64
    sandbox_network_mode: str = "none"
    sandbox_default_timeout: int = 30
    sandbox_max_timeout: int = 300
    sandbox_output_max_bytes: int = 1 * 1024 * 1024  # 1 MB
    sandbox_enabled: bool = True  # if False and no fallback → unavailable

    # ---- Audit ----
    audit_log_path: str = str(_BASE_DIR / "logs" / "audit.jsonl")
    audit_fail_open: bool = False  # if True, audit failures don't block requests

    # ---- Inspection ----
    inspection_fail_closed: bool = True  # if inspector unavailable → deny

    # ---- Person 1 security engine integration (optional) ----
    # pip install -e ".[p1]" then set AGENTSHIELD_P1_ENABLED=true
    p1_enabled: bool = False
    # Path to the penetration-prevention repo root (auto-detected as sibling dir if empty)
    p1_module_path: str = ""
    p1_fail_closed: bool = True

    # ---- NeMo Guardrails (optional integration) ----
    # Set AGENTSHIELD_NEMO_ENABLED=true to activate the NeMo inspection layer.
    # The module runs fully without NeMo when this is false (default).
    nemo_enabled: bool = False
    nemo_config_path: str = str(_CONFIGS_DIR / "nemo")
    nemo_timeout: int = 30              # seconds per inspection call
    nemo_fail_closed: bool = True       # if NeMo unavailable → deny (when enabled)
    # Profile: "local" | "model_backed" | "production"
    # "local" uses only heuristic/regex rails (no external model needed).
    # "model_backed" requires a configured model provider in the NeMo config.
    nemo_profile: str = "local"
    # Whether to run NeMo input rails on document content
    nemo_inspect_documents: bool = True
    # Whether to run NeMo output rails on terminal stdout/stderr
    nemo_inspect_terminal_output: bool = True
    # Max characters sent to NeMo (content is truncated if longer)
    nemo_max_content_chars: int = 50_000
    # Telemetry opt-out — always defaults to off; never enable without consent
    nemo_telemetry_disabled: bool = True

    # ---- Config file paths ----
    offline_policy_path: str = str(_CONFIGS_DIR / "offline_policy.yaml")
    protected_paths_config: str = str(_CONFIGS_DIR / "protected_paths.yaml")
    document_limits_config: str = str(_CONFIGS_DIR / "document_limits.yaml")
    sandbox_config: str = str(_CONFIGS_DIR / "sandbox.yaml")

    @field_validator("environment")
    @classmethod
    def valid_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"environment must be one of {allowed}")
        return v


@lru_cache(maxsize=1)
def get_settings() -> OfflineSettings:
    return OfflineSettings()


def load_yaml_config(path: str) -> dict[str, Any]:
    """Load a YAML config file safely, returning an empty dict on failure."""
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data
