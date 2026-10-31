"""
AgentShield Configuration and Safe Logging System.
Supports environment-variable based configuration via pydantic-settings
with prefix AGENTSHIELD_ and built-in safe logging that masks secrets & PII.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from core.schemas import Action, RedactionMode, SensitivityLevel


class AgentShieldConfig(BaseSettings):
    """
    Central configuration for AgentShield Gateway.
    Values can be overridden via environment variables prefixed with AGENTSHIELD_.
    E.g. AGENTSHIELD_INJECTION_BLOCK_THRESHOLD=0.85
    """
    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------------
    # Gateway Operational Mode
    # ------------------------------------------------------------------------
    environment: str = Field(default="production", description="Environment: production, staging, test")
    log_level: str = Field(default="INFO", description="Logging level: DEBUG, INFO, WARNING, ERROR")
    safe_logging: bool = Field(default=True, description="Strictly redact PII and secrets in all logs")

    # ------------------------------------------------------------------------
    # Sub-Engine Feature Flags
    # ------------------------------------------------------------------------
    enable_injection_detection: bool = Field(default=True, description="Enable prompt injection detector")
    enable_pii_detection: bool = Field(default=True, description="Enable PII detector and redactor")
    enable_secret_scanning: bool = Field(default=True, description="Enable secret and credential scanner")
    enable_dlp: bool = Field(default=True, description="Enable Data Loss Prevention rules")
    enable_provenance: bool = Field(default=True, description="Enable cryptographic audit provenance ledger")

    # ------------------------------------------------------------------------
    # Thresholds & Calibration
    # ------------------------------------------------------------------------
    injection_warn_threshold: float = Field(default=0.40, ge=0.0, le=1.0)
    injection_block_threshold: float = Field(default=0.70, ge=0.0, le=1.0)

    secret_entropy_threshold: float = Field(default=4.2, ge=2.0, le=8.0, description="Shannon entropy threshold")
    
    risk_warn_threshold: float = Field(default=0.45, ge=0.0, le=1.0)
    risk_block_threshold: float = Field(default=0.75, ge=0.0, le=1.0)

    # ------------------------------------------------------------------------
    # Policies & Actions
    # ------------------------------------------------------------------------
    default_input_action: Action = Field(default=Action.ALLOW)
    default_output_action: Action = Field(default=Action.ALLOW)

    block_on_secret_leak: bool = Field(default=True, description="Hard block if unredacted secrets found in output")
    block_on_critical_injection: bool = Field(default=True, description="Hard block if critical injection detected")

    pii_redaction_mode: RedactionMode = Field(default=RedactionMode.MASK)
    secret_redaction_mode: RedactionMode = Field(default=RedactionMode.FULL_REDACT)

    dlp_max_allowed_sensitivity: SensitivityLevel = Field(
        default=SensitivityLevel.INTERNAL,
        description="Max sensitivity allowed without blocking (e.g., RESTRICTED will block)"
    )

    # ------------------------------------------------------------------------
    # Risk Weight Factors (Must sum reasonably)
    # ------------------------------------------------------------------------
    weight_injection: float = Field(default=0.35, ge=0.0, le=1.0)
    weight_secret: float = Field(default=0.30, ge=0.0, le=1.0)
    weight_dlp: float = Field(default=0.20, ge=0.0, le=1.0)
    weight_pii: float = Field(default=0.15, ge=0.0, le=1.0)
    privileged_agent_multiplier: float = Field(default=1.35, ge=1.0, le=2.5)

    # ------------------------------------------------------------------------
    # Cryptographic Provenance Ledger
    # ------------------------------------------------------------------------
    hmac_secret_key: str = Field(
        default="agentshield-production-runtime-integrity-key-32b",
        description="HMAC secret key used for digital provenance signatures"
    )
    hash_algorithm: str = Field(default="sha256")

    # ------------------------------------------------------------------------
    # DLP Custom Matchers
    # ------------------------------------------------------------------------
    custom_dlp_keywords: list[str] = Field(
        default_factory=lambda: ["PROJECT_TITAN_SECRET", "CONFIDENTIAL_MERGER", "PROPRIETARY_ALGO"]
    )

    @field_validator("injection_block_threshold")
    @classmethod
    def validate_injection_thresholds(cls, v: float, info: Any) -> float:
        warn = info.data.get("injection_warn_threshold", 0.40)
        if v < warn:
            raise ValueError(f"injection_block_threshold ({v}) cannot be less than warn_threshold ({warn})")
        return v

    @field_validator("risk_block_threshold")
    @classmethod
    def validate_risk_thresholds(cls, v: float, info: Any) -> float:
        warn = info.data.get("risk_warn_threshold", 0.45)
        if v < warn:
            raise ValueError(f"risk_block_threshold ({v}) cannot be less than warn_threshold ({warn})")
        return v


# ============================================================================
# Safe Logger & Privacy Redaction Filter
# ============================================================================

class SafeLogFilter(logging.Filter):
    """
    Log filter that scrubs credentials, tokens, and PII patterns from all log records
    before they are written to disk, console, or central sinks.
    """
    # Regex patterns for common sensitive items to scrub from log messages
    REDACT_PATTERNS = [
        (re.compile(r"sk-[a-zA-Z0-9_\-]{16,}", re.IGNORECASE), "[REDACTED_API_KEY]"),
        (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "[REDACTED_AWS_KEY]"),
        (re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE), "[REDACTED_GITHUB_TOKEN]"),
        (re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", re.IGNORECASE), "[REDACTED_SLACK_TOKEN]"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"), "[REDACTED_EMAIL]"),
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
        (re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), "[REDACTED_CARD]"),
        (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, replacement in self.REDACT_PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)
        if record.args:
            cleaned_args = []
            for arg in record.args if isinstance(record.args, tuple) else [record.args]:
                if isinstance(arg, str):
                    for pattern, replacement in self.REDACT_PATTERNS:
                        arg = pattern.sub(replacement, arg)
                cleaned_args.append(arg)
            record.args = tuple(cleaned_args)
        return True


def setup_logger(name: str = "agentshield", config: AgentShieldConfig | None = None) -> logging.Logger:
    """
    Configures and returns a safe logger with privacy redacting filter attached.
    """
    cfg = config or AgentShieldConfig()
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))

    # Avoid duplicate handlers if already initialized
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        if cfg.safe_logging:
            handler.addFilter(SafeLogFilter())
        logger.addHandler(handler)
        logger.propagate = False

    return logger
