"""
Application-wide configuration loaded from environment variables.
Uses pydantic-settings for typed, validated config.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    app_env: Literal["development", "staging", "production"] = "development"
    app_secret_key: str = "CHANGE_ME_INSECURE_DEFAULT"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "INFO"

    # Database
    database_url: str = "sqlite+aiosqlite:///./agentshield_online.db"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Browser Worker
    browser_worker_url: str = "http://localhost:3001"
    browser_worker_api_key: str = "dev-browser-worker-key-change-me"

    # Search
    search_provider: Literal["serper", "brave", "mock"] = "mock"
    serper_api_key: str = ""
    brave_search_api_key: str = ""

    # Gmail
    gmail_client_id: str = ""
    gmail_client_secret: str = ""
    gmail_redirect_uri: str = "http://localhost:8000/online/email/oauth/callback"
    gmail_token_path: str = "./gmail_token.json"

    # Microsoft Graph
    msgraph_client_id: str = ""
    msgraph_client_secret: str = ""
    msgraph_tenant_id: str = ""
    msgraph_redirect_uri: str = "http://localhost:8000/online/email/outlook/callback"

    # ClamAV
    clamav_host: str = "localhost"
    clamav_port: int = 3310
    clamav_enabled: bool = True
    clamav_fail_closed: bool = True

    # Downloads
    download_base_dir: str = "./downloads"
    quarantine_base_dir: str = "./quarantine"

    # Razorpay — TEST MODE ONLY
    razorpay_key_id: str = ""
    razorpay_key_secret: str = ""
    razorpay_webhook_secret: str = ""

    # Stripe — TEST MODE ONLY
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""

    # Payment safety guard
    payment_mode: Literal["test"] = "test"

    # Vault
    vault_url: str = ""
    vault_token: str = ""
    vault_mount: str = "secret"

    # Local auth (dev only)
    local_auth_enabled: bool = True
    local_dev_api_key: str = "dev-api-key-change-me"

    # MCP
    mcp_connection_timeout: int = 30
    mcp_tool_timeout: int = 60

    @field_validator("payment_mode")
    @classmethod
    def enforce_test_mode(cls, v: str) -> str:
        if v != "test":
            raise ValueError(
                "CRITICAL: payment_mode must be 'test'. "
                "Live payment processing is not permitted in this module."
            )
        return v

    @field_validator("app_secret_key")
    @classmethod
    def warn_insecure_key(cls, v: str) -> str:
        if v in ("CHANGE_ME_INSECURE_DEFAULT", ""):
            import warnings
            warnings.warn(
                "APP_SECRET_KEY is set to an insecure default. "
                "Set a strong random key in .env before deployment.",
                stacklevel=2,
            )
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
