from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AgentShield"
    environment: str = "development"
    version: str = "1.0.0"
    database_url: str = "sqlite+aiosqlite:///./agentshield.db"
    redis_url: str | None = None
    jwt_secret: str = "development-only-jwt-secret-change-before-production"
    jwt_issuer: str = "agentshield"
    jwt_audience: str = "agentshield-api"
    jwt_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    api_key_pepper: str = "development-only-api-key-pepper"
    approval_signing_secret: str = "development-only-approval-secret"
    approval_ttl_minutes: int = Field(default=30, ge=1, le=1440)
    opa_url: str | None = None
    opa_timeout_seconds: float = Field(default=2.0, gt=0, le=10)
    p1_engine: str = "mock"
    p2_adapters: str = "mock"
    p3_adapters: str = "mock"
    admin_email: str = "admin@agentshield.local"
    admin_password: str = "admin-change-me"
    admin_tenant_slug: str = "acme"
    admin_tenant_name: str = "Acme workspace"
    seed_demo_data: bool = True
    allowed_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:8443",
            "http://127.0.0.1:8443",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
        ]
    )
    trust_proxy_headers: bool = False
    rate_limit_per_minute: int = Field(default=240, ge=1, le=100000)

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def validate_secrets(self) -> "Settings":
        if self.environment == "production":
            insecure = {
                "development-only-jwt-secret-change-before-production",
                "development-only-api-key-pepper",
                "development-only-approval-secret",
                "admin-change-me",
            }
            if insecure & {
                self.jwt_secret,
                self.api_key_pepper,
                self.approval_signing_secret,
                self.admin_password,
            }:
                raise ValueError("production requires non-default secrets")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
