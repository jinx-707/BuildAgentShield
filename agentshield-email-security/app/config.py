"""Configuration and environment settings for AgentShield Email Security."""

import base64
import logging
import os
from functools import lru_cache
from typing import List, Optional
from cryptography.fernet import Fernet
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("agentshield.email.config")


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_ENV: str = Field(default="development", description="Environment: development, test, production")
    DEBUG: bool = Field(default=False, description="Debug mode")
    HOST: str = Field(default="0.0.0.0", description="API host")
    PORT: int = Field(default=8001, description="API port")

    # Database
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./agentshield_email.db",
        description="Async SQLAlchemy database connection URL",
    )

    # Google OAuth 2.0 Credentials
    GOOGLE_CLIENT_ID: str = Field(default="", description="Google OAuth Client ID")
    GOOGLE_CLIENT_SECRET: str = Field(default="", description="Google OAuth Client Secret")
    GOOGLE_REDIRECT_URI: str = Field(
        default="http://localhost:8001/online/email/oauth/google/callback",
        description="Google OAuth Callback URI",
    )

    # Cryptography
    TOKEN_ENCRYPTION_KEY: str = Field(
        default="",
        description="Base64 32-byte Fernet key for encrypting OAuth tokens at rest",
    )

    # Security Integration Services
    POLICY_SERVICE_URL: str = Field(default="", description="External Policy Service endpoint")
    INSPECTION_SERVICE_URL: str = Field(default="", description="External Inspection/DLP Service endpoint")
    AUDIT_SERVICE_URL: str = Field(default="", description="External Audit Logging Service endpoint")
    USE_MOCK_INTEGRATIONS: bool = Field(
        default=False,
        description=(
            "Enable mock security integrations for local development and tests ONLY. "
            "Must be False in production — startup will refuse to proceed if True."
        ),
    )

    # Rate limiting
    REDIS_URL: str = Field(
        default="",
        description="Redis connection URL for shared rate limiting (required in production).",
    )
    RATE_LIMITER_BACKEND: str = Field(
        default="development",
        description=(
            "Rate limiter backend: 'redis' (production, shared) or 'development' "
            "(in-memory, single-process only). Production startup rejects 'development'."
        ),
    )

    # Gateway Authentication
    INTERNAL_SERVICE_TOKEN: str = Field(
        default="dev-secret-token",
        description="Internal shared token required between API gateway and Email service",
    )
    REQUIRE_GATEWAY_AUTH: bool = Field(
        default=False,
        description="Strictly require gateway authentication headers (always True in production)",
    )

    # Email and Security Limits
    MAX_ATTACHMENT_SIZE_BYTES: int = Field(
        default=25 * 1024 * 1024,  # 25 MB
        description="Maximum allowed single attachment size in bytes",
    )
    MAX_TOTAL_MESSAGE_SIZE_BYTES: int = Field(
        default=35 * 1024 * 1024,  # 35 MB
        description="Maximum total email size in bytes",
    )
    MAX_SEARCH_RESULTS: int = Field(
        default=50,
        description="Maximum messages returned in a single search operation",
    )

    # OAuth Scope Presets (Least privilege by default)
    DEFAULT_OAUTH_SCOPES: List[str] = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/userinfo.email",
    ]

    ALLOWED_OAUTH_SCOPES: List[str] = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/userinfo.email",
    ]

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        # Normalize sqlite URLs for async
        if v.startswith("sqlite:///"):
            return v.replace("sqlite:///", "sqlite+aiosqlite:///")
        # Normalize postgres URLs for asyncpg
        if v.startswith("postgresql://") and not v.startswith("postgresql+asyncpg://"):
            return v.replace("postgresql://", "postgresql+asyncpg://")
        return v

    def get_encryption_key(self) -> bytes:
        """Retrieve or generate a valid 32-byte Fernet key."""
        if self.TOKEN_ENCRYPTION_KEY:
            key_str = self.TOKEN_ENCRYPTION_KEY.strip()
            # If standard base64 string
            try:
                # Test validity
                Fernet(key_str.encode("utf-8"))
                return key_str.encode("utf-8")
            except Exception as e:
                logger.error(f"Configured TOKEN_ENCRYPTION_KEY is invalid: {e}")
                if self.APP_ENV == "production":
                    raise ValueError("Invalid TOKEN_ENCRYPTION_KEY in production") from e

        if self.APP_ENV == "production":
            raise ValueError("TOKEN_ENCRYPTION_KEY must be configured in production environment!")

        # For development / test fallback: deterministic key based on INTERNAL_SERVICE_TOKEN or generated
        logger.warning(
            "Using development token encryption key fallback. DO NOT USE IN PRODUCTION."
        )
        padded = (self.INTERNAL_SERVICE_TOKEN.ljust(32, "0")[:32]).encode("utf-8")
        return base64.urlsafe_b64encode(padded)


@lru_cache
def get_settings() -> Settings:
    """Singleton cached settings instance."""
    return Settings()

