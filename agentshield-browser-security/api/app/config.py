from functools import lru_cache
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.security.ports import parse_port_spec


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "agentshield-browser-security-api"
    environment: str = "development"
    log_level: str = "INFO"

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: str = (
        "http://127.0.0.1:8443,http://localhost:8443,"
        "http://127.0.0.1:5173,http://localhost:5173"
    )

    browser_worker_url: str = "http://127.0.0.1:8080"
    browser_worker_timeout_seconds: float = 30.0
    browser_worker_health_timeout_seconds: float = 3.0
    worker_auth_token: str = ""
    api_auth_token: str = ""  # Optional Bearer token for API callers

    egress_proxy_url: str = ""
    egress_proxy_health_url: str = ""
    require_egress_proxy: bool = True

    policy_backend: str = "mock"
    inspection_backend: str = "mock"

    allowed_domains: str = ""
    blocked_domains: str = ""
    default_domain_policy: str = "deny"
    allowed_ports: str = "80,443"
    max_redirects: int = Field(default=5, ge=0, le=20)
    block_https_downgrade: bool = True
    allow_private_networks: bool = False
    dns_preflight_enabled: bool = True

    # Database
    database_url: str = ""
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=100)

    # Rate limiting. The memory backend is development/test only; production
    # requires Redis so counters are shared across replicas and survive restarts.
    rate_limit_enabled: bool = True
    rate_limit_backend: str = "memory"
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000)
    rate_limit_burst: int = Field(default=10, ge=1, le=100)
    rate_limit_navigation_per_minute: int = Field(default=30, ge=1, le=10000)
    rate_limit_search_per_minute: int = Field(default=20, ge=1, le=10000)
    rate_limit_session_create_per_minute: int = Field(default=10, ge=1, le=10000)
    rate_limit_action_per_minute: int = Field(default=60, ge=1, le=10000)
    rate_limit_extract_per_minute: int = Field(default=30, ge=1, le=10000)
    rate_limit_screenshot_per_minute: int = Field(default=20, ge=1, le=10000)
    rate_limit_window_seconds: int = Field(default=60, ge=10, le=3600)
    rate_limit_fail_open: bool = False
    # Comma-separated IPs/CIDRs. X-Forwarded-For is trusted only when the
    # direct peer is one of these networks. Empty means ignore the header.
    rate_limit_trusted_proxies: str = ""
    rate_limit_trusted_proxy_max_hops: int = Field(default=10, ge=1, le=20)
    redis_url: SecretStr = SecretStr("")
    redis_timeout_seconds: float = Field(default=1.0, gt=0, le=10)

    # JWT — required for enterprise authentication
    # Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
    jwt_secret: SecretStr = SecretStr("INSECURE-dev-default-change-me")

    # Web search provider (C1). The API key is wrapped in SecretStr so it can
    # never be rendered by repr(), logging, or a settings dump.
    search_provider: str = "brave"
    search_api_key: SecretStr = SecretStr("")
    search_timeout_ms: int = Field(default=5000, ge=500, le=30000)
    search_max_results: int = Field(default=5, ge=1, le=20)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be a standard Python logging level")
        return normalized

    @field_validator("browser_worker_url")
    @classmethod
    def validate_browser_worker_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("browser_worker_url must be an absolute HTTP(S) URL")
        return value.rstrip("/")

    @field_validator("browser_worker_timeout_seconds", "browser_worker_health_timeout_seconds")
    @classmethod
    def validate_timeout(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("timeouts must be positive")
        return value

    @field_validator("default_domain_policy")
    @classmethod
    def validate_default_domain_policy(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"allow", "deny"}:
            raise ValueError("default_domain_policy must be 'allow' or 'deny'")
        return normalized

    @field_validator("allowed_ports")
    @classmethod
    def validate_allowed_ports(cls, value: str) -> str:
        parse_port_spec(value)
        return value

    @field_validator("rate_limit_backend")
    @classmethod
    def validate_rate_limit_backend(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"memory", "redis"}:
            raise ValueError("rate_limit_backend must be 'memory' or 'redis'")
        return normalized

    @field_validator("search_provider")
    @classmethod
    def validate_search_provider(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"brave", "duckduckgo"}:
            raise ValueError(
                "search_provider must be 'brave' or 'duckduckgo' "
                "(duckduckgo is a limited keyless fallback)"
            )
        return normalized

    @field_validator("egress_proxy_url")
    @classmethod
    def validate_egress_proxy_url(cls, value: str) -> str:
        if not value:
            return value
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("egress_proxy_url must be an absolute HTTP(S) URL")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_production_auth(self) -> "Settings":
        """Fail closed: production deployments must configure API_AUTH_TOKEN and JWT_SECRET.

        An empty token in production silently disables authentication on all
        non-health endpoints.  We refuse to construct a valid Settings object
        in that state so the misconfiguration is caught at startup, not silently
        at request time.
        """
        _INSECURE_JWT = "INSECURE-dev-default-change-me"
        if self.environment.lower() == "production":
            if not self.api_auth_token:
                raise ValueError(
                    "API_AUTH_TOKEN must be set in production. "
                    "An empty token disables authentication on all non-health endpoints. "
                    "Set API_AUTH_TOKEN to a secret Bearer token before deploying."
                )
            if self.jwt_secret.get_secret_value() == _INSECURE_JWT:
                raise ValueError(
                    "JWT_SECRET must be set to a strong random value in production. "
                    "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
                )
        if (
            self.environment.lower() == "production"
            and self.default_domain_policy.lower() != "allow"
            and not self.allowed_domains.strip()
        ):
            raise ValueError(
                "ALLOWED_DOMAINS must be set in production when "
                "DEFAULT_DOMAIN_POLICY is 'deny'. "
                "An empty allowlist with default-deny blocks every navigation request. "
                "Set ALLOWED_DOMAINS to the permitted destination domains before deploying."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
