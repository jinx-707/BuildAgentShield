"""
Configuration for AgentShield Secure Downloads.

All values are read from environment variables (or .env files).
The Settings object fails closed in production: it raises ValidationError
at construction time rather than silently operating with insecure defaults.

Environment classification
--------------------------
ENVIRONMENT must be set explicitly.  Values are normalized (case and
surrounding whitespace) and mapped to one of four canonical environments:

    development  (aliases: dev, local)
    test         (aliases: tests)
    staging      (aliases: stage, preprod, pre-production)
    production   (aliases: prod)

Security-relevant decisions:
* Unknown values, empty values and a missing ENVIRONMENT all raise
  ValidationError at construction — no value is ever silently treated as
  "development", and a forgotten ENVIRONMENT cannot disable production
  controls.
* "staging" is production-like: it enforces the full production security
  policy so staging cannot drift from the checks production relies on.
* The development-only exceptions (no proxy, DNS preflight off, private
  networks allowed, no API token) apply only to the canonical "development"
  and "test" environments.
"""
from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ── Environment classification ─────────────────────────────────────────────
# Normalized (case- and whitespace-folded) input value → canonical environment.
ENVIRONMENT_ALIASES: dict[str, str] = {
    "production": "production",
    "prod": "production",
    "staging": "staging",
    "stage": "staging",
    "preprod": "staging",
    "pre-production": "staging",
    "development": "development",
    "dev": "development",
    "local": "development",
    "test": "test",
    "tests": "test",
}

# Canonical environments that must enforce the production security policy.
PRODUCTION_LIKE_ENVIRONMENTS: frozenset[str] = frozenset({"production", "staging"})

# Document-analysis provider modes.  "local_mock" exists only for explicit
# local testing and is refused in production-like environments.
ANALYSIS_PROVIDER_MODES: frozenset[str] = frozenset({"disabled", "local_mock", "http"})

LOCAL_ENDPOINT_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})

ENVIRONMENT_HELP = (
    "ENVIRONMENT must be set explicitly to one of: production, prod, staging, "
    "stage, preprod, pre-production, development, dev, local, test, tests "
    "(case-insensitive). Unknown, empty, or missing values are rejected so a "
    "misconfigured deployment cannot silently skip production security checks."
)


def classify_environment(raw: object) -> str:
    """Normalize an ENVIRONMENT value to its canonical form or raise ValueError."""
    if raw is None:
        raise ValueError(ENVIRONMENT_HELP)
    normalized = str(raw).strip().lower()
    if not normalized:
        raise ValueError(
            "ENVIRONMENT must not be empty. " + ENVIRONMENT_HELP
        )
    canonical = ENVIRONMENT_ALIASES.get(normalized)
    if canonical is None:
        raise ValueError(f"Unrecognized ENVIRONMENT value {str(raw)!r}. " + ENVIRONMENT_HELP)
    return canonical


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Service identity ───────────────────────────────────────────────────
    app_name: str = "agentshield-secure-downloads"
    # No usable default: an unset ENVIRONMENT is a fail-closed configuration
    # error (see module docstring), enforced by validate_default below.
    environment: str = Field(default="", validate_default=True)
    log_level: str = "INFO"

    # ── API auth ───────────────────────────────────────────────────────────
    api_auth_token: str = ""

    # ── Database ───────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./secure_downloads.db"

    # ── Egress proxy ───────────────────────────────────────────────────────
    egress_proxy_url: str = ""
    egress_proxy_health_url: str = ""
    require_egress_proxy: bool = True
    # Optional Basic-auth password for the egress proxy.  httpx receives it as
    # userinfo on the proxy URL and sends "Proxy-Authorization: Basic" with
    # username "agentshield" (see security/proxy_auth.py).  The value is a
    # secret: it must never be logged or surfaced in error messages.
    proxy_auth_token: str = ""

    # ── Domain / port policy ───────────────────────────────────────────────
    allowed_domains: str = ""
    blocked_domains: str = ""
    default_domain_policy: str = "deny"
    allowed_ports: str = "80,443"

    # ── SSRF / network hardening ───────────────────────────────────────────
    allow_private_networks: bool = False
    dns_preflight_enabled: bool = True

    # ── Download limits ────────────────────────────────────────────────────
    max_file_size_bytes: int = Field(default=52_428_800, ge=1)          # 50 MB
    download_connect_timeout_seconds: float = Field(default=10.0, gt=0)
    download_read_timeout_seconds: float = Field(default=30.0, gt=0)
    download_total_timeout_seconds: float = Field(default=120.0, gt=0)
    max_redirects: int = Field(default=5, ge=0, le=20)
    max_concurrent_downloads_per_tenant: int = Field(default=5, ge=1, le=100)

    # ── ClamAV ────────────────────────────────────────────────────────────
    clamav_host: str = "127.0.0.1"
    clamav_port: int = Field(default=3310, ge=1, le=65535)
    clamav_timeout_seconds: float = Field(default=60.0, gt=0)
    clamav_fail_closed: bool = True

    # ── Document analysis ─────────────────────────────────────────────────
    # Provider selection is explicit.  "local_mock" is for local testing only
    # and is refused in production-like environments; "disabled" turns the
    # analysis feature off (downloads still work).  "http" is the real
    # provider integration and is the only mode allowed in production.
    analysis_provider: str = "disabled"
    analysis_endpoint_url: str = ""
    analysis_api_token: str = ""
    analysis_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    analysis_read_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    analysis_total_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    analysis_job_timeout_seconds: float = Field(default=120.0, gt=0, le=900)
    analysis_max_attempts: int = Field(default=3, ge=1, le=10)
    analysis_retry_base_delay_seconds: float = Field(default=0.25, ge=0, le=10)
    analysis_worker_concurrency: int = Field(default=2, ge=1, le=16)
    # Hard caps on what crosses the provider boundary.
    analysis_max_payload_bytes: int = Field(default=10_485_760, ge=1)
    analysis_max_response_bytes: int = Field(default=2_097_152, ge=1)
    # Hard caps on local PDF processing.
    analysis_max_pages: int = Field(default=200, ge=1, le=5000)
    analysis_max_extracted_chars: int = Field(default=200_000, ge=100, le=5_000_000)
    analysis_processing_timeout_seconds: float = Field(default=20.0, gt=0, le=300)
    # Test-only escape hatches; refused in production-like environments.
    analysis_allow_insecure_local: bool = False
    analysis_allow_private_endpoints: bool = False
    # Route analysis egress through the same attested egress proxy.
    analysis_use_egress_proxy: bool = True

    # ── Storage ────────────────────────────────────────────────────────────
    storage_root: str = "/var/secure-download-storage"
    approved_file_ttl_seconds: int = Field(default=3600, ge=60)
    # How often the background sweeper expires approved files past their TTL.
    cleanup_interval_seconds: int = Field(default=60, ge=5, le=3600)

    # ── Rate limiting ──────────────────────────────────────────────────────
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = Field(default=30, ge=1, le=10_000)

    # ── Validators ────────────────────────────────────────────────────────

    @field_validator("environment", mode="before")
    @classmethod
    def validate_environment(cls, value: object) -> str:
        return classify_environment(value)

    @field_validator("proxy_auth_token")
    @classmethod
    def validate_proxy_auth_token(cls, value: str) -> str:
        return value.strip()

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be a standard Python logging level")
        return normalized

    @field_validator("default_domain_policy")
    @classmethod
    def validate_default_domain_policy(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"allow", "deny"}:
            raise ValueError("default_domain_policy must be 'allow' or 'deny'")
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

    @field_validator("analysis_provider", mode="before")
    @classmethod
    def validate_analysis_provider(cls, value: object) -> str:
        normalized = str(value).strip().lower()
        if normalized not in ANALYSIS_PROVIDER_MODES:
            raise ValueError(
                "ANALYSIS_PROVIDER must be one of 'disabled', 'local_mock', "
                "or 'http'."
            )
        return normalized

    @field_validator("analysis_api_token")
    @classmethod
    def validate_analysis_api_token(cls, value: str) -> str:
        return value.strip()

    @field_validator("analysis_endpoint_url")
    @classmethod
    def validate_analysis_endpoint_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return value
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(
                "analysis_endpoint_url must be an absolute HTTP(S) URL"
            )
        if parsed.username is not None or parsed.password is not None:
            # Credentials belong in ANALYSIS_API_TOKEN, not in a URL that
            # ends up in logs and error messages.
            raise ValueError(
                "analysis_endpoint_url must not embed credentials; use "
                "ANALYSIS_API_TOKEN."
            )
        return value

    @property
    def is_production_like(self) -> bool:
        """True when the canonical environment must enforce the production policy."""
        return self.environment in PRODUCTION_LIKE_ENVIRONMENTS

    @model_validator(mode="after")
    def validate_production_requirements(self) -> "Settings":
        # A proxy auth password without a proxy to send it to is dead
        # configuration; refuse rather than let it silently do nothing.
        if self.proxy_auth_token and not self.egress_proxy_url:
            raise ValueError(
                "PROXY_AUTH_TOKEN is set but EGRESS_PROXY_URL is not: proxy "
                "credentials require an egress proxy to authenticate against."
            )

        # ── Document analysis, every environment ──────────────────────────
        if self.analysis_provider == "http":
            if not self.analysis_endpoint_url:
                raise ValueError(
                    "ANALYSIS_ENDPOINT_URL must be set when ANALYSIS_PROVIDER=http."
                )
            if not self.analysis_api_token:
                raise ValueError(
                    "ANALYSIS_API_TOKEN must be set when ANALYSIS_PROVIDER=http; "
                    "the provider requires authentication."
                )
            endpoint = urlparse(self.analysis_endpoint_url)
            if endpoint.scheme != "https":
                if not self.analysis_allow_insecure_local:
                    raise ValueError(
                        "ANALYSIS_ENDPOINT_URL must use https. Plain HTTP is "
                        "only permitted for a local mock endpoint via "
                        "ANALYSIS_ALLOW_INSECURE_LOCAL=true (refused in "
                        "production-like environments)."
                    )
                if endpoint.hostname not in LOCAL_ENDPOINT_HOSTS:
                    raise ValueError(
                        "ANALYSIS_ALLOW_INSECURE_LOCAL only applies to a "
                        "loopback endpoint (127.0.0.1, ::1, localhost)."
                    )
        elif self.analysis_endpoint_url or self.analysis_api_token:
            # Dead configuration: provider credentials/endpoint with no
            # provider that uses them.  Refuse rather than silently ignore.
            raise ValueError(
                "ANALYSIS_ENDPOINT_URL/ANALYSIS_API_TOKEN are set but "
                f"ANALYSIS_PROVIDER is {self.analysis_provider!r}; set "
                "ANALYSIS_PROVIDER=http or remove them."
            )

        if not self.is_production_like:
            return self

        # Fail closed: production (and staging) must have an API auth token.
        if not self.api_auth_token:
            raise ValueError(
                "API_AUTH_TOKEN must be set in production. "
                "An empty token disables authentication on all non-health endpoints."
            )

        # Fail closed: production must route through the egress proxy.  The
        # opt-out flag is not honoured in production — without it, downloads
        # would leave the host directly and no IP-policy enforcement would
        # exist at TCP-connection time.
        if not self.require_egress_proxy:
            raise ValueError(
                "REQUIRE_EGRESS_PROXY must be true in production; direct "
                "egress is not a supported configuration."
            )

        if not self.egress_proxy_url:
            raise ValueError(
                "EGRESS_PROXY_URL must be set in production: downloads must "
                "leave through the egress proxy."
            )

        # Without the health endpoint the streamer cannot attest that the proxy
        # is in enforcing mode, so a permissive proxy would be used silently.
        if not self.egress_proxy_health_url:
            raise ValueError(
                "EGRESS_PROXY_HEALTH_URL must be set in production so proxy "
                "enforcement mode can be verified."
            )

        # Fail closed: the preflight SSRF check must stay enabled.
        if not self.dns_preflight_enabled:
            raise ValueError(
                "DNS_PREFLIGHT_ENABLED must be true in production; disabling it "
                "removes the pre-connection SSRF check."
            )

        # Fail closed: production targets must not be allowed to resolve into
        # private/loopback space, which is what the SSRF guard exists to stop.
        if self.allow_private_networks:
            raise ValueError(
                "ALLOW_PRIVATE_NETWORKS must be false in production."
            )

        # Fail closed: default-deny with no allowlist blocks everything.
        if (
            self.default_domain_policy.lower() == "deny"
            and not self.allowed_domains.strip()
        ):
            raise ValueError(
                "ALLOWED_DOMAINS must be set in production when "
                "DEFAULT_DOMAIN_POLICY is 'deny'."
            )

        # Fail closed: the real provider integration is mandatory in
        # production.  A mock must never be reachable from a production
        # deployment, and an insecure/private provider endpoint would create
        # an unmonitored egress path.
        if self.analysis_provider != "http":
            raise ValueError(
                "ANALYSIS_PROVIDER must be 'http' in production-like "
                "environments; 'local_mock' and 'disabled' are refused."
            )
        if self.analysis_allow_insecure_local:
            raise ValueError(
                "ANALYSIS_ALLOW_INSECURE_LOCAL must be false in production."
            )
        if self.analysis_allow_private_endpoints:
            raise ValueError(
                "ANALYSIS_ALLOW_PRIVATE_ENDPOINTS must be false in production."
            )
        # Fail closed: analysis is a second egress path and must not bypass
        # the attested egress proxy that the rest of the service relies on.
        if not self.analysis_use_egress_proxy:
            raise ValueError(
                "ANALYSIS_USE_EGRESS_PROXY must be true in production; "
                "provider traffic must leave through the egress proxy."
            )

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


def security_issues(settings: Settings) -> list[str]:
    """
    Return a list of unsafe-but-parseable configuration problems.

    The list is configuration-name based only — it never contains secret
    values — so it is safe to expose through the readiness endpoint and logs.

    A non-empty list means the service can run (in a permissive environment)
    but must not be reported as security-ready.  Production-like environments
    reject most of these at Settings construction already; this function is the
    startup safety net and the readiness signal for every environment.
    """
    issues: list[str] = []

    if not settings.api_auth_token:
        issues.append("API_AUTH_TOKEN is not set: all non-health endpoints are unauthenticated.")

    if settings.require_egress_proxy and not settings.egress_proxy_url:
        issues.append("REQUIRE_EGRESS_PROXY is true but EGRESS_PROXY_URL is not set.")

    if settings.egress_proxy_url and not settings.egress_proxy_health_url:
        issues.append(
            "An egress proxy is configured but EGRESS_PROXY_HEALTH_URL is not: "
            "the proxy's enforcement mode cannot be verified."
        )

    if not settings.dns_preflight_enabled:
        issues.append("DNS_PREFLIGHT_ENABLED is false: the pre-connection SSRF check is disabled.")

    if settings.allow_private_networks:
        issues.append("ALLOW_PRIVATE_NETWORKS is true: private/loopback targets are permitted.")

    if (
        settings.default_domain_policy == "deny"
        and not settings.allowed_domains.strip()
    ):
        issues.append("DEFAULT_DOMAIN_POLICY is 'deny' but ALLOWED_DOMAINS is empty.")

    if settings.analysis_provider == "local_mock":
        issues.append(
            "ANALYSIS_PROVIDER is 'local_mock': documents are not sent to a "
            "real analysis provider."
        )
    if settings.analysis_provider == "http":
        if not settings.analysis_endpoint_url:
            issues.append(
                "ANALYSIS_PROVIDER is 'http' but ANALYSIS_ENDPOINT_URL is not set."
            )
        elif urlparse(settings.analysis_endpoint_url).scheme != "https":
            issues.append(
                "ANALYSIS_ENDPOINT_URL does not use https: provider traffic "
                "would not be encrypted."
            )
        if not settings.analysis_api_token:
            issues.append(
                "ANALYSIS_PROVIDER is 'http' but ANALYSIS_API_TOKEN is not set."
            )
    if settings.analysis_allow_insecure_local:
        issues.append(
            "ANALYSIS_ALLOW_INSECURE_LOCAL is true: plain-HTTP provider "
            "endpoints are permitted."
        )
    if settings.analysis_allow_private_endpoints:
        issues.append(
            "ANALYSIS_ALLOW_PRIVATE_ENDPOINTS is true: private/loopback "
            "analysis endpoints are permitted."
        )
    if (
        settings.analysis_provider == "http"
        and settings.egress_proxy_url
        and not settings.analysis_use_egress_proxy
    ):
        issues.append(
            "ANALYSIS_USE_EGRESS_PROXY is false: analysis provider traffic "
            "would bypass the configured egress proxy."
        )

    return issues
