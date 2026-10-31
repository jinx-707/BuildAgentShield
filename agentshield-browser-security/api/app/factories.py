import hashlib
import json

from app.config import Settings
from app.interfaces.inspection import ContentInspector
from app.interfaces.policy import PolicyEngine
from app.mocks.inspection import MockContentInspector
from app.mocks.policy import MockPolicyEngine
from app.security.content_inspector import PromptInjectionInspector
from app.security.dns_policy import DnsValidator
from app.security.policy_engine import RealPolicyEngine
from app.security.preflight import NetworkPreflight
from app.security.url_policy import UrlPolicy


def compute_policy_fingerprint(settings: Settings) -> str:
    """Compute a short fingerprint of the four canonical policy values.

    Uses the same canonical algorithm as the JavaScript
    computePolicyFingerprint() in proxy/src/lib/policy.js so that the API,
    worker and proxy log the same fingerprint when loaded with the same env
    vars.  Operators can compare startup logs to detect policy drift.

    Returns the first 16 hex characters of SHA-256(canonical JSON).
    """
    canonical_domains = ",".join(
        sorted(p.strip().lower() for p in settings.allowed_domains.split(",") if p.strip())
    )
    canonical_blocked = ",".join(
        sorted(p.strip().lower() for p in settings.blocked_domains.split(",") if p.strip())
    )
    canonical_ports = ",".join(
        sorted(p.strip() for p in settings.allowed_ports.split(",") if p.strip())
    )
    canonical = json.dumps(
        {
            "allowedDomains": canonical_domains,
            "blockedDomains": canonical_blocked,
            "defaultDomainPolicy": settings.default_domain_policy.lower(),
            "allowedPorts": canonical_ports,
        },
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def build_policy_engine(settings: Settings) -> PolicyEngine:
    backend = settings.policy_backend

    if backend == "mock":
        if settings.environment == "production":
            raise ValueError(
                "mock policy backend is not permitted in production; "
                "set POLICY_BACKEND=egress-policy or another real backend"
            )
        return MockPolicyEngine()

    if backend == "egress-policy":
        return RealPolicyEngine(
            allowed_domains=settings.allowed_domains,
            blocked_domains=settings.blocked_domains,
            default_domain_policy=settings.default_domain_policy,
        )

    raise ValueError(
        f"Unsupported policy_backend '{backend}'. "
        "Supported: 'mock' (development only), 'egress-policy'."
    )


def build_content_inspector(settings: Settings) -> ContentInspector:
    backend = settings.inspection_backend

    if backend == "mock":
        if settings.environment == "production":
            raise ValueError(
                "mock inspection backend is not permitted in production; "
                "set INSPECTION_BACKEND=prompt-injection or another real backend"
            )
        return MockContentInspector()

    if backend == "prompt-injection":
        return PromptInjectionInspector()

    raise ValueError(
        f"Unsupported inspection_backend '{backend}'. "
        "Supported: 'mock' (development only), 'prompt-injection'."
    )


def build_network_preflight(settings: Settings) -> NetworkPreflight:
    return NetworkPreflight(
        url_policy=UrlPolicy(
            allowed_ports=settings.allowed_ports,
            allowed_domains=settings.allowed_domains,
            blocked_domains=settings.blocked_domains,
            default_domain_policy=settings.default_domain_policy,
            allow_private_networks=settings.allow_private_networks,
        ),
        dns_validator=DnsValidator(
            allow_private_networks=settings.allow_private_networks
        ),
        dns_enabled=settings.dns_preflight_enabled,
    )
