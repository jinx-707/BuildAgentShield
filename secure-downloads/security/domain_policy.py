"""
Domain and port policy for the secure-downloads module.

Mirrors the logic in the browser-security API (api/app/security/domain_policy.py
and api/app/security/ports.py) but lives independently here.

Policy evaluation order
-----------------------
1. Blocked list checked first (explicit deny wins over everything).
2. Allowed list checked second.
3. Default policy applies if neither list matched.
"""
from __future__ import annotations

from security.errors import DOMAIN_BLOCKED, PORT_NOT_ALLOWED, DownloadSecurityError


# ── Hostname normalisation ─────────────────────────────────────────────────────

def normalize_hostname(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not normalized:
        return ""
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError:
        normalized = normalized.encode("idna").decode("ascii").lower()
    return normalized


def domain_matches(hostname: str, pattern: str) -> bool:
    host = normalize_hostname(hostname)
    rule = normalize_hostname(pattern)
    if not host or not rule:
        return False
    if rule.startswith("*."):
        suffix = rule[2:]
        return bool(suffix) and host.endswith(f".{suffix}")
    return host == rule


def _validate_pattern(pattern: str) -> str:
    normalized = normalize_hostname(pattern)
    if not normalized:
        raise ValueError("empty domain policy pattern")
    if normalized == "*":
        raise ValueError("standalone wildcard is not permitted")
    if "*" in normalized and not normalized.startswith("*."):
        raise ValueError(f"unsupported wildcard pattern: {pattern}")
    if normalized.startswith("*.") and len(normalized) <= 2:
        raise ValueError(f"invalid wildcard pattern: {pattern}")
    if "://" in normalized or "/" in normalized:
        raise ValueError(f"domain policy patterns must be hostnames, not URLs: {pattern}")
    return normalized


def parse_domain_list(value: str) -> tuple[str, ...]:
    return tuple(_validate_pattern(p) for p in value.split(",") if p.strip())


class DomainPolicy:
    def __init__(
        self,
        *,
        allowed_domains: str = "",
        blocked_domains: str = "",
        default_policy: str = "deny",
    ) -> None:
        self._allowed = parse_domain_list(allowed_domains)
        self._blocked = parse_domain_list(blocked_domains)
        self._default_policy = default_policy.lower()
        if self._default_policy not in {"allow", "deny"}:
            raise ValueError("default domain policy must be 'allow' or 'deny'")

    def evaluate(self, hostname: str) -> None:
        if any(domain_matches(hostname, p) for p in self._blocked):
            raise DownloadSecurityError(
                DOMAIN_BLOCKED, "The destination domain is blocked by policy."
            )
        if any(domain_matches(hostname, p) for p in self._allowed):
            return
        if self._default_policy == "deny":
            raise DownloadSecurityError(
                DOMAIN_BLOCKED, "The destination domain is not on the allowlist."
            )


# ── Port policy ───────────────────────────────────────────────────────────────

def parse_port_spec(spec: str) -> list[tuple[int, int]]:
    """Parse "80,443,8080-8090" into a list of (low, high) inclusive ranges."""
    ranges: list[tuple[int, int]] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            raw_low, raw_high = part.split("-", 1)
            low, high = int(raw_low), int(raw_high)
        else:
            low = high = int(part)
        if not (1 <= low <= high <= 65535):
            raise ValueError(f"invalid port range: {part!r}")
        ranges.append((low, high))
    if not ranges:
        raise ValueError("port spec must contain at least one port")
    return ranges


class PortPolicy:
    def __init__(self, spec: str = "80,443") -> None:
        self._ranges = parse_port_spec(spec)

    def is_allowed(self, port: int) -> bool:
        return any(low <= port <= high for low, high in self._ranges)

    def assert_allowed(self, port: int) -> None:
        if not self.is_allowed(port):
            raise DownloadSecurityError(
                PORT_NOT_ALLOWED,
                "The destination port is not permitted by policy.",
            )
