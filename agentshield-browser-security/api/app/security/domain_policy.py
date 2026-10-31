from __future__ import annotations

from app.security.errors import DOMAIN_BLOCKED, SecurityViolation


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
        raise ValueError(f"domain policy patterns must be hostnames: {pattern}")
    return normalized


def parse_domain_list(value: str) -> tuple[str, ...]:
    return tuple(
        _validate_pattern(part) for part in value.split(",") if part.strip()
    )


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
        if any(domain_matches(hostname, pattern) for pattern in self._blocked):
            raise SecurityViolation(
                DOMAIN_BLOCKED, "The destination domain is blocked by policy."
            )

        if any(domain_matches(hostname, pattern) for pattern in self._allowed):
            return

        if self._default_policy == "deny":
            raise SecurityViolation(
                DOMAIN_BLOCKED, "The destination domain is not on the allowlist."
            )
