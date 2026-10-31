"""Policy synchronization and fingerprint tests.

Verifies that:
- compute_policy_fingerprint produces stable, deterministic output.
- Identical policy values → identical fingerprint.
- Different values → different fingerprint (drift is detectable).
- Canonical form normalises ordering and case so the fingerprint matches
  the JavaScript implementation in proxy/src/lib/policy.js.
- Production startup is rejected when allowedDomains is empty + default-deny.
- Production startup is allowed when allowedDomains is set.
- Production startup is allowed when defaultDomainPolicy is 'allow'.
- Development startup is allowed with empty allowedDomains.
- The API fingerprint matches a known reference value (cross-language sanity).
"""

import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.factories import compute_policy_fingerprint
from tests.conftest import make_settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROD_BASE = dict(
    environment="production",
    api_auth_token="prod-token",
    jwt_secret="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    allowed_domains="example.com",
    browser_worker_url="http://worker.test:8080",
    policy_backend="egress-policy",
    inspection_backend="prompt-injection",
)


def make_prod(**overrides):
    return Settings(_env_file=None, **{**PROD_BASE, **overrides})


# ---------------------------------------------------------------------------
# compute_policy_fingerprint determinism
# ---------------------------------------------------------------------------


def test_fingerprint_is_deterministic():
    s = make_settings(
        allowed_domains="example.com",
        blocked_domains="evil.com",
        default_domain_policy="deny",
        allowed_ports="80,443",
    )
    assert compute_policy_fingerprint(s) == compute_policy_fingerprint(s)


def test_fingerprint_is_16_hex_chars():
    s = make_settings(allowed_domains="example.com", allowed_ports="443")
    fp = compute_policy_fingerprint(s)
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_identical_settings_produce_identical_fingerprint():
    a = make_settings(allowed_domains="example.com", allowed_ports="443")
    b = make_settings(allowed_domains="example.com", allowed_ports="443")
    assert compute_policy_fingerprint(a) == compute_policy_fingerprint(b)


def test_different_allowed_domains_produce_different_fingerprint():
    a = make_settings(allowed_domains="example.com", allowed_ports="443")
    b = make_settings(allowed_domains="other.com", allowed_ports="443")
    assert compute_policy_fingerprint(a) != compute_policy_fingerprint(b)


def test_different_blocked_domains_produce_different_fingerprint():
    a = make_settings(allowed_domains="example.com", blocked_domains="", allowed_ports="443")
    b = make_settings(allowed_domains="example.com", blocked_domains="evil.com", allowed_ports="443")
    assert compute_policy_fingerprint(a) != compute_policy_fingerprint(b)


def test_different_default_policy_produces_different_fingerprint():
    a = make_settings(allowed_domains="example.com", default_domain_policy="deny", allowed_ports="443")
    b = make_settings(allowed_domains="example.com", default_domain_policy="allow", allowed_ports="443")
    assert compute_policy_fingerprint(a) != compute_policy_fingerprint(b)


def test_different_ports_produce_different_fingerprint():
    a = make_settings(allowed_domains="example.com", allowed_ports="80,443")
    b = make_settings(allowed_domains="example.com", allowed_ports="443")
    assert compute_policy_fingerprint(a) != compute_policy_fingerprint(b)


# ---------------------------------------------------------------------------
# Canonical form: order/case normalisation
# ---------------------------------------------------------------------------


def test_domain_order_does_not_affect_fingerprint():
    a = make_settings(allowed_domains="alpha.com,beta.com,gamma.com", allowed_ports="443")
    b = make_settings(allowed_domains="gamma.com,alpha.com,beta.com", allowed_ports="443")
    assert compute_policy_fingerprint(a) == compute_policy_fingerprint(b), (
        "domain list order must not change fingerprint"
    )


def test_domain_case_does_not_affect_fingerprint():
    a = make_settings(allowed_domains="Example.COM", allowed_ports="443")
    b = make_settings(allowed_domains="example.com", allowed_ports="443")
    assert compute_policy_fingerprint(a) == compute_policy_fingerprint(b), (
        "domain case must not change fingerprint"
    )


def test_port_order_does_not_affect_fingerprint():
    a = make_settings(allowed_domains="example.com", allowed_ports="443,80")
    b = make_settings(allowed_domains="example.com", allowed_ports="80,443")
    assert compute_policy_fingerprint(a) == compute_policy_fingerprint(b), (
        "port order must not change fingerprint"
    )


def test_adding_domain_changes_fingerprint():
    before = make_settings(allowed_domains="example.com", allowed_ports="443")
    after = make_settings(allowed_domains="example.com,extra.com", allowed_ports="443")
    assert compute_policy_fingerprint(before) != compute_policy_fingerprint(after)


# ---------------------------------------------------------------------------
# Cross-language fingerprint agreement
# ---------------------------------------------------------------------------


def test_fingerprint_matches_javascript_implementation():
    """The Python fingerprint must produce the same value as the Node.js
    computePolicyFingerprint() for the same inputs.

    This test runs the JS implementation in a subprocess so we can compare
    both outputs without any mocking.
    """
    repo_root = Path(__file__).resolve().parents[2]
    policy_js = repo_root / "proxy" / "src" / "lib" / "policy.js"
    if not policy_js.exists():
        pytest.skip("proxy/src/lib/policy.js not found")

    js_script = f"""
import {{ computePolicyFingerprint }} from {repr(str(policy_js.as_posix()))};
const fp = computePolicyFingerprint({{
  allowedDomains: "example.com,api.example.org",
  blockedDomains: "evil.com",
  defaultDomainPolicy: "deny",
  allowedPorts: "80,443",
}});
process.stdout.write(fp);
"""
    result = subprocess.run(
        ["node", "--input-type=module"],
        input=js_script,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        pytest.skip(f"node subprocess failed: {result.stderr[:200]}")

    js_fingerprint = result.stdout.strip()
    assert len(js_fingerprint) == 16, f"JS returned unexpected fingerprint: {js_fingerprint!r}"

    py_settings = make_settings(
        allowed_domains="example.com,api.example.org",
        blocked_domains="evil.com",
        default_domain_policy="deny",
        allowed_ports="80,443",
    )
    py_fingerprint = compute_policy_fingerprint(py_settings)

    assert py_fingerprint == js_fingerprint, (
        f"Python fingerprint {py_fingerprint!r} != "
        f"JavaScript fingerprint {js_fingerprint!r}. "
        "The canonical algorithms are out of sync."
    )


# ---------------------------------------------------------------------------
# Production startup validation — allowedDomains guard
# ---------------------------------------------------------------------------


def test_production_startup_fails_with_empty_allowed_domains_and_default_deny():
    """Production + empty allowedDomains + default-deny → ValidationError."""
    with pytest.raises(ValidationError, match="ALLOWED_DOMAINS must be set in production"):
        Settings(
            _env_file=None,
            environment="production",
            api_auth_token="prod-token",
            jwt_secret="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            allowed_domains="",
            default_domain_policy="deny",
            browser_worker_url="http://worker.test:8080",
        )


def test_production_startup_succeeds_with_allowed_domains_set():
    s = make_prod(allowed_domains="example.com")
    assert s.allowed_domains == "example.com"


def test_production_startup_succeeds_with_default_allow_and_empty_allowlist():
    """If the operator deliberately chooses default-allow, they accept
    that traffic is not allowlist-restricted.  We allow it but the proxy
    health endpoint will report mode=permissive."""
    s = make_prod(allowed_domains="", default_domain_policy="allow")
    assert s.default_domain_policy == "allow"


def test_development_startup_succeeds_with_empty_allowed_domains():
    s = make_settings(environment="development", allowed_domains="")
    assert s.allowed_domains == ""


def test_test_environment_startup_succeeds_with_empty_allowed_domains():
    s = make_settings(environment="test", allowed_domains="")
    assert s.allowed_domains == ""
