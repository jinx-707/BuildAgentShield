"""
F4 unit coverage: proxy-auth configuration and URL construction.

Settings-level rules:
* PROXY_AUTH_TOKEN without EGRESS_PROXY_URL is rejected — no dead config.
* The token is whitespace-stripped at ingest.

Helper-level rules (security/proxy_auth.py):
* credentials are attached as proxy-URL userinfo with the fixed username;
* the token is percent-encoded so it cannot corrupt the URL structure;
* redaction strips userinfo so logs never carry the credential.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from config.settings import Settings
from security.proxy_auth import (
    PROXY_AUTH_USERNAME,
    build_authorized_proxy_url,
    redact_proxy_url,
)


def make(**overrides) -> Settings:
    base = dict(
        environment="test",
        _env_file=None,
        database_url="sqlite+aiosqlite:///:memory:",
    )
    base.update(overrides)
    return Settings(**base)


class TestSettingsValidation:
    def test_token_without_proxy_url_is_rejected(self):
        with pytest.raises(ValidationError, match="PROXY_AUTH_TOKEN"):
            make(proxy_auth_token="tok", egress_proxy_url="")

    def test_token_with_proxy_url_builds(self):
        settings = make(
            proxy_auth_token="tok", egress_proxy_url="http://proxy.internal:3128"
        )
        assert settings.proxy_auth_token == "tok"

    def test_empty_token_is_allowed_and_stripped(self):
        settings = make(
            proxy_auth_token="   ", egress_proxy_url="http://proxy.internal:3128"
        )
        assert settings.proxy_auth_token == ""

    def test_token_whitespace_stripped(self):
        settings = make(
            proxy_auth_token="  tok  ", egress_proxy_url="http://proxy.internal:3128"
        )
        assert settings.proxy_auth_token == "tok"


class TestBuildAuthorizedProxyUrl:
    def test_no_token_returns_url_unchanged(self):
        url = "http://proxy.internal:3128"
        assert build_authorized_proxy_url(url, "") == url

    def test_empty_proxy_url_stays_empty(self):
        assert build_authorized_proxy_url("", "tok") == ""

    def test_credentials_are_attached_with_fixed_username(self):
        out = build_authorized_proxy_url("http://proxy.internal:3128", "tok")
        assert out == f"http://{PROXY_AUTH_USERNAME}:tok@proxy.internal:3128"

    def test_special_characters_are_percent_encoded(self):
        out = build_authorized_proxy_url("http://proxy.internal:3128", "p@ss:w/rd?#1%")
        userinfo = out.split("@")[0].split("://", 1)[1]
        username, password = userinfo.split(":", 1)
        assert username == PROXY_AUTH_USERNAME
        from urllib.parse import unquote

        assert unquote(password) == "p@ss:w/rd?#1%"
        assert "/" not in password and "@" not in password

    def test_existing_userinfo_is_replaced(self):
        out = build_authorized_proxy_url("http://old:creds@proxy.internal:3128", "tok")
        assert out.count("@") == 1
        assert "old" not in out and "creds" not in out

    def test_port_is_preserved(self):
        out = build_authorized_proxy_url("http://127.0.0.1:3128", "tok")
        assert out.endswith("@127.0.0.1:3128")

    def test_ipv6_host_is_bracketed(self):
        out = build_authorized_proxy_url("http://[::1]:3128", "tok")
        assert "@[::1]:3128" in out

    def test_https_proxy_scheme_preserved(self):
        out = build_authorized_proxy_url("https://proxy.internal:3128", "tok")
        assert out.startswith("https://")


class TestRedactProxyUrl:
    def test_userinfo_is_stripped(self):
        assert (
            redact_proxy_url("http://agentshield:sup3rsekret@proxy.internal:3128")
            == "http://proxy.internal:3128"
        )

    def test_clean_url_unchanged(self):
        assert redact_proxy_url("http://proxy.internal:3128") == "http://proxy.internal:3128"

    def test_empty_unchanged(self):
        assert redact_proxy_url("") == ""

    def test_redaction_removes_the_token(self):
        secret = "s3kr3t"
        built = build_authorized_proxy_url("http://proxy.internal:3128", secret)
        assert secret in built
        assert secret not in redact_proxy_url(built)
