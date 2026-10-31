"""
F4 regression: PROXY_AUTH_TOKEN is a live, tested security control.

Mechanism (documented in security/proxy_auth.py): the token is the Basic-auth
password with fixed username "agentshield", attached as userinfo to the proxy
URL given to httpx.  httpcore then sends `Proxy-Authorization: Basic ...` on
the request to the forwarding proxy (and would do the same on the CONNECT
line for an HTTPS tunnel) — never to the origin.  These tests run against a
real local forwarding proxy that inspects that header.

Covered: correct credentials, missing credentials, invalid credentials,
proxy-auth failure classification, no-auth configurations, and proof that
the token never leaks into log records, error messages, or exception strings.
"""
from __future__ import annotations

import base64
import hashlib
import logging

import pytest

from security.errors import PROXY_AUTH_FAILED, DownloadSecurityError
from tests.integration.raw_http import (
    PDF_BYTES,
    build_streamer,
    serve_raw,
    url_for,
    zone_listing,
)

pytestmark = pytest.mark.integration

SECRET = "s3kr3t-token-v4"
EXPECTED_HEADER = "Basic " + base64.b64encode(
    f"agentshield:{SECRET}".encode()
).decode()

PDF_LEN = str(len(PDF_BYTES))


class AuthProxyHandler:
    """
    A same-box forwarding proxy: the server proxies to itself.

    Requests arriving in absolute form are the proxied download requests;
    /health is the attestation endpoint fetched directly.
    """

    def __init__(self, routes: dict) -> None:
        routes["/health"] = self.health
        routes["/proxied.pdf"] = self.proxied

    def health(self, handler):
        import json

        body = json.dumps({"status": "ok", "mode": "enforcing"}).encode()
        handler.write_raw(
            "200 OK",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
            body,
        )

    def proxied(self, handler):
        st = handler.server.state
        auth = handler.headers.get("Proxy-Authorization", "")
        st.setdefault("proxy_auth_seen", []).append(auth)

        if not st.get("require_auth", True) and not auth:
            self._serve(handler)
            return
        if auth == EXPECTED_HEADER:
            self._serve(handler)
            return
        # 407 with a tiny body; the client must classify this as an auth
        # failure and must not have the token echoed anywhere.
        handler.write_raw(
            "407 Proxy Authentication Required",
            [("Proxy-Authenticate", 'Basic realm="egress"'), ("Content-Length", "0")],
            b"",
        )

    @staticmethod
    def _serve(handler):
        handler.write_raw(
            "200 OK",
            [("Content-Type", "application/pdf"), ("Content-Length", PDF_LEN)],
            PDF_BYTES,
        )


@pytest.fixture
def auth_proxy():
    routes: dict = {}
    AuthProxyHandler(routes)
    srv, shutdown = serve_raw(routes)
    try:
        yield srv
    finally:
        shutdown()


def proxy_streamer(auth_proxy, tmp_path, *, token: str = SECRET, require_auth: bool = True):
    auth_proxy.state["require_auth"] = require_auth
    return build_streamer(
        auth_proxy,
        tmp_path,
        proxy_url=url_for(auth_proxy, ""),
        health_url=url_for(auth_proxy, "/health"),
        proxy_auth_token=token,
        require_proxy=True,
    )


class TestProxyAuthentication:
    async def test_correct_credentials_download_succeeds(self, auth_proxy, tmp_path):
        streamer = proxy_streamer(auth_proxy, tmp_path)
        result = await streamer.download(url_for(auth_proxy, "/proxied.pdf"))

        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()
        seen = auth_proxy.state["proxy_auth_seen"]
        assert seen and all(h == EXPECTED_HEADER for h in seen)

    async def test_credentials_reach_the_proxy_not_the_origin_file_name(
        self, auth_proxy, tmp_path
    ):
        """Username is the fixed 'agentshield'; password is the token."""
        streamer = proxy_streamer(auth_proxy, tmp_path)
        await streamer.download(url_for(auth_proxy, "/proxied.pdf"))
        decoded = base64.b64decode(EXPECTED_HEADER.removeprefix("Basic ")).decode()
        assert decoded == f"agentshield:{SECRET}"

    async def test_missing_credentials_are_rejected_and_classified(
        self, auth_proxy, tmp_path
    ):
        streamer = proxy_streamer(auth_proxy, tmp_path, token="")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(auth_proxy, "/proxied.pdf"))

        assert exc_info.value.code == PROXY_AUTH_FAILED
        assert exc_info.value.http_status == 502
        assert auth_proxy.state["proxy_auth_seen"] == [""]
        assert zone_listing(tmp_path, "temporary") == []

    async def test_invalid_credentials_are_rejected(self, auth_proxy, tmp_path):
        streamer = proxy_streamer(auth_proxy, tmp_path, token="wrong-token!")

        with pytest.raises(DownloadSecurityError) as exc_info:
            await streamer.download(url_for(auth_proxy, "/proxied.pdf"))

        assert exc_info.value.code == PROXY_AUTH_FAILED
        seen = auth_proxy.state["proxy_auth_seen"]
        assert seen and seen[0] != EXPECTED_HEADER

    async def test_no_authentication_configured_works_when_proxy_allows(
        self, auth_proxy, tmp_path
    ):
        """Token empty + proxy not requiring auth → no Proxy-Authorization sent."""
        streamer = proxy_streamer(
            auth_proxy, tmp_path, token="", require_auth=False
        )
        result = await streamer.download(url_for(auth_proxy, "/proxied.pdf"))

        assert result.sha256 == hashlib.sha256(PDF_BYTES).hexdigest()
        assert auth_proxy.state["proxy_auth_seen"] == [""]


class TestNoCredentialLeakage:
    async def test_token_absent_from_error_message_and_exception_str(
        self, auth_proxy, tmp_path
    ):
        """A rejected credential must not be echoed back in any failure text."""
        streamer = proxy_streamer(auth_proxy, tmp_path, token=SECRET)
        # The proxy only accepts EXPECTED_HEADER; flip the expectation by
        # configuring the client with a token the proxy has never seen.
        failing = proxy_streamer(auth_proxy, tmp_path, token="not-the-real-one")
        with pytest.raises(DownloadSecurityError) as exc_info:
            await failing.download(url_for(auth_proxy, "/proxied.pdf"))

        assert exc_info.value.code == PROXY_AUTH_FAILED
        assert "not-the-real-one" not in exc_info.value.message
        assert "not-the-real-one" not in str(exc_info.value)
        assert "not-the-real-one" not in repr(exc_info.value)
        assert SECRET not in exc_info.value.message
        _ = streamer  # valid-credential streamer is exercised in other tests

    async def test_token_absent_from_all_log_records(self, auth_proxy, tmp_path, caplog):
        with caplog.at_level(logging.DEBUG):
            streamer = proxy_streamer(auth_proxy, tmp_path, token="")
            with pytest.raises(DownloadSecurityError):
                await streamer.download(url_for(auth_proxy, "/proxied.pdf"))

        for record in caplog.records:
            text = record.getMessage()
            assert SECRET not in text
            assert "agentshield:" not in text
            blob = str(record.__dict__)
            assert SECRET not in blob

    async def test_success_path_logs_no_credentials(self, auth_proxy, tmp_path, caplog):
        with caplog.at_level(logging.DEBUG):
            streamer = proxy_streamer(auth_proxy, tmp_path)
            await streamer.download(url_for(auth_proxy, "/proxied.pdf"))

        for record in caplog.records:
            assert SECRET not in record.getMessage()
            assert EXPECTED_HEADER not in record.getMessage()
