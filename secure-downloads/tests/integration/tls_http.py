"""
Local HTTPS variant of the raw-framing test server.

The production URL validator is HTTPS-only, so API-level end-to-end tests
exercise the real download path (preflight, DNS/IP policy, TLS, streaming,
framing acceptance, scan gate, zone transition) against a self-signed
loopback server rather than a plain-HTTP shortcut.

The certificate is generated with the local ``openssl`` binary and trusted by
the process via ``SSL_CERT_FILE`` (httpx's ``verify=True`` builds its default
context from the OpenSSL default paths).  Tests skip when openssl is not
installed.  Nothing here is used in production.
"""
from __future__ import annotations

import shutil
import ssl
import subprocess
from pathlib import Path

import pytest

from tests.integration.raw_http import RawServer


class TlsRawServer(RawServer):
    """RawServer whose listening socket performs TLS."""

    def __init__(self, routes: dict[str, object], *, certfile: Path, keyfile: Path) -> None:
        super().__init__(routes)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certfile), str(keyfile))
        self.socket = context.wrap_socket(self.socket, server_side=True)


def generate_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    """
    Create a one-day self-signed certificate for 127.0.0.1 / localhost.

    Raises pytest.skip when the openssl binary is unavailable, so the suite
    remains runnable on a machine without it (the transport-level tests cover
    the same downloader logic over plain HTTP).
    """
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl binary is required for local HTTPS end-to-end tests")

    certfile = directory / "server-cert.pem"
    keyfile = directory / "server-key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(keyfile),
            "-out",
            str(certfile),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return certfile, keyfile


def tls_url(srv: TlsRawServer, path: str) -> str:
    port = srv.server_address[1]
    return f"https://127.0.0.1:{port}{path}"
