"""
Proxy authentication helpers.

Deployment mechanism
--------------------
The egress proxy authenticates downloads with HTTP Basic
``Proxy-Authorization`` (the only proxy-auth scheme a standard forward/CONNECT
proxy speaks).  The operator supplies the password through PROXY_AUTH_TOKEN;
the username is fixed ("agentshield").  The downloader injects the credentials
as userinfo on the proxy URL handed to httpx, which makes httpcore attach a
``Proxy-Authorization: Basic`` header to the proxy request (forwarded GET) or
to the CONNECT tunnel establishment — never to the origin server, so
credentials cannot leak over an HTTPS tunnel.

Secret handling
---------------
The token must never appear in logs, error messages or readiness payloads.
``redact_proxy_url`` strips userinfo and is the only sanctioned way to render
a proxy URL in user-facing output.
"""
from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

# Fixed Basic-auth username used against the egress proxy.
PROXY_AUTH_USERNAME = "agentshield"


def build_authorized_proxy_url(proxy_url: str, token: str) -> str:
    """
    Return proxy_url with Basic-auth credentials embedded as userinfo.

    - Empty token → proxy_url unchanged (no auth configured).
    - Any pre-existing userinfo on proxy_url is replaced by the
      PROXY_AUTH_USERNAME/ token pair.
    - The token is percent-encoded so arbitrary secret characters cannot
      corrupt the URL structure.
    """
    if not token or not proxy_url:
        return proxy_url

    parts = urlsplit(proxy_url)
    userinfo = f"{PROXY_AUTH_USERNAME}:{quote(token, safe='')}"
    host = parts.hostname or ""
    if ":" in host:  # IPv6 literal must be bracketed inside userinfo@host
        host = f"[{host}]"
    netloc = f"{userinfo}@{host}"
    if parts.port is not None:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def redact_proxy_url(proxy_url: str) -> str:
    """Strip any userinfo from proxy_url so it is safe to log."""
    if not proxy_url:
        return proxy_url
    parts = urlsplit(proxy_url)
    if "@" not in parts.netloc:
        return proxy_url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
