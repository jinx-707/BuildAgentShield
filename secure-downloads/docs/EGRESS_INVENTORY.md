# Network Egress Inventory

Complete list of outbound network paths from the service, compiled by reading
every module that opens a socket or delegates to one. No new external HTTP
client may be added without the review checklist at the end of this document.

## Summary

| # | Path | Source module | Destination | Transport | Auth |
|---|---|---|---|---|---|
| E1 | Source document download | `services/downloader.py` | Caller-supplied HTTPS URL (validated) | TCP/TLS via `httpx.AsyncHTTPTransport`, optionally through the egress proxy | None to origin; `Proxy-Authorization` when configured |
| E2 | Analysis provider request | `integrations/analysis_adapter.py` via `security/analysis_egress.py` | `ANALYSIS_ENDPOINT_URL` (fixed at startup) | TCP/TLS via `httpx.AsyncHTTPTransport`, optionally through the egress proxy | `Authorization: Bearer <ANALYSIS_API_TOKEN>` |
| E3 | Egress-proxy health probe | `security/proxy_enforcement.py` | `EGRESS_PROXY_HEALTH_URL` | TCP/HTTP via a dedicated `httpx.AsyncClient`, direct (never proxied) | None (URL userinfo would be sent by httpx as Basic; credentials are not used by the service here) |
| E4 | DNS resolution | `security/ssrf.py`, `security/dns_revalidation.py` | System resolver (`socket.getaddrinfo`) | UDP/TCP DNS as configured by the host resolver | None |
| E5 | ClamAV scan / ping | `services/scanner.py` | `CLAMAV_HOST:CLAMAV_PORT` | clamd TCP protocol (`clamd` package); INSTREAM and PING | None; protocol is unauthenticated and unencrypted |
| E6 | Database | `models/database.py` | `DATABASE_URL` | SQLite file (default) or PostgreSQL TCP when a driver is added | Driver-level credentials in the URL |
| E7 | Outbound from tests/scripts only | `tests/`, `scripts/load_test.py` | Loopback only | Loopback TCP/TLS | None |

There are no other outbound clients: no `requests`, no `aiohttp`, no websocket
client, no SMTP/S3 SDK, no subprocess network calls, and no usage of environment
proxy variables.

## E1 — Source document download

- **Code:** `services/downloader.py` (`DownloadStreamer`), with
  `security/preflight.py`, `security/dns_revalidation.py`,
  `security/proxy_enforcement.py`.
- **Destination:** the HTTPS URL submitted by the caller. Scheme HTTPS only;
  host must satisfy `ALLOWED_DOMAINS`/`BLOCKED_DOMAINS`/`DEFAULT_DOMAIN_POLICY`;
  port must be in `ALLOWED_PORTS`.
- **Transport:** `httpx.AsyncClient` with a freshly built
  `httpx.AsyncHTTPTransport` per hop (first request and every redirect).
  `trust_env=False`, `verify=True`. Proxy from `EGRESS_PROXY_URL` when set,
  with optional Basic credentials derived from `PROXY_AUTH_TOKEN`.
- **SSRF controls:** URL/domain/port policy; preflight DNS resolution validating
  every A/AAAA record; `DnsRevalidatingTransport` re-resolving and re-checking
  immediately before each request; `EnforcingProxyTransport` re-attesting the
  proxy mode on every request (success cached 5 s).
- **Proxy enforcement:** required in production/staging (startup fails
  otherwise). If configured, every request goes through it; there is no
  per-request bypass. Without a proxy (development only), in-process checks are
  the only boundary.
- **Timeouts:** connect 10 s, per-read 30 s, total deadline 120 s (defaults,
  configurable). The deadline wraps the whole transfer.
- **Response limit:** `MAX_FILE_SIZE_BYTES` (default 50 MiB), enforced by a
  byte counter during streaming — `Content-Length` is never trusted.
- **Redirects:** manual, maximum `MAX_REDIRECTS` (default 5); every destination
  runs the full policy + preflight again; each hop has its own client and
  transport, closing the previous connection before the next request.
- **Framing:** complete, unambiguous HTTP only. Conflicting/multiple
  `Content-Length`, `Content-Length` plus chunked, invalid lengths, truncation,
  and broken chunk framing fail the download with `RESPONSE_INCOMPLETE`.
- **Tests:** `tests/integration/test_downloader_http.py` (20),
  `test_redirect_smuggling.py` (7), `test_response_acceptance.py` (11),
  `test_download_timeouts.py` (7), `test_proxy_auth_http.py` (8),
  `tests/integration/test_e2e_demos.py` (29), plus unit transport/SSRF tests.
- **Known limits:** DNS re-validation is a gate, not IP pinning; behind a proxy
  the proxy resolves the name and is authoritative.

## E2 — Analysis provider request

- **Code:** `integrations/analysis_adapter.py`, `security/analysis_egress.py`.
- **Destination:** `ANALYSIS_ENDPOINT_URL`, fixed at construction. HTTPS port
  443; plain HTTP only for loopback with `ANALYSIS_ALLOW_INSECURE_LOCAL=true`
  (test-only, refused in production).
- **Transport:** explicit chain built per request:
  `AsyncHTTPTransport(proxy=... or direct, verify=True)` →
  `DnsRevalidatingTransport` → `EnforcingProxyTransport` (when a proxy is set)
  → `DestinationCheckTransport`. `trust_env=False`.
- **Authentication:** `Authorization: Bearer <ANALYSIS_API_TOKEN>`; the token is
  never logged and never included in error text. Credentials must not be placed
  in the endpoint URL (validated).
- **SSRF controls:** endpoint identity check at construction and at dispatch;
  private/loopback/link-local/metadata targets rejected unless
  `ANALYSIS_ALLOW_PRIVATE_ENDPOINTS=true` (test-only); per-request DNS
  re-validation.
- **Proxy enforcement:** `ANALYSIS_USE_EGRESS_PROXY=true` is required in
  production; the same attested proxy and health URL as E1 are used.
- **Timeouts:** connect 5 s, read 30 s, total 60 s (defaults, configurable);
  additionally a job-level wall-clock deadline (`ANALYSIS_JOB_TIMEOUT_SECONDS`,
  default 120 s).
- **Size limits:** request payload `ANALYSIS_MAX_PAYLOAD_BYTES` (10 MiB);
  response `ANALYSIS_MAX_RESPONSE_BYTES` (2 MiB). Responses are read bounded.
- **Redirects:** disabled. Any 3xx is `ANALYSIS_REDIRECT_BLOCKED`; the bearer
  token is never replayed to a new destination.
- **Tests:** `tests/integration/test_analysis_adapter_http.py` (16, against a
  local fake provider implementing contract v1), `tests/unit/test_analysis_egress.py`
  (12), `tests/unit/test_analysis_models.py` (23), `test_analysis_service.py`
  (18), E2E demo 5 in `test_e2e_demos.py`.
- **Known limits:** the local test server is **not** a real provider
  integration; no vendor has been selected. Provider-side prompt-injection
  resistance is out of scope.

## E3 — Egress-proxy health probe

- **Code:** `security/proxy_enforcement.py` (`assert_proxy_enforcing`,
  `EnforcingProxyTransport`).
- **Destination:** `EGRESS_PROXY_HEALTH_URL`, fixed at startup. Direct
  connection — the health probe never goes through the proxy it checks.
- **Transport:** `httpx.AsyncClient(timeout=5.0, trust_env=False)`, streaming
  GET, `follow_redirects=False`.
- **Response limit:** 64 KiB; larger responses fail attestation.
- **Validation:** HTTP 200, JSON object, `status == "ok"`, `mode ==
  "enforcing"`. Anything else blocks the download.
- **Auth:** none in code. Note that if the health URL embeds userinfo, httpx
  will send it as Basic auth — do not put credentials in this URL; the service
  does not manage them.
- **Tests:** `tests/unit/test_proxy_enforcement.py` (23), including oversized
  and redirecting health responses; readiness tests in
  `tests/unit/test_startup_readiness.py`.
- **Known limits:** self-reported attestation. A proxy that lies cannot be
  detected.

## E4 — DNS resolution

- **Code:** `security/ssrf.py` (`SystemDnsResolver`), used by preflight and
  `DnsRevalidatingTransport`.
- **Destination:** the hostnames already admitted by URL policy.
- **Transport:** `socket.getaddrinfo` in a worker thread, 5 s timeout.
- **Controls:** every A/AAAA answer is checked against the IP policy; a single
  blocked answer rejects the request.
- **Tests:** `test_ssrf_protection.py`, `test_dns_revalidation.py`,
  `test_ip_policy.py`, plus E2E DNS-rebinding scenario.
- **Known limits:** the resolver is not pinned; the transport resolves again.
  Rebinding window remains (risk R2).

## E5 — ClamAV

- **Code:** `services/scanner.py` (`ClamAvScanner`), `clamd` package.
- **Destination:** `CLAMAV_HOST:CLAMAV_PORT` (default `127.0.0.1:3310`).
- **Transport:** clamd TCP protocol (INSTREAM with size-prefixed chunks; PING
  for availability). No TLS, no authentication.
- **Timeouts:** scan `CLAMAV_TIMEOUT_SECONDS` (60 s) via `asyncio.wait_for`
  around a worker thread; availability ping 5 s.
- **Controls:** fail-closed by default — error/timeout/unparseable verdict/
  unavailable daemon never yields `CLEAN`; infected is always `INFECTED` and
  the file is quarantined; results are tied to the file that was scanned.
- **Tests:** `tests/unit/test_scanner.py` (15, simulated), scan concurrency
  tests, and opt-in `tests/integration/test_clamav_optional.py` (3, **skipped
  unless a real clamd and EICAR opt-in are present**).
- **Known limits:** clamd traffic is plaintext/unauthenticated; keep it on a
  private network or a local socket proxy. The default test suite uses a
  simulated scanner, not a real ClamAV integration.

## E6 — Database

- **Code:** `models/database.py`, SQLAlchemy async engine.
- **Default:** `sqlite+aiosqlite:///...` — local file, no network.
- **PostgreSQL:** `postgresql+asyncpg://...` is documented in `.env.example`,
  but `asyncpg` is not a declared dependency; install it explicitly if
  PostgreSQL is used. This is a documented gap, not an integrated path.
- **Tests:** repository, migration, and integration tests use file-backed
  SQLite.

## E7 — Tests and load harness

All servers bind to loopback (`127.0.0.1`) with ephemeral ports. The E2E suite
uses a local TLS server with a self-signed certificate trusted via
`SSL_CERT_FILE`; no external host is contacted. `scripts/load_test.py` runs a
local uvicorn instance and a local TLS origin.

## Verification

The inventory was compiled by searching for socket/HTTP/DB clients:

```
grep -rn "httpx\|aiohttp\|requests\|urllib\|socket\|getaddrinfo\|clamd\|create_async_engine" \
     --include="*.py" api config integrations models security services storage
```

Only the paths above appear. `trust_env=False` appears on every httpx client
construction that can leave the process.

## Checklist for a new external client

1. Name the destination and who controls it; require HTTPS (or a private
   socket) and fixed endpoints.
2. Set `trust_env=False`, `verify=True`, explicit transport, no implicit proxy.
3. Disable redirects or re-run full destination policy on each hop.
4. Bound connect/read/total timeouts and response bytes.
5. Add destination policy (scheme/host/port/IP) and per-request DNS checks.
6. Add authentication with constant-time comparison; never log credentials.
7. Add tests against a real local socket server, including failure, truncation,
   oversize, redirect, and timeout cases.
8. Update this inventory and [SECURITY_CONTROLS.md](SECURITY_CONTROLS.md).
