# Threat Model

**Date:** 2026-10-31  
**Method:** Asset/actor/threat review plus adversarial test mapping.  
**Companion:** `BROWSER_SECURITY_THREAT_MODEL.md` contains the earlier detailed SSRF/DNS-rebinding analysis; this document reflects the current implementation.

## Assets

- Internal networks, cloud metadata endpoints, and loopback services.
- API, worker, and proxy credentials.
- Browser session state, cookies, and page content.
- Search provider API keys.
- Availability of the API, worker, proxy, Redis, and Chromium.
- Integrity of policy configuration and logs.

## Actors

| Actor | Capability |
| --- | --- |
| Untrusted caller / compromised agent | Controls request bodies, URLs, search queries, action targets, and headers |
| Malicious web page | Controls page content, scripts, redirects, forms, and subresources |
| Network attacker | Can spoof `X-Forwarded-For` if able to reach the API |
| Malicious tenant | Possesses a valid API token and agent identity, attempts cross-tenant access |
| Operator error | Misconfigures allowlists, proxies, rate limits, or credentials |

## Threats and mitigations

### T1. SSRF to internal services or cloud metadata

**Mitigations:** scheme allowlist; credential rejection; ambiguous-IP rejection; domain/port policy; private/loopback/link-local/metadata blocking at API, worker, and proxy; proxy DNS double-lookup and IP pinning; Docker internal worker network; redirect revalidation.

**Residual risk:** proxy bypass or permissive `ALLOW_PRIVATE_NETWORKS` configuration defeats the network control. Keep `REQUIRE_EGRESS_PROXY=true` and private networking disabled outside isolated tests.

### T2. DNS rebinding

**Mitigations:** proxy resolves at connection time, checks all answers, re-resolves, and connects to the validated literal IP; Chromium host-resolver rules prevent browser DNS.

**Residual risk:** API DNS preflight is TOCTOU and defense-in-depth only. The proxy is authoritative.

### T3. Redirect or subresource bypass

**Mitigations:** worker request interception; redirect limits and loop detection; HTTPS downgrade blocking; API revalidation of `final_url`; proxy per-connection policy.

**Residual risk:** policy drift between API, worker, and proxy. Compare policy fingerprints in startup logs.

### T4. WebSocket, WebRTC, popup, prerender, or background-channel bypass

**Mitigations:** proxy validates WebSocket upgrades; WebRTC hard-blocked; page security removes relevant APIs and tags; popups suppressed; background networking disabled; prerender/prefetch disabled.

**Residual risk:** new browser features can create new channels. Re-run adversarial browser tests after Chromium upgrades.

### T5. Session theft or cross-tenant access

**Mitigations:** API authentication; owner-bound sessions via `X-Agent-ID`; session IDs are not credentials; concurrent use refused; owner checks on every operation; idle/max-age/lease cleanup.

**Residual risk:** this is owner binding, not full tenant isolation. A compromised caller with the same agent identity can act as that agent.

### T6. Malicious page content / prompt injection

**Mitigations:** content returned as bounded text; explicit `untrusted` labels; hidden-content exclusion; heuristic prompt-injection inspection; typed-value redaction.

**Residual risk:** inspection is not a sanitizer. Downstream agents must not treat page content as instructions.

### T7. Credential leakage

**Mitigations:** API/worker/proxy bearer or Basic tokens compared in constant time; search keys in `SecretStr`; typed values not logged; proxy authorization header stripped; structured logging with redaction.

**Residual risk:** environment variables and logs remain sensitive. Use secret management and log access controls in production.

### T8. Rate-limit evasion and abuse

**Mitigations:** API-wide and per-category limits; tenant/session/IP dimensions; shared Redis counters; trusted-proxy-aware identity; malformed trusted XFF rejected; fail-closed backend errors.

**Residual risk:** distributed clients with many IPs can still consume capacity. Add edge/WAF rate limiting and capacity controls for production.

### T9. `X-Forwarded-For` spoofing

**Mitigations:** direct TCP peer authoritative; header honored only from configured trusted proxies; rightmost untrusted address selected; max hops; malformed chains rejected; Uvicorn proxy-header processing disabled.

**Residual risk:** a trusted proxy that forwards a caller-supplied chain unchanged violates the contract. The application cannot detect that.

### T10. Browser/worker denial of service

**Mitigations:** navigation/action/screenshot timeouts; max concurrent contexts; max sessions; per-session screenshot rate and lifetime limits; bounded content/extraction; process and memory limits in Compose; worker health checks.

**Residual risk:** Chromium memory is significant. The load test showed the worker process tree growing from about 470 MiB to about 539 MiB over 100 navigations; capacity planning must include Chromium children.

### T11. Dependency or configuration compromise

**Mitigations:** pinned version ranges; production guards for mock backends, empty API auth, and memory rate limiting; policy fingerprint logging; read-only containers and dropped capabilities.

**Residual risk:** no automated dependency-update or SBOM process is included in this module.

## Assumptions

- The proxy is the only route from the worker to the internet.
- The API is not directly exposed to untrusted networks without a reverse proxy and TLS.
- Operators configure consistent domain/port policy across API, worker, and proxy.
- Production sets `API_AUTH_TOKEN`, `WORKER_AUTH_TOKEN`, `PROXY_AUTH_TOKEN`, Redis, and a real policy/inspection backend.
- The ASGI server runs with `--no-proxy-headers` or an equivalent setting.
- Chromium is kept patched.

## Out of scope

- Full WAF/bot management.
- Persistent audit ledger or SIEM.
- File download/PDF handling.
- Multi-tenant isolation beyond owner-bound sessions.
- Protection against a compromised host or container runtime.
