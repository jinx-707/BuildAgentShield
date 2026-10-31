# Threat Model

## Assets

- The browser-security environment and its internal network.
- Documents downloaded on behalf of agents (confidentiality, integrity).
- Approved files staged for downstream use.
- ClamAV verdicts and their link to the scanned bytes.
- API and provider credentials; proxy credentials.
- Download and analysis metadata (tenant association, URLs, findings).
- Service availability and storage/CPU capacity.

## Actors

| Actor | Capability |
|---|---|
| Unauthenticated network client | Can reach the API port; cannot pass bearer auth |
| Authenticated tenant caller | Has the shared token and can choose `X-Tenant-ID` |
| Malicious origin server | Controls the HTTP responses for a URL it hosts |
| Attacker-controlled DNS | Controls resolution for a domain it owns |
| Compromised/misconfigured egress proxy | Can forward traffic, lie about its mode |
| Malicious document author | Controls PDF bytes and embedded active content |
| Compromised provider | Controls the analysis response |
| Insider/operator | Can read logs and storage volumes |
| Resource-exhaustion attacker | Can submit many downloads or large responses |

## Trust boundaries

B1 caller→API; B2 API→origin; B3 API→provider; B4 API→ClamAV; B5 API→DB;
B6 API→storage; B7 API→logs. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Scenarios and mitigations

| # | Scenario | Mitigation | Residual risk |
|---|---|---|---|
| T1 | SSRF to loopback/private/metadata services via submitted URL | HTTPS-only, domain/port policy, IP policy on every DNS answer, proxy enforcement | R2 (rebinding), R3 (lying proxy) |
| T2 | DNS rebinding between validation and connect | Re-validation immediately before each request, per hop | R2: gate, not pinning |
| T3 | Redirect to a blocked host or smuggling across hops | Full preflight per hop; fresh client/transport per hop; max redirects | None known |
| T4 | Malicious HTTP framing (conflicting lengths, truncation, chunk abuse) | Strict acceptance; `RESPONSE_INCOMPLETE`; byte counter | R11: surplus beyond short declared length discarded, not detectable |
| T5 | Oversized response exhausts memory/disk | Streaming with enforced byte cap; 16 MiB-vs-1 MiB test aborts mid-transfer | Disk quota is operator-dependent |
| T6 | Malware reaches approved zone | Fail-closed ClamAV; infected → quarantine; unavailable never clean | R15: real ClamAV not verified here |
| T7 | Malicious PDF executes code or exhausts CPU | pypdf parsing only; no execution; page/text/time caps; encrypted rejected | R9: timeout is not thread pre-emption |
| T8 | Quarantined/rejected file is analyzed or served | Approved-only gate re-checks state, zone, existence, SHA-256; no retrieval endpoint | R8 (no download retrieval) |
| T9 | Cross-tenant data access by ID guessing | Every query tenant-scoped; foreign/unknown IDs both 404; no ID-as-authorization | R1: tenant header is trusted |
| T10 | Token theft enables all tenants | Constant-time compare, no logging, rate limits | R1: one shared token, no per-tenant credentials |
| T11 | Proxy downgraded during a download | Re-attestation per request (5 s cache); fail closed | R3: self-report |
| T12 | Credentials leak through logs/errors/readiness | Fixed error text; redacted proxy URL; no tokens in readiness; JSON logs of structured fields; hygiene tests | R18: tracebacks |
| T13 | Prompt injection through document text to provider | Text is untrusted data in a dedicated field, bounded and sanitized; provider contract defines it as data | Provider behavior is out of scope |
| T14 | Provider returns malicious/malformed payload | Whole-response validation; schema version check; size cap; sanitization; nothing partially stored | R14: no real provider tested |
| T15 | Provider token replayed to a redirect target | Redirects disabled for provider calls | None known |
| T16 | Path traversal or symlink escape in storage | UUID names, resolve + `relative_to`, symlink rejection, approved-only accessor | Volume protection is operator-dependent |
| T17 | Duplicate scans/moves/analysis | Per-download locks, state re-reads, unique analysis index | R6: single process |
| T18 | Resource exhaustion via request floods | Per-IP + per-tenant rate limits; concurrency caps; bounded queues | R5: in-memory limits, multiple replicas bypass |
| T19 | Crash leaves stale in-progress records/files | Startup recovery fails records, sweeps temp; TTL sweeper | No cross-process coordination |
| T20 | Partial write/disk full during move | `os.replace`, source preserved on failure, cleanup errors logged | Disk exhaustion is operator-dependent |
| T21 | Attacker guesses download UUID to authorize | UUIDs are not used as authorization; tenant scope is checked | — |
| T22 | Health endpoint discloses secrets | Payload contains check states and variable names only; tests assert no tokens/passwords | R21: readiness state is public to port reachability |

## Out of scope

- Compromise of the host kernel, container runtime, or secret store.
- Malicious insiders with root access to the storage volume or database.
- The internal security of a selected analysis vendor.
- Anti-virus engine vulnerabilities themselves (ClamAV version/patching).
- DDoS at the network edge (no L7 gateway in this service).
- Multi-tenant cryptographic isolation of data at rest.
