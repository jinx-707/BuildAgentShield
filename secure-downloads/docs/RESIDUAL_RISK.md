# Residual Risk Register

Ratings are engineering judgements for a controlled deployment, not a formal
quantitative assessment. "Owner" is the team that must accept the risk.

| ID | Risk | Likelihood | Impact | Mitigation in place | Owner | Status |
|---|---|---|---|---|---|---|
| R1 | One shared bearer token; `X-Tenant-ID` is trusted after auth, so one token holder can act as any tenant | Medium | High (tenant isolation relies on caller honesty) | Tenant scoping on every query; 404 for foreign IDs; rate limit per tenant; token never logged | Platform / IAM | Open — blocks multi-tenant production |
| R2 | DNS re-validation is a gate, not pinning; rebinding between lookup and connect can reach a non-approved IP | Low–Medium | High if no proxy | Checks immediately before each request; proxy is authoritative when configured; production requires proxy | Network security | Open — accepted with proxy |
| R3 | Proxy enforcement is self-attested; a lying or misconfigured proxy is undetectable | Low | High | Health attestation per request; fixed-text failure; production requires proxy + health URL | Network security | Open — proxy is trust anchor |
| R4 | True IP pinning not implemented | — | — | See R2; explicitly not claimed | Network security | Accepted |
| R5 | Rate limits are in-memory per process; multiple replicas do not share budgets; restart resets them | Medium in scaled deployments | Medium | Per-IP and per-tenant sliding windows; bucket pruning; documented | Platform | Open if scaling horizontally |
| R6 | Scan locks, download semaphores, and analysis queue are in-process | Medium if scaled | Medium (duplicate work, not bypass of security) | Per-download locks + state re-reads; unique DB index for analysis jobs | Platform | Open if scaling horizontally |
| R7 | SQLite default; PostgreSQL path lacks the `asyncpg` dependency; SQLite is single-writer | Medium at higher concurrency | Medium | Documented; migrations; file-backed SQLite tested | Platform | Open for production scale |
| R8 | No endpoint to retrieve an approved file; downstream retrieves it out of band | — | Medium (integration gap) | Approved zone + metadata/checksum returned | Product | Open by design |
| R9 | PDF processing timeout is not hard CPU pre-emption; a pathological file can occupy a worker thread past the deadline | Low | Medium | Input-size cap, page cap, text cap, bounded thread pool; job fails on deadline | Platform | Open |
| R10 | No download idempotency key and no cancel endpoint; repeated submits create distinct downloads | Medium | Low–Medium (resource use) | Per-tenant concurrency cap; client can poll status; analysis is idempotent per download | Product | Open |
| R11 | A body longer than a short declared `Content-Length` is discarded with the per-hop connection but not reported | Low | Low | Fresh connection per hop; stored hash/size describe accepted bytes | Engineering | Accepted |
| R12 | Quarantined files are retained indefinitely; deletion is manual | — | Medium (disk growth, data retention) | Escalating disk-usage operational check; documented procedure | Operations | Operator policy required |
| R13 | `/health/ready` probes dependencies and security config, so a dependency outage removes pods from service | Medium | Low–Medium | Separate `/health/live`; readiness is the security gate by design | Operations | Accepted |
| R14 | No real analysis vendor is selected or tested; provider integration is contract-only | High | High for analysis feature | Contract v1, hardened adapter, local real-HTTP fake, failure taxonomy | Product | Open — production blocker |
| R15 | No real ClamAV/EICAR run in this environment; default tests use a simulated scanner | High for verification | High for malware assurance | Fail-closed logic, opt-in real-ClamAV tests, staging runbook | Security | Open — must run in staging |
| R16 | clamd protocol is plaintext and unauthenticated | Low on private network | Medium | Host/port config; deployment guidance to isolate; fail-closed | Operations | Open — network isolation required |
| R17 | No secret rotation or vault integration; secrets are environment variables | Medium | Medium | Never logged; `.env.example` contains no real secrets; production validation | Security / Platform | Open |
| R18 | Error tracebacks (`exc_info=True`) can include internal exception text | Low | Low–Medium | Fixed API messages; structured fields; logs restricted to operators | Operations | Accepted with log access control |
| R19 | Load numbers are local and single-machine; not a capacity model | — | — | Documented in [PERFORMANCE.md](PERFORMANCE.md) | Engineering | Accepted |
| R20 | No automated backup/restore for database or storage zones | Medium | High (data loss) | Documented manual procedure | Operations | Open — deployment requirement |
| R21 | Health endpoints are unauthenticated and unrate-limited; readiness reveals dependency states | Low | Low | Payload contains no values or secrets | Security | Accepted |
| R22 | Quarantine/approved file contents are not encrypted at rest | Medium | High if volume exposed | 0700/0600, zone isolation, host/volume controls | Operations | Open — use encrypted volume |
| R23 | No persistent audit trail of security decisions beyond logs (logs may rotate) | Medium | Medium | Structured events; operator log retention | Security | Open — SIEM integration needed |

## Risk acceptance for a controlled demo

R1, R2, R3, R14, R15, R20, and R22 must be explicitly accepted (or resolved)
before production. For a controlled demo with fixed tenants, a real egress
proxy, and a staging ClamAV run, R2/R3 are bounded by the proxy, and R1 is
bounded by demo-only credentials. R14/R15 remain feature-level blockers for
production claims.
