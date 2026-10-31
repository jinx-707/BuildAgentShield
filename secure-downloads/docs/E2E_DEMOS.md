# End-to-End Demo Guide (DEMO 1–10)

The E2E suite runs the real FastAPI app against a real local HTTPS origin
(TLS socket, self-signed certificate trusted for the test process). It covers
the production download path end to end: URL and IP policy, TLS verification,
bounded streaming, strict framing, checksum, scan gate, zone transitions, the
analysis pipeline, and restart recovery.

**Simulation boundaries — read before quoting results**

| Component | In these demos | Real integration? |
|---|---|---|
| Origin server | Local TLS server over loopback | Real HTTPS transport, local origin |
| Malware scanner | `FakeScanner` scripted verdicts | **No** — logic only, not ClamAV |
| Analysis provider | Explicit `local_mock` provider | **No** — not a vendor integration |
| Egress proxy | Configured local mock/health server in proxy demo | **No** — not a production proxy |
| DNS | Real system resolver by default; patched resolver for rebinding tests | Real where noted |

Real-ClamAV coverage is opt-in and separate
(`tests/integration/test_clamav_optional.py`); there is no real provider test.

## Running

```bash
cd secure-downloads
.venv/bin/pytest tests/integration/test_e2e_demos.py -v
# or by marker
.venv/bin/pytest -m e2e -v
```

Optional real ClamAV (requires a reachable clamd and EICAR support):

```bash
SECURE_DOWNLOADS_CLAMAV_EICAR_TEST=1 \
.venv/bin/pytest tests/integration/test_clamav_optional.py -v -m real_clamav
```

## Scenario matrix

| Demo | What it proves | Representative tests |
|---|---|---|
| 1. Successful secure download | Real TLS download, SHA-256 matches, clean scan, `APPROVED`, file in approved zone; metadata contains no storage path | `test_download_verifies_checksum_scans_and_approves` |
| 2. SSRF prevention | Private IP literal, private DNS answer, disallowed domain, disallowed port, and redirect-to-metadata are all rejected; blocked targets are never connected to | 5 tests in `TestDemo2SsrfPrevention` |
| 3. Malicious HTTP responses | Truncated body never approved; oversized body rejected mid-stream; redirect loop rejected; temp files removed | 3 tests in `TestDemo3MaliciousResponses` |
| 4. Malware / quarantine | Infected verdict → `QUARANTINED`, never `APPROVED`, not analyzable, not readable | `test_infected_file_is_quarantined_and_unreachable` (**simulated scanner**) |
| 5. Document analysis | Approved PDF → analysis job → normalized result; tenant-scoped; extracted text separated from provider fields | `test_approved_pdf_is_analyzed_and_normalized` (local mock provider) |
| 6. Tenant isolation | Another tenant cannot use a guessed download ID; 404, no metadata; analysis/result/retry also scoped | `test_another_tenant_cannot_substitute_a_download_id` |
| 7. Concurrency / idempotency | Concurrent result reads are consistent; retry while running is refused; per-tenant concurrency limit is deterministic | 3 tests in `TestDemo7Concurrency` |
| 8. Failure recovery | API restart fails interrupted downloads and reclaims temp files; scanner outage fails closed; proxy outage blocks; provider outage is retryable and identifiable | 4 tests in `TestDemo8Recovery` |
| 9. Resource exhaustion | Slow origin times out with no artifacts; PDF over page limit fails non-retryably | 2 tests in `TestDemo9ResourceExhaustion` |
| 10. Configuration/deployment safety | Permissive provider mode is flagged not-ready; production with mock provider cannot be constructed | 2 tests in `TestDemo10Configuration` |

Total: **29 E2E tests**, all passing.

## What each demo asserts about security

- No path from a failed/quarantined download to `APPROVED`, analysis, or a
  served result.
- No temporary file survives failure, cancellation, or restart.
- A blocked destination is rejected before any socket is opened (tests assert
  the origin observed zero connections for blocked targets).
- Cross-tenant requests are indistinguishable from unknown IDs.
- Configurations that are unsafe for production are refused or reported
  not-ready, never silently accepted.

## Related suites

- Network-transport edge cases: `test_downloader_http.py`,
  `test_redirect_smuggling.py`, `test_response_acceptance.py`,
  `test_download_timeouts.py`, `test_proxy_auth_http.py`.
- Provider adapter against a local HTTP server: `test_analysis_adapter_http.py`
  (a local fake implementing contract v1 — **not** a real provider).
- Auth/tenant matrix: `test_auth_tenant_matrix.py`.
- Real-ClamAV opt-in: `test_clamav_optional.py` (skipped here).

## Caveats

- Passing demos demonstrate the implemented logic and local transport
  behavior. They do not validate a specific proxy implementation, a real
  ClamAV build/signature set, or any vendor provider.
- The self-signed certificate is trusted only through `SSL_CERT_FILE` in the
  test process; certificate verification itself is active in these tests.
