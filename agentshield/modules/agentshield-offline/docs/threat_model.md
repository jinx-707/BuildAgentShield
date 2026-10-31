# AgentShield Offline — Threat Model

## Assets Being Protected

| Asset | Description |
|-------|-------------|
| Host filesystem | OS files, credentials, configuration |
| Agent workspace | Files the agent is authorized to access |
| Environment secrets | API keys, DB passwords, cloud credentials |
| Other agents' data | Cross-tenant and cross-agent isolation |
| Host OS | Integrity of the operating system |
| Command execution environment | Isolation from untrusted commands |

---

## Threat Actors

1. **Compromised AI model output** — LLM generates malicious instructions
2. **Prompt injection via document** — Malicious content embedded in user-supplied files
3. **Malicious agent code** — An agent process that has been hijacked
4. **Insider threat** — Authorized agent abusing elevated permissions

---

## Threat Coverage by Module

### Document Analysis

| Threat | Mitigation | Coverage |
|--------|-----------|----------|
| Prompt injection via document | Content inspection via ContentInspectionPort | ⚠️ Limited (rule-based in dev; replace with Person 1) |
| Malware in documents | ClamAV scanning + quarantine | ✓ When ClamAV available |
| XML entity (XXE) | stdlib ET + entity expansion disabled | ✓ |
| Decompression bomb | File size limits + archive entry limits | ✓ |
| Parser resource exhaustion | Processing timeout | ✓ |
| Spoofed file extension | Magic byte + MIME validation | ✓ |
| Oversized document | Size limit enforcement | ✓ |

### System File Protection

| Threat | Mitigation | Coverage |
|--------|-----------|----------|
| /etc/passwd read | Protected path registry | ✓ |
| SSH key exfiltration | Sensitive pattern matching | ✓ |
| Path traversal | String + canonical path validation | ✓ |
| Symlink escape | Realpath check + workspace boundary | ✓ (best-effort) |
| Unicode path bypass | Bidirectional and BOM detection | ✓ |
| Null byte injection | Explicit null byte check | ✓ |

**Limitation**: Container-level filesystem restrictions provide the primary enforcement. This module provides defence-in-depth Python-level checks.

### Local File Access Control

| Threat | Mitigation | Coverage |
|--------|-----------|----------|
| Unauthorized file read | Directory scope + operation permissions | ✓ |
| Workspace escape | Canonical path + workspace boundary check | ✓ |
| Cross-agent file access | Per-agent workspace isolation | ✓ |
| Atomic write corruption | Temp file + rename pattern | ✓ |
| File size DoS | Per-agent max file size | ✓ |
| Dangerous extensions | Extension allowlist/denylist | ✓ |

### Environment Protection

| Threat | Mitigation | Coverage |
|--------|-----------|----------|
| API key enumeration | Always-denied list + sensitive patterns | ✓ |
| Host env inheritance | build_minimal_env() never reads os.environ | ✓ |
| Secret in logs | Secret values never logged | ✓ |
| Secret in LLM response | Response never includes secret values | ✓ |
| Unauthorized secret access | Per-agent broker permissions | ✓ |
| Process environment pollution | Container-level env isolation | ✓ |

**Limitation**: Python-level isolation (same process) is insufficient for true secret isolation. Container isolation is required.

### Terminal Execution

| Threat | Mitigation | Coverage |
|--------|-----------|----------|
| Destructive commands | Denylist + sandbox | ✓ |
| Privilege escalation | sudo/su/doas denied | ✓ |
| Shell injection | Argument validation + no shell=True | ✓ |
| Host filesystem access | read-only rootfs + no host mounts | ✓ (with Docker) |
| Network exfiltration | network_mode=none | ✓ (with Docker) |
| Resource exhaustion | CPU/memory/pid limits | ✓ (with Docker) |
| Container escape | No privileged mode, all caps dropped | ✓ |
| Sandbox unavailable host exec | Fail-closed (raises SandboxUnavailableError) | ✓ |
| Output secret leakage | Output inspection + redaction | ⚠️ Limited in dev |

---

## Known Limitations and Non-Covered Threats

1. **Sophisticated prompt injection**: The local development content inspector uses regex only. Replace with Person 1's ML-based engine.
2. **Zero-day parser exploits**: Parser library vulnerabilities are outside scope. Keep dependencies updated.
3. **Kernel exploits via containers**: gVisor or VM-based isolation provides stronger guarantees.
4. **Side-channel attacks**: Timing attacks and memory side channels are not addressed.
5. **Supply chain attacks**: Dependency integrity verification is out of scope.
6. **Concurrent TOCTOU on same file**: The atomic write pattern mitigates most cases; full TOCTOU protection requires OS-level file locks.
7. **In-process secret isolation**: If an untrusted agent runs in the same Python process, `os.environ` is accessible. Container isolation is required for true isolation.
8. **ClamAV false negatives**: No antivirus engine catches 100% of malware.
9. **Physical access**: Out of scope.
