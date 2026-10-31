# AgentShield Offline Security Module

**Person 2 — Standalone Offline Security Subsystem**  
**Version:** 0.1.0 | **Python:** 3.11+ | **Status:** Development / Integration-Ready

---

## What This Is

The AgentShield Offline Security Module is a standalone Python security subsystem that protects AI agents from:

- Prompt injection via malicious documents
- Unauthorized access to OS files and credentials
- Workspace escape and path traversal attacks
- Credential theft through environment variables
- Destructive or exploitative command execution
- Cross-agent data access

It is designed as **Person 2's independent contribution** to the AgentShield platform and can run completely standalone — no other team members' code is required.

---

## Five Security Capabilities

| # | Module | Endpoint |
|---|--------|----------|
| 1 | Document Analysis Security | `POST /offline/documents/analyze` |
| 2 | System File Access Protection | `POST /offline/system/inspect` |
| 3 | Local File Access Control | `POST /offline/files/{read,create,update,delete,...}` |
| 4 | Environment & Secret Protection | `POST /offline/environment/{inspect,secret}` |
| 5 | Terminal Execution (Docker sandbox) | `POST /offline/terminal/execute` |

---

## Quick Start

```bash
# Clone and enter directory
cd agentshield-offline

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env

# Start the API (development mode)
python -m app.main

# Or with uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

**API Docs:** http://localhost:8001/offline/docs  
**Health:** http://localhost:8001/offline/health  
**Capabilities:** http://localhost:8001/offline/capabilities

---

## Install & Run Tests

```bash
# Run all tests (no Docker or ClamAV required)
pytest tests/unit tests/integration tests/adversarial -v

# Run only unit tests
pytest tests/unit -v

# Run adversarial security tests
pytest tests/adversarial -v -m adversarial

# Run with coverage
pytest tests/ --cov=app --cov-report=term-missing --ignore=tests/sandbox

# Run Docker sandbox tests (requires Docker)
pytest tests/sandbox -v -m docker
```

---

## Run Demo Scripts

```bash
# File access control demo
python examples/secure_file_access.py

# Environment and secret protection demo
python examples/environment_protection.py

# Terminal command policy demo
python examples/terminal_execution.py

# Document analysis demo
python examples/analyze_document.py /path/to/file.pdf
```

---

## Docker Deployment

```bash
# Build image
docker build -t agentshield-offline .

# Start full stack (with ClamAV)
docker-compose up -d

# Health check
curl http://localhost:8001/offline/health
```

---

## Project Structure

```
agentshield-offline/
├── app/
│   ├── main.py                         # FastAPI app
│   ├── api/routes/                     # API endpoints
│   ├── core/                           # Contracts, decisions, runtime
│   ├── integrations/                   # Ports (interfaces) + local adapters
│   ├── capabilities/offline/
│   │   ├── documents/                  # Module 1: Document analysis
│   │   ├── system_files/               # Module 2: System path protection
│   │   ├── local_files/                # Module 3: Filesystem access control
│   │   ├── environment/                # Module 4: Env/secret protection
│   │   └── terminal/                   # Module 5: Sandboxed execution
│   └── utils/
├── configs/                            # YAML policy files
├── tests/
│   ├── unit/                           # Component-level tests
│   ├── integration/                    # End-to-end gateway tests
│   ├── adversarial/                    # Attack simulation tests
│   └── sandbox/                        # Docker execution tests
├── examples/                           # Demo scripts
├── docs/                               # Architecture & integration docs
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Integration with Other AgentShield Modules

Person 1's `penetration-prevention--main` engine is integrated out of the box.
Set `AGENTSHIELD_P1_ENABLED=true` (and install `pip install -e ".[p1]"`) to
route content/data inspection through Person 1's `InputGuard`/`OutputGuard`.
The sibling repo is auto-detected; override with `AGENTSHIELD_P1_MODULE_PATH`.
See `docs/integration_guide.md` for details and `GET /offline/security/p1/health`
for live status.

This module also exposes replaceable interfaces for Person 1 and Person 4:

| Interface | Local Adapter (dev) | Production Replacement |
|-----------|--------------------|-----------------------|
| `ContentInspectionPort` | `LocalDevelopmentContentInspector` | Person 1's ML injection detector |
| `DataInspectionPort` | `LocalDevelopmentDataInspector` | Person 1's DLP engine |
| `PolicyPort` | `LocalFilesystemPolicyAdapter` | Person 4's OPA engine |
| `AuditPort` | `LocalAuditAdapter` (JSONL file) | Person 4's central audit service |
| `ApprovalPort` | `DenyByDefaultApprovalAdapter` | Person 4's approval manager |

See `docs/integration_guide.md` for step-by-step instructions.

---

## Security Notes

- **Fail-closed by default** — unavailable scanners/inspectors result in DENY, not ALLOW
- **No shell=True** — all subprocess calls use structured argument lists
- **No host fallback** — if Docker sandbox is unavailable, execution is denied
- **Secret values never logged** — only identifiers appear in audit logs
- **Document content always UNTRUSTED** — regardless of source
- **Local dev adapters are clearly labelled** — not claimed as production controls

---

## Known Limitations

- The local content inspector uses simple regex (not ML) — for demonstration only
- Full Docker sandbox security requires Linux kernel features (not available on Windows)
- ClamAV requires separate installation/daemon for malware scanning
- In-process secret isolation is insufficient without container-level separation

See `docs/threat_model.md` for complete threat coverage analysis.
