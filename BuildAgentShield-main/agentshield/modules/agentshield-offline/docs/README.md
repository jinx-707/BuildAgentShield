# AgentShield Offline Security Module

**Person 2 — Standalone Offline Security Subsystem**

This is the independent offline security module for the AgentShield platform. It protects AI agents from unauthorized resource access, prompt injection via documents, credential theft, destructive command execution, and file system attacks — all within a local or isolated execution environment.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env as needed

# 3. Run the standalone API
python -m app.main

# 4. Run tests
pytest tests/ -v --ignore=tests/sandbox

# 5. Run demos
python examples/secure_file_access.py
python examples/environment_protection.py
python examples/terminal_execution.py
```

The API will be available at: `http://localhost:8001/offline/`

Interactive docs: `http://localhost:8001/offline/docs`

## What's Included

| Module | Description |
|--------|-------------|
| Document Analysis | PDF/DOCX/XLSX/PPTX/TXT/CSV/JSON/XML parsing with malware scanning and injection detection |
| System File Protection | Blocks access to /etc, /root, /proc, /sys, SSH keys, cloud credentials |
| Local File Access Control | Workspace-scoped read/write/delete with per-agent permissions |
| Environment Protection | Variable allowlists, secret broker, minimal environment for subprocesses |
| Terminal Execution | Docker-sandboxed command execution with strict command policy |

## Architecture

```
Agent Request
     │
     ▼
OfflineSecurityRuntime (app/core/runtime.py)
     │
     ├── DocumentGateway      (capabilities/offline/documents/)
     ├── LocalFilesystemGateway (capabilities/offline/local_files/)
     ├── SystemFileGateway    (capabilities/offline/system_files/)
     ├── EnvironmentGateway   (capabilities/offline/environment/)
     └── TerminalGateway      (capabilities/offline/terminal/)
          │
          ▼
     AuditPort (integrations/local_audit_adapter.py)
```

## Integration Readiness

This module exposes clean interfaces for integration with:
- **Person 1** (content inspection, PII detection, DLP) via `ContentInspectionPort`
- **Person 4** (policy engine, audit, approval) via `PolicyPort`, `AuditPort`, `ApprovalPort`

See `docs/integration_guide.md` for details.

## Testing

```bash
# All tests (excludes Docker and ClamAV)
pytest tests/ -v --ignore=tests/sandbox

# Unit tests only
pytest tests/unit -v

# Integration tests
pytest tests/integration -v

# Adversarial tests
pytest tests/adversarial -v -m adversarial

# Docker sandbox tests (requires Docker)
pytest tests/sandbox -v -m docker
```

## Platform Notes

- Primary target: **Linux** (full security enforcement)
- **Windows**: Path validation works; Docker sandbox requires Docker Desktop; ClamAV requires separate installation
- macOS: Mostly compatible; use Homebrew for libmagic (`brew install libmagic`)
