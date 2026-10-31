# AgentShield Offline — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    AgentShield Offline Module                    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              FastAPI Standalone Dev API                  │    │
│  │         (app/main.py + app/api/routes/)                  │    │
│  └─────────────────────┬───────────────────────────────────┘    │
│                         │                                        │
│  ┌─────────────────────▼───────────────────────────────────┐    │
│  │            OfflineSecurityRuntime                        │    │
│  │              (app/core/runtime.py)                       │    │
│  └──┬──────────┬──────────┬──────────┬──────────┬──────────┘    │
│     │          │          │          │          │                │
│  ┌──▼──┐  ┌───▼──┐  ┌────▼──┐  ┌───▼──┐  ┌───▼────┐          │
│  │ Doc │  │ Sys  │  │ Local │  │ Env  │  │Terminal│          │
│  │ GW  │  │ File │  │  FS   │  │  GW  │  │   GW   │          │
│  │     │  │  GW  │  │  GW   │  │      │  │        │          │
│  └──┬──┘  └───┬──┘  └────┬──┘  └───┬──┘  └───┬────┘          │
│     │          │          │          │          │                │
│  ┌──▼──────────▼──────────▼──────────▼──────────▼──────────┐   │
│  │              Integration Ports (app/integrations/)        │   │
│  │  ContentInspectionPort  PolicyPort  AuditPort  Approval  │   │
│  │  LocalDev↑              LocalDev↑   LocalDev↑  DenyAll↑  │   │
│  │  Person1→               Person4→    Person4→   Person4→  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐     │
│  │                  Core Contracts                         │     │
│  │        (app/core/contracts.py, exceptions.py)          │     │
│  └────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
    ClamAV Daemon                 Docker Daemon
    (malware scan)              (command sandbox)
```

## Request Flow — Document Analysis

```
POST /offline/documents/analyze
         │
         ▼
    Auth middleware (dev: API key check)
         │
         ▼
    DocumentAnalysisRequest (Pydantic validation)
         │
         ▼
    OfflineSecurityRuntime.analyze_document()
         │
         ├── 1. FileValidator.validate()
         │        ├── size check
         │        ├── extension check
         │        └── magic byte / MIME check
         │
         ├── 2. SHA-256 hash
         │
         ├── 3. ClamAVScanner.scan_file()
         │        └── if INFECTED → QuarantineManager.quarantine() → DENY
         │        └── if UNAVAILABLE + fail_closed → DENY
         │
         ├── 4. DocumentParser.parse()
         │        └── format-specific parser with timeout
         │
         ├── 5. DocumentInspector.inspect()
         │        └── ContentInspectionPort.inspect()
         │              └── LocalDevelopmentContentInspector (dev)
         │              └── Person1Engine (production)
         │
         └── 6. Build DocumentAnalysisResult → BaseOfflineResponse
                  │
                  └── AuditPort.record()
```

## Request Flow — Terminal Execution

```
POST /offline/terminal/execute
         │
         ▼
    CommandRequest (Pydantic + metachar validator)
         │
         ▼
    TerminalGateway.execute()
         │
         ├── 1. CommandParser.validate()
         │        ├── null byte check
         │        ├── Unicode check
         │        └── argument length/count limits
         │
         ├── 2. CommandPolicy.evaluate()
         │        ├── shell injection patterns
         │        ├── argument blocklist
         │        ├── denylist check → DENY
         │        ├── sandbox_only → SANDBOX_ONLY
         │        └── allowed_restricted → ALLOW_RESTRICTED
         │
         ├── 3. DockerSandboxManager.execute()
         │        ├── start container (non-root, read-only, no network)
         │        ├── wait with timeout
         │        ├── collect output (size-limited)
         │        └── ALWAYS remove container
         │
         └── 4. TerminalOutputInspector.inspect_and_redact()
                  ├── ContentInspectionPort (injection check)
                  └── DataInspectionPort (secret redaction)
```

## Dependency Injection

All gateways and adapters are constructed in `app/api/dependencies.py` using
`@lru_cache` singleton factories. To replace any adapter:

1. Implement the corresponding Port protocol.
2. Change the factory function in `dependencies.py`.
3. No other code changes required.

## Configuration

Settings are loaded from environment variables (with `.env` file support) via
Pydantic Settings. YAML config files under `configs/` provide policy data:

- `offline_policy.yaml` — agent workspace and env permissions
- `protected_paths.yaml` — extra protected system paths
- `document_limits.yaml` — document processing limits
- `sandbox.yaml` — command policy and Docker settings
