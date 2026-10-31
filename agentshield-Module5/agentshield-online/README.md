# AgentShield Online Security Module

**Person 3 — Online Capabilities**

Controls all AI agent interactions with external internet services.

> ⚠️ **Payment mode: TEST ONLY** — No real money is processed under any circumstances.

---

## What This Module Does

Every external action proposed by an AI agent passes through a security enforcement gateway before execution. This module prevents agents from:

- Visiting unauthorized websites or following malicious webpage instructions
- Sending emails without permission or forwarding confidential information
- Downloading malicious files or bypassing file validation
- Calling unauthorized external APIs or MCP tools
- Initiating unauthorized, manipulated or duplicate financial transactions

## Five Capabilities

| # | Capability | Gateway | Key Security |
|---|---|---|---|
| 1 | Browser & Search | `BrowserGateway` | SSRF prevention, URL validation, prompt injection detection |
| 2 | Email | `EmailGateway` | Recipient allowlists, DLP, exact-action approval binding |
| 3 | Downloads | `DownloadGateway` | ClamAV scanning, magic-byte validation, quarantine |
| 4 | External APIs & MCP | `APIGateway`, `MCPGateway` | Connector allowlists, tool allowlists, credential injection |
| 5 | Payments | `PaymentGateway` | Merchant validation, spending limits, idempotency, webhook verification |

---

## Quick Start

```bash
# 1. Clone and enter the directory
cd agentshield-online

# 2. Copy environment config
cp .env.example .env
# Edit .env with your test credentials

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the API server
python -m app.main

# 5. Visit API docs
open http://localhost:8000/docs
```

## Run Tests

```bash
# All tests (no external services required)
python -m pytest tests/ --no-cov -v

# Unit tests only
python -m pytest tests/unit/ -v

# Adversarial security tests
python -m pytest tests/adversarial/ -v

# Payment security tests
python -m pytest tests/payments/ -v
```

## Run Demos

```bash
python -m examples.browser_attack_demo
python -m examples.payment_security_demo
python -m examples.email_security_demo
python -m examples.mcp_security_demo
python -m examples.download_security_demo
```

## Docker

```bash
# Start all services
docker-compose up

# API available at http://localhost:8000
```

---

## Integration Contracts

### For Person 1 (Security Engine)
Replace `LocalContentInspectionAdapter` and `LocalDataInspectionAdapter` in `app/main.py`:
```python
from your_module import ProductionContentInspector, ProductionDLPInspector
runtime.content_inspector = ProductionContentInspector()
runtime.data_inspector = ProductionDLPInspector()
```
Both must implement `ContentInspectionPort` and `DataInspectionPort` from `app/integrations/ports.py`.

### For Person 4 (Platform & Policy)
Replace the three local adapters:
```python
runtime.policy = YourOPAPolicyAdapter()
runtime.approval = YourApprovalWorkflowAdapter()
runtime.audit = YourCentralAuditAdapter()
```
All implement their respective ports from `app/integrations/ports.py`.

### For Person 2 (Offline Security)
The download gateway calls a document processor adapter after malware scanning.
Implement `DocumentProcessorPort` and inject at `DownloadGateway` creation.

---

## API Endpoints

```
GET  /online/health
GET  /online/capabilities

POST /online/browser/search
POST /online/browser/navigate
POST /online/browser/extract
POST /online/browser/action

POST /online/email/search
POST /online/email/read
POST /online/email/draft
POST /online/email/send/request-approval
POST /online/email/send

POST /online/downloads/request
GET  /online/downloads/{id}/status

POST /online/apis/execute
GET  /online/mcp/servers
GET  /online/mcp/tools
POST /online/mcp/invoke

POST /online/payments/validate
POST /online/payments/request-approval
POST /online/payments/create-order
POST /online/payments/webhook
GET  /online/payments/{id}/status
```

## Configuration Files

All in `configs/`:
- `online_policy.yaml` — master policy
- `browser_policy.yaml` — URL allowlists, action policies
- `email_policy.yaml` — recipient allowlists, OAuth scopes
- `download_policy.yaml` — size limits, MIME types, ClamAV
- `api_policy.yaml` — approved API connectors
- `mcp_policy.yaml` — approved MCP servers and tools
- `payment_policy.yaml` — spending limits, merchants, TEST MODE only

## Architecture

See `docs/architecture.md` for the full architecture documentation.
