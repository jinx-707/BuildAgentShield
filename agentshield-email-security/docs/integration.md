# AgentShield Email Security — Platform Integration Guide

This guide details how `agentshield-email-security` integrates into the main AgentShield platform and microservices ecosystem.

---

## 1. Role in the AgentShield Ecosystem

AgentShield comprises several modular security components:
- **Module 1**: `agentshield-browser-security` (Web & browser execution sandbox)
- **Module 2**: `agentshield-email-security` (Email communications gateway & DLP egress filter)
- **Central Gateway**: Ingress authentication, agent token verification, and reverse proxy
- **Central Policy Engine**: Centralized RBAC/ABAC and human-in-the-loop approvals (OPA / custom)
- **Central Inspection Service**: Deep learning DLP, PII scanning, and prompt-injection detection
- **Central SIEM / Audit Engine**: Immutable compliance event logging

---

## 2. Replaceable Integration Interfaces

The service decouples from central platform infrastructure through three abstract contracts located in `app/integrations/`:

### A. PolicyClient (`app/integrations/policy_client.py`)
```python
class BasePolicyClient(ABC):
    async def authorize_read(tenant_id, agent_id, account_id, message_id) -> PolicyDecision: ...
    async def authorize_search(tenant_id, agent_id, account_id, query) -> PolicyDecision: ...
    async def authorize_draft(tenant_id, agent_id, account_id, draft_request) -> PolicyDecision: ...
    async def authorize_send(tenant_id, agent_id, account_id, send_request) -> PolicyDecision: ...
    async def authorize_forward(tenant_id, agent_id, account_id, forward_request) -> PolicyDecision: ...
```

### B. InspectionClient (`app/integrations/inspection_client.py`)
```python
class BaseInspectionClient(ABC):
    async def inspect_incoming_email(email: EmailMessage) -> InspectionResult: ...
    async def inspect_outgoing_email(draft: EmailDraftRequest | EmailSendRequest) -> InspectionResult: ...
    async def inspect_attachment(filename: str, content_type: str, data: bytes) -> InspectionResult: ...
```

### C. AuditClient (`app/integrations/audit_client.py`)
```python
class BaseAuditClient(ABC):
    async def record_event(tenant_id, agent_id, event_type, status, metadata, ...) -> str: ...
```

---

## 3. Switching from Local Mocks to Central Platform Services

During local development and unit tests, the service defaults to using `mocks/`:
- `MockPolicyClient`
- `MockInspectionClient`
- `MockAuditClient`

To connect to production AgentShield microservices, set environment variables in `.env`:

```ini
APP_ENV=production
USE_MOCK_INTEGRATIONS=false
POLICY_SERVICE_URL=http://policy-service.internal.agentshield:8010
INSPECTION_SERVICE_URL=http://inspection-service.internal.agentshield:8020
AUDIT_SERVICE_URL=http://audit-service.internal.agentshield:8030
INTERNAL_SERVICE_TOKEN=your-high-entropy-production-internal-token
```

When `USE_MOCK_INTEGRATIONS=false`, `app.services.email_service.build_policy_coordinator()` automatically instantiates:
- `HttpPolicyClient`
- `HttpInspectionClient`
- `HttpAuditClient`

These communicate over HTTP using internal service tokens and strict timeout controls.

---

## 4. Merging into the Main AgentShield Repository

When integrating this component into the main monorepo:
1. Copy `agentshield-email-security` into the `services/` or `modules/` folder (e.g. `services/email-security/`).
2. Point the central API Gateway route `/online/email/*` to the `agentshield-email-security` service port (default: 8001).
3. Ensure the gateway propagates headers:
   - `X-Tenant-ID`: Authenticated tenant UUID
   - `X-Agent-ID`: Authenticated agent UUID
   - `Authorization: Bearer <INTERNAL_SERVICE_TOKEN>`
   - `X-Request-ID`: Distributed tracing correlation ID
4. Include `agentshield-email-security` in the monorepo's root `docker-compose.yml` or Kubernetes Helm charts.

