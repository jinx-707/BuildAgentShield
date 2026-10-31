# AgentShield Offline — Integration Guide

This guide explains how Person 1's and Person 4's components integrate with this module.

## Overview of Integration Points

```
Person 2 (this module)
    └── app/integrations/ports.py      ← Integration interfaces (Protocols)
         ├── ContentInspectionPort     ← Person 1 replaces LocalDevelopmentContentInspector
         ├── DataInspectionPort        ← Person 1 replaces LocalDevelopmentDataInspector
         ├── PolicyPort                ← Person 4 replaces LocalFilesystemPolicyAdapter
         ├── AuditPort                 ← Person 4 replaces LocalAuditAdapter
         └── ApprovalPort              ← Person 4 replaces DenyByDefaultApprovalAdapter
```

The injection point is `app/api/dependencies.py`. Change only the factory functions there.

---

## Person 1 Security Engine — built-in integration (already implemented)

The repository ships a ready-to-use adapter for Person 1's
`penetration-prevention--main` engine. No code changes are required — only
configuration:

```bash
# 1. Install Person 1's optional runtime dependencies
pip install -e ".[p1]"

# 2. Enable the integration
#    AGENTSHIELD_P1_ENABLED=true
#    AGENTSHIELD_P1_FAIL_CLOSED=true
#    AGENTSHIELD_P1_MODULE_PATH=../penetration-prevention--main   # optional
```

If `AGENTSHIELD_P1_MODULE_PATH` is left empty, the loader auto-detects the
sibling directory `../penetration-prevention--main`.

What gets wired when enabled (`app/api/dependencies.py`):

| Port | Adapter | Person 1 component |
|------|---------|--------------------|
| `ContentInspectionPort` | `P1ContentInspectionAdapter` | `InputGuard` (injection, PII, secrets, DLP, risk) |
| `DataInspectionPort` | `P1DataInspectionAdapter` | `OutputGuard` (secret/DLP output protection) |

The adapters are chained **after** the local regex inspector, so the local
inspector short-circuits obvious attacks and P1 adds deeper analysis. P1 is
fail-closed by default, and a P1 `ALLOW` never grants filesystem or command
permissions. Status is exposed at `GET /offline/security/p1/health`.

Verification:

```bash
pytest tests/unit/test_p1_adapters.py \
       tests/integration/test_p1_offline_combined.py \
       tests/integration/test_p1_live.py -v
```

---

## Integrating a remote Person 1 Content Inspector

The following is the generic pattern if Person 1 is deployed as a separate
HTTP service instead of the bundled module.

### Step 1: Implement the interface

```python
# person1_integration.py (Person 1 provides this)
from app.integrations.ports import ContentInspectionResult

class Person1ContentInspector:
    def __init__(self, endpoint: str, api_key: str):
        self._endpoint = endpoint
        self._api_key = api_key

    async def inspect(self, content: str, *, source_metadata=None) -> ContentInspectionResult:
        response = await self._client.post(
            f"{self._endpoint}/inspect",
            json={"content": content, "metadata": source_metadata},
            headers={"Authorization": f"Bearer {self._api_key}"},
        )
        data = response.json()
        return ContentInspectionResult(
            passed=data["passed"],
            findings=data["findings"],
            risk_score=data["risk_score"],
            inspector="person1_engine",
        )
```

### Step 2: Wire it in dependencies.py

```python
# In app/api/dependencies.py — replace this function:
@lru_cache(maxsize=1)
def get_content_inspector():
    from person1_integration import Person1ContentInspector
    return Person1ContentInspector(
        endpoint=settings.person1_endpoint,
        api_key=settings.person1_api_key,
    )
```

That's it. No other files need changing.

---

## Integrating Person 1's Data Inspector (DLP)

Identical pattern — replace `get_data_inspector()` in `dependencies.py`:

```python
@lru_cache(maxsize=1)
def get_data_inspector():
    from person1_integration import Person1DataInspector
    return Person1DataInspector(endpoint=settings.person1_dlp_endpoint)
```

---

## Integrating Person 4's Policy Engine (OPA)

```python
# person4_policy.py (Person 4 provides this)
from app.core.contracts import SecurityDecision

class Person4PolicyAdapter:
    async def authorize(self, *, agent_id, tenant_id, operation, resource, context=None):
        result = await self._opa_client.evaluate(
            policy="agentshield/offline/allow",
            input={"agent": agent_id, "tenant": tenant_id,
                   "operation": operation, "resource": resource, "context": context}
        )
        return SecurityDecision.ALLOW if result["allow"] else SecurityDecision.DENY
```

Wire in `dependencies.py` as needed by each gateway.

---

## Integrating Person 4's Audit Service

```python
# In app/api/dependencies.py:
@lru_cache(maxsize=1)
def get_audit_adapter():
    from person4_audit import Person4AuditAdapter
    return Person4AuditAdapter(
        endpoint=settings.audit_endpoint,
        api_key=settings.audit_api_key,
    )
```

The `LocalAuditAdapter` continues to write to a local JSONL file as a fallback.

---

## Integrating Person 4's Approval Manager

```python
# In app/api/dependencies.py:
def get_approval_adapter():
    from person4_approval import Person4ApprovalAdapter
    return Person4ApprovalAdapter(endpoint=settings.approval_endpoint)
```

Then inject it into the gateway constructors that need human-in-the-loop approval.

---

## Mounting Under Person 4's Central Gateway

When Person 4's API gateway is ready, this module's routers can be mounted as a sub-application:

```python
# In Person 4's main gateway app:
from app.main import create_app as create_offline_app

offline_app = create_offline_app()
gateway_app.mount("/offline", offline_app)
```

Or import the routers directly:

```python
from app.api.routes import documents, filesystem, system_files, environment, terminal

gateway_app.include_router(documents.router, prefix="/offline")
gateway_app.include_router(filesystem.router, prefix="/offline")
# ... etc
```

---

## Security Context Injection

In the standalone API, identity comes from the `X-API-Key` header (development only).

In production, Person 4's gateway authenticates the request and injects a `RuntimeSecurityContext` before dispatching to this module. The request body's `agent_id` and `tenant_id` fields must be verified against the authenticated context.

```python
# Person 4's middleware injects this before calling our handlers:
from app.core.security_context import RuntimeSecurityContext

context = RuntimeSecurityContext(
    agent_id=verified_agent_id,   # from Person 4's auth
    tenant_id=verified_tenant_id,
    claims={"workspace": "/workspace/agent123", "roles": ["agent"]},
)
# Pass to the runtime as a dependency
```

---

## Known Limitations

1. The local development adapters are intentionally limited and must not be used in production.
2. The local content inspector uses simple regex — it will miss sophisticated prompt injection attacks.
3. Docker socket access for the sandbox requires careful privilege management in production.
4. ClamAV database freshness depends on `freshclam` running regularly.
5. The secret broker mock provider stores secrets in memory — use Vault in production.

See `docs/threat_model.md` for full threat coverage analysis.
