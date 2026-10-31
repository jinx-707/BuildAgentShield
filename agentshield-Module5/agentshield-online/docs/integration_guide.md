# Integration Guide

## Connecting Person 1's Security Engine

Implement `ContentInspectionPort` and `DataInspectionPort`:

```python
from app.integrations.ports import ContentInspectionPort, InspectionResult

class ProductionContentInspector(ContentInspectionPort):
    async def inspect(self, content, source, metadata=None) -> InspectionResult:
        # Call Person 1's classifier
        ...
```

Inject in `app/main.py` lifespan:
```python
runtime.content_inspector = ProductionContentInspector()
runtime.data_inspector = ProductionDLPInspector()
```

## Connecting Person 4's Platform

Implement `PolicyPort`, `ApprovalPort`, `AuditPort`:

```python
runtime.policy = OPAPolicyAdapter(opa_url="http://opa:8181")
runtime.approval = ApprovalWorkflowAdapter(workflow_url="...")
runtime.audit = CentralAuditAdapter(kafka_topic="agentshield.audit")
```

The `ApprovalPort.verify_approval(approval_id, action_hash)` must:
1. Confirm the approval exists and is not expired
2. Verify the `action_hash` matches the originally approved hash (constant-time)
3. Mark it consumed (single-use)

## Connecting Person 2's Document Processor

After a file is downloaded and scanned clean, it can be handed to Person 2 for document security processing. Add an adapter at `DownloadGateway` instantiation:

```python
gateway = DownloadGateway(
    ...
    document_processor=Person2DocumentAdapter(),
)
```

## Authentication Header Contract

All requests must include:
```
X-Agent-Id: agent_123
X-Tenant-Id: tenant_123
X-Api-Key: <dev key or Person 4 JWT>
```

In production, replace `local_auth_enabled=true` with Person 4's JWT middleware.
