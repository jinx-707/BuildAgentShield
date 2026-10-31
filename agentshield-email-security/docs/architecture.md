# AgentShield Email Security — Architecture Specification

`agentshield-email-security` is an independently deployable component providing secure, controlled email integration for authorized AI agents within the AgentShield platform (Module 2).

## 1. System Topology & Architectural Boundaries

```mermaid
flowchart TD
    Caller["AI Agent / Gateway"] -->|HTTP + Gateway Context| API["FastAPI Security Control Plane"]
    
    subgraph ControlPlane ["AgentShield Email Security Control Plane"]
        API --> MW["Auth & RequestID Middleware"]
        MW --> Service["Email Service Orchestrator"]
        
        Service --> SecCoord["MessagePolicyCoordinator"]
        SecCoord --> RecipVal["RecipientValidator"]
        SecCoord --> AttVal["AttachmentValidator"]
        SecCoord --> ContentClass["ContentClassifier (Local DLP)"]
        
        SecCoord --> PolicyIface["PolicyClient (Replaceable)"]
        SecCoord --> InspectIface["InspectionClient (Replaceable)"]
        SecCoord --> AuditIface["AuditClient (Replaceable)"]
        
        Service --> ProviderIface["BaseEmailProvider (Interface)"]
        Service --> Repo["Repository & DB (Encrypted at Rest)"]
    end
    
    subgraph ExternalAdapters ["Email Service Adapters"]
        ProviderIface --> GmailAdapter["GmailClient (Gmail API v1)"]
        ProviderIface --> MSGraphAdapter["MicrosoftGraphClient (Future MS 365)"]
    end
    
    subgraph CentralPlatform ["AgentShield Platform Integration"]
        PolicyIface -.-> PolicyServer["Central Policy Engine / OPA"]
        InspectIface -.-> InspectServer["Central Inspection / DLP Engine"]
        AuditIface -.-> SIEM["Central Audit Log / SIEM"]
    end
```

### Architectural Boundaries
1. **API Boundary**: FastAPI exposes REST endpoints. Provider-specific types, token strings, and internal credentials never escape this layer.
2. **Identity Boundary**: The service never trusts agent-supplied tenant or agent identities. Identity is derived strictly from authenticated gateway headers (`X-Tenant-ID`, `X-Agent-ID`, `Authorization`).
3. **Security Coordination Boundary**: Every action traverses `MessagePolicyCoordinator`. Local checks (syntax, extensions, regex, Luhn algorithm) execute first, followed by centralized external policy and DLP calls.
4. **Provider Isolation Boundary**: All mail interaction occurs via `BaseEmailProvider`. Neither route handlers nor business services import or reference Google- or Microsoft-specific client APIs directly.
5. **Persistence Boundary**: Field-level token encryption protects credentials at rest with Fernet (AES-128-CBC + HMAC-SHA256).

---

## 2. Inbound & Outbound Data Flows

### Outbound Transmission (Send / Forward) Flow
```mermaid
sequenceDiagram
    autonumber
    actor Agent as AI Agent
    participant Gateway as API Gateway
    participant API as Email Security API
    participant Sec as MessagePolicyCoordinator
    participant DLP as InspectionClient
    participant Policy as PolicyClient
    participant Provider as GmailClient / MSGraph
    participant Audit as AuditClient

    Agent->>Gateway: POST /online/email/send
    Gateway->>API: Forward with X-Tenant-ID, X-Agent-ID, Bearer token
    API->>Sec: Validate send request
    Sec->>Sec: Recipient validation (hygiene, disposable check)
    Sec->>Sec: Attachment validation (MIME, double extensions, size)
    Sec->>Sec: Local DLP scan (CC Luhn, SSN, AWS keys)
    Sec->>DLP: inspect_outgoing_email()
    alt DLP Violation
        DLP-->>Sec: Violation detected
        Sec->>Audit: record_event(EMAIL_SEND_BLOCKED)
        Sec-->>API: Raise SecurityPolicyEnforcementError
        API-->>Agent: 403 Forbidden (DLP_DATA_LEAKAGE)
    end
    Sec->>Policy: authorize_send()
    alt Human Approval Required
        Policy-->>Sec: requires_human_approval = True
        Sec-->>API: Register ApprovalReference
        API-->>Agent: 202 Accepted (PENDING_APPROVAL)
    else Authorized
        Policy-->>Sec: allowed = True
        API->>Provider: send_email()
        Provider-->>API: Message sent confirmation
        API->>Audit: record_event(EMAIL_SENT)
        API-->>Agent: 200 OK (EmailSendResponse)
    end
```

### Inbound Reading Flow
```mermaid
sequenceDiagram
    autonumber
    actor Agent as AI Agent
    participant API as Email Security API
    participant Sec as MessagePolicyCoordinator
    participant Provider as GmailClient
    participant DLP as InspectionClient
    participant Audit as AuditClient

    Agent->>API: GET /online/email/messages/{message_id}
    API->>Sec: validate_and_authorize_read()
    API->>Provider: get_message(message_id)
    Provider-->>API: Raw Gmail message payload
    API->>API: GmailMessageParser (decode base64url, headers, parts)
    API->>Sec: inspect_inbound_message()
    Sec->>DLP: inspect_incoming_email()
    Note over Sec: Detect indirect prompt injections & phishing
    API->>Audit: record_event(EMAIL_READ_SINGLE)
    API-->>Agent: 200 OK (EmailMessage with safety annotations)
```

---

## 3. Database Schema

Managed via SQLAlchemy 2 and Alembic:

- **`oauth_accounts`**:
  - `id` (UUID, PK)
  - `tenant_id` (String, Index)
  - `agent_id` (String, Index)
  - `provider` (String: `google`, `microsoft`)
  - `account_email` (String, Index)
  - `encrypted_access_token` (Text, Fernet encrypted)
  - `encrypted_refresh_token` (Text, Fernet encrypted)
  - `token_expiry` (DateTime, TZ)
  - `granted_scopes` (JSON)
  - `status` (String: `active`, `revoked`, `expired`)
  - `created_at`, `updated_at` (DateTime, TZ)

- **`oauth_states`**:
  - `state_token` (String, PK, cryptographically random + HMAC signed)
  - `tenant_id`, `agent_id`, `provider`, `requested_scopes`, `redirect_uri`
  - `expires_at` (DateTime, 10 min TTL)
  - `used` (Boolean, single-use anti-replay)

- **`email_audit_records`**:
  - `id` (UUID, PK)
  - `tenant_id`, `agent_id`, `account_id`
  - `event_type` (`EMAIL_READ`, `EMAIL_SENT`, `DLP_LEAKAGE_BLOCKED`, etc.)
  - `status` (`ALLOWED`, `BLOCKED`, `FLAGGED`, `ERROR`)
  - `policy_decision_id`, `inspection_reference_id`
  - `metadata_json` (Sanitized parameters: recipient domains, count, message ID; no bodies or secrets)
  - `timestamp` (DateTime, TZ)

- **`approval_references`**:
  - `id` (UUID, PK)
  - `tenant_id`, `agent_id`, `action_type`, `target_resource`
  - `status` (`PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`)
  - `reason`, `payload_summary`
  - `approved_by`, `created_at`, `expires_at`

