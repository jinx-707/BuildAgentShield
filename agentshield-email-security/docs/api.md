# AgentShield Email Security — API Specification

Base Path: `/`

All requests except `/health` and `/docs` require gateway context headers:
- `Authorization: Bearer <INTERNAL_SERVICE_TOKEN>`
- `X-Tenant-ID: <tenant_id>`
- `X-Agent-ID: <agent_id>`
- `X-Request-ID: <optional-uuid-correlation-id>`

---

## 1. System & Health

### `GET /health`
Returns health status and database connectivity.
- **Auth**: None
- **Response `200 OK`**:
```json
{
  "status": "ok",
  "service": "agentshield-email-security",
  "version": "1.0.0",
  "environment": "development",
  "database": "connected",
  "mock_integrations": true
}
```

---

## 2. OAuth Lifecycle Management

### `GET /online/email/oauth/google/start`
Initiates a Google OAuth 2.0 authorization handshake with minimum scopes (least privilege).
- **Query Parameters**:
  - `scopes` (optional string): Comma-separated list of scopes to request. Default: `gmail.readonly, userinfo.email`.
- **Response `200 OK`**:
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&scope=...&state=...",
  "state": "random_token_hmac_signature",
  "expires_in_seconds": 600,
  "scopes": ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/userinfo.email"]
}
```

### `GET /online/email/oauth/google/callback`
Callback endpoint invoked by Google OAuth consent redirect.
- **Query Parameters**:
  - `code` (string, required): Google authorization code.
  - `state` (string, required): CSRF state token issued during start.
  - `error` (string, optional): Provider error string if user denied consent.
- **Response `200 OK`**:
```json
{
  "status": "success",
  "account_id": "893c5240-a19e-4c74-9642-1262d140e909",
  "email": "user@example.com",
  "provider": "google",
  "granted_scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
  "created_at": "2026-10-30T14:20:00Z"
}
```
*Note: Tokens are encrypted at rest and never returned in the response.*

### `POST /online/email/accounts/{account_id}/revoke`
Revokes credentials with the identity provider and marks account revoked in local storage.
- **Response `200 OK`**:
```json
{
  "status": "revoked",
  "account_id": "893c5240-a19e-4c74-9642-1262d140e909"
}
```

---

## 3. Email Operations

### `GET /online/email/accounts`
Lists connected mailboxes accessible to the calling tenant and agent.
- **Response `200 OK`**:
```json
[
  {
    "id": "893c5240-a19e-4c74-9642-1262d140e909",
    "account_email": "support@example.com",
    "provider": "google",
    "status": "active",
    "granted_scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
    "created_at": "2026-10-30T14:20:00Z",
    "updated_at": "2026-10-30T14:20:00Z"
  }
]
```

### `GET /online/email/messages`
Lists messages for an account with inbound security inspection.
- **Query Parameters**:
  - `account_id` (UUID, required): Mailbox ID.
  - `q` (string, optional): Search query filter.
  - `max_results` (int, default: 10, max: 50).
  - `page_token` (string, optional).
- **Response `200 OK`**: List of `EmailMessage` objects.

### `GET /online/email/messages/{message_id}`
Retrieves a normalized email message with decoded body and attachment metadata.
- **Query Parameters**:
  - `account_id` (UUID, required).
- **Response `200 OK`**:
```json
{
  "id": "18b958df4211ac29",
  "thread_id": "18b958df4211ac29",
  "subject": "Q4 Performance",
  "sender": {
    "email": "finance@company.com",
    "name": "Finance Team"
  },
  "to": [
    {
      "email": "support@example.com",
      "name": "Support Agent"
    }
  ],
  "cc": [],
  "bcc": [],
  "received_at": "2026-10-30T12:00:00Z",
  "snippet": "Here is the Q4 performance overview...",
  "body_text": "Here is the Q4 performance overview...",
  "body_html": "<p>Here is the Q4 performance overview...</p>",
  "attachments": [
    {
      "attachment_id": "att-1234",
      "filename": "summary.pdf",
      "content_type": "application/pdf",
      "size_bytes": 45012
    }
  ],
  "labels": ["INBOX", "IMPORTANT"]
}
```

### `POST /online/email/search`
Executes an email search query subject to query policy validation.
- **Request Body**:
```json
{
  "account_id": "893c5240-a19e-4c74-9642-1262d140e909",
  "query": "is:unread label:billing",
  "max_results": 10
}
```
- **Response `200 OK`**:
```json
{
  "messages": [...],
  "next_page_token": "token_xyz",
  "total_estimated": 1
}
```

### `POST /online/email/draft`
Creates a draft email after validating recipients and scanning for confidential data leakage (DLP).
- **Request Body**:
```json
{
  "account_id": "893c5240-a19e-4c74-9642-1262d140e909",
  "to": [{"email": "client@example.com", "name": "Client"}],
  "cc": [],
  "bcc": [],
  "subject": "Meeting Agenda",
  "body_text": "Here is the agenda for our sync...",
  "body_html": null,
  "thread_id": null
}
```
- **Response `201 Created`**:
```json
{
  "draft_id": "draft-18b958df",
  "message_id": "msg-18b958df",
  "account_id": "893c5240-a19e-4c74-9642-1262d140e909",
  "subject": "Meeting Agenda",
  "status": "drafted",
  "created_at": "2026-10-30T14:30:00Z"
}
```

### `POST /online/email/send`
Validates recipients, filters attachments, inspects content against DLP rules, and delivers the email.
- **Request Body**:
```json
{
  "account_id": "893c5240-a19e-4c74-9642-1262d140e909",
  "to": [{"email": "customer@example.com"}],
  "subject": "Order Confirmation",
  "body_text": "Your order #123 has shipped.",
  "attachments": []
}
```
- **Response `200 OK`**:
```json
{
  "message_id": "sent-msg-9921",
  "thread_id": "th-9921",
  "account_id": "893c5240-a19e-4c74-9642-1262d140e909",
  "sent_at": "2026-10-30T14:35:00Z",
  "status": "sent"
}
```
- **Response `202 Accepted` (When human approval is triggered)**:
```json
{
  "detail": {
    "message": "Action held for human authorization",
    "status": "PENDING_APPROVAL",
    "approval_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### `POST /online/email/forward`
Forwards an existing email with recipient validation and policy authorization.
- **Request Body**:
```json
{
  "account_id": "893c5240-a19e-4c74-9642-1262d140e909",
  "original_message_id": "18b958df4211ac29",
  "to": [{"email": "team@example.com"}],
  "additional_comment": "Please review this customer inquiry."
}
```
- **Response `200 OK`**:
```json
{
  "message_id": "sent-fwd-001",
  "account_id": "893c5240-a19e-4c74-9642-1262d140e909",
  "forwarded_to": ["team@example.com"],
  "status": "forwarded",
  "sent_at": "2026-10-30T14:40:00Z"
}
```

---

## 4. Error Responses

All errors return structured JSON with consistent error codes and correlation request IDs:

```json
{
  "error": {
    "code": "DLP_DATA_LEAKAGE",
    "message": "Outbound DLP policy violation: confidential data detected (DLP_CREDIT_CARD_LEAK)",
    "request_id": "8fa368aa-eb8b-4914-9989-1065208f8892"
  }
}
```

Common error codes:
| HTTP Status | Error Code | Description |
|---|---|---|
| 400 | `INVALID_RECIPIENT` | Malformed address, CRLF injection, or disposable domain |
| 401 | `UNAUTHORIZED` | Missing or invalid gateway internal service token |
| 403 | `OAUTH_SCOPE_INSUFFICIENT` | Action requires scope not granted to account |
| 403 | `DLP_DATA_LEAKAGE` | Outbound content contained PII/confidential data |
| 403 | `ATTACHMENT_DISALLOWED` | Executable extension, double-extension, or size violation |
| 403 | `POLICY_DISALLOWED` | Action rejected by PolicyClient |
| 404 | `NOT_FOUND` | Mailbox, message, or draft not found |
| 422 | `REQUEST_VALIDATION_ERROR` | Schema validation error |
| 503 | `SECURITY_SERVICE_UNAVAILABLE` | Policy or Inspection service unreachable (Fail-Closed) |

