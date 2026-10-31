# AgentShield Email Security — Security & Threat Model

This document outlines the security architecture, threat model, control implementations, and compliance posture for `agentshield-email-security`.

---

## 1. Core Security Principles

1. **Least Privilege by Default**: OAuth authorization starts with `gmail.readonly`. Elevated permissions (`send`, `compose`, `modify`) are only requested or accepted when explicitly required.
2. **Zero-Trust Token Handling**: The AI agent never sees, handles, or receives OAuth access tokens, refresh tokens, or mailbox passwords. Tokens are stored using field-level authenticated symmetric encryption (Fernet: AES-128-CBC + HMAC-SHA256).
3. **Fail-Closed Architecture**: If any security dependency (Policy service, Inspection service, or Audit trail) becomes unreachable or encounters a 5xx error, all sensitive email actions immediately fail closed (HTTP 503/403). Operations are never permitted to proceed silently without policy clearance.
4. **Strict Egress Validation**: All outbound messages and attachments are inspected before transmission for recipient domain reputation, executable payloads, double-extension deception, and confidential data leakage (credit cards, SSNs, API tokens).
5. **Inbound Prompt Injection Defense**: Incoming email bodies and snippets are scanned for indirect prompt injection indicators (`ignore previous instructions`, `system prompt override`, etc.) and annotated with warning banners.
6. **Caller Identity Isolation**: Identity is strictly derived from authenticated gateway headers (`X-Tenant-ID`, `X-Agent-ID`). Mailbox access is bounded by tenant and agent. Cross-tenant or cross-agent unauthorized access returns HTTP 404.

---

## 2. Threat Model & Mitigations

| Threat | Attack Vector | Mitigation in AgentShield Email Security |
|---|---|---|
| **Credential Theft / Exposure** | Agent attempts to read stored OAuth tokens or configuration | API responses omit credentials; tokens are encrypted at rest with `TOKEN_ENCRYPTION_KEY`; passwords are never accepted or stored. |
| **CSRF in OAuth Handshake** | Attacker redirects victim's OAuth code or injects malicious callback | Ephemeral `OAuthState` tokens are generated with high entropy, HMAC-signed, stored in DB with a 10-minute TTL, and marked used immediately upon consumption (anti-replay). |
| **Data Leakage (Outbound DLP)** | Agent inadvertently or maliciously emails credit cards, SSNs, or cloud API keys | `ContentClassifier` scans outbound bodies and subjects using regex + Luhn checksum algorithm for credit cards, SSN validation, AWS access keys (`AKIA...`), and private key headers. Violations fail closed. |
| **Malicious Attachment Ingestion / Egress** | Attacker attaches `.exe`, `.vbs`, or double-extension `.pdf.exe` | `AttachmentValidator` rejects dangerous extensions, detects double-extension spoofing (e.g., `invoice.pdf.vbs`), enforces MIME type validation, and rejects files exceeding `MAX_ATTACHMENT_SIZE_BYTES`. |
| **Indirect Prompt Injection** | Attacker emails prompt injections into an agent-monitored inbox | `ContentClassifier` and `InspectionClient` scan inbound content. If suspicious prompt injection directives are found, an audit event is raised and a security warning banner is prepended to the email text. |
| **Header Injection / CRLF Attacks** | Attacker injects `\r\nBcc:...` into recipient fields | `RecipientValidator` explicitly scans for `\r`, `\n`, `\0`, `%0d`, `%0a` and rejects the address with HTTP 400. |
| **Homoglyph / Punycode Deception** | Attacker registers lookalike domain (e.g., Cyrillic 'о' in `micrоsoft.com`) | `RecipientValidator` checks for IDN/punycode indicators (`xn--` or non-ASCII characters) and flags them as high-risk homograph attempts. |
| **Tenant / Agent Impersonation** | Rogue agent supplies falsified tenant headers | `GatewayAuthenticationMiddleware` validates internal bearer token `INTERNAL_SERVICE_TOKEN` and ensures context is derived from the verified API gateway. |

---

## 3. Token Encryption at Rest

OAuth tokens (`access_token` and `refresh_token`) are encrypted before database insertion using `TokenCrypto`:

```python
# app/security/token_crypto.py
class TokenCrypto:
    def __init__(self, key: bytes = None):
        # Uses 32-byte urlsafe base64 Fernet key
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
```

In production, `TOKEN_ENCRYPTION_KEY` must be configured via environment variables or secret manager. The application refuses to start in production if the key is missing or invalid.

---

## 4. Scope Enforcement Matrix

| API Action | Minimum Required Google OAuth Scope |
|---|---|
| `GET /online/email/accounts` | Authenticated tenant/agent session (no provider scope) |
| `GET /online/email/messages` | `https://www.googleapis.com/auth/gmail.readonly` |
| `GET /online/email/messages/{id}` | `https://www.googleapis.com/auth/gmail.readonly` |
| `POST /online/email/search` | `https://www.googleapis.com/auth/gmail.readonly` |
| `POST /online/email/draft` | `https://www.googleapis.com/auth/gmail.compose` OR `gmail.modify` |
| `POST /online/email/send` | `https://www.googleapis.com/auth/gmail.send` OR `gmail.modify` |
| `POST /online/email/forward` | `https://www.googleapis.com/auth/gmail.send` OR `gmail.modify` |

If an agent attempts `send` or `draft` using an account authorized with only `gmail.readonly`, `MessagePolicyCoordinator` blocks the request before provider dispatch with error code `OAUTH_SCOPE_INSUFFICIENT`.

