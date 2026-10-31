# AgentShield Prompt 3 — Data Loss Prevention (DLP) Policy Guide

## Overview

The DLP module detects sensitive information in agent tool arguments, browser
content, and outbound data. Detection is configurable and pattern-based
(regular expressions). Supported actions per rule: `redact`, `block`, `allow`.

## Detection Rules (default)

| Rule ID | Name | Pattern (summary) | Severity | Action | Confidence |
|---------|------|-------------------|----------|--------|------------|
| DLP-001 | API Key | `api_key=...` / `apikey=...` (16+ chars) | high | block | 85 |
| DLP-002 | Auth Token | `authorization:` / `bearer:` / `token=` (16+ chars) | high | block | 80 |
| DLP-003 | Password | `password=` (6+ chars) | high | block | 80 |
| DLP-004 | SSN-like | `ddd-dd-dddd` | medium | redact | 70 |
| DLP-005 | Credit Card-like | 13-16 digit groups | medium | redact | 65 |
| DLP-006 | Confidential Marker | `confidential`, `proprietary`, `internal only` | low | allow | 60 |

## Behavior

- **Detection**: DLP findings are recorded as `DlpFinding` records
  (organization-scoped) with rule ID, severity, confidence, and action taken.
  Raw sensitive values are never stored or logged; evidence stores
  `[REDACTED]` placeholders.
- **Redaction**: `DlpEngine.redact()` returns content with detected matches
  replaced by `[REDACTED]`. Raw values are never returned.
- **Blocking**: Rules with action `block` cause the enclosing agent action to
  be denied.
- **Audit**: Every DLP finding generates an audit event and an SSE event for
  the enterprise console.

## Configuration

Rules are constructed in Python:

```python
from app.security.ai.dlp import DlpEngine, DlpRule
import re

dlp = DlpEngine(rules=[
    DlpRule(
        rule_id="ORG-001",
        name="Org Project ID",
        pattern=re.compile(r"\bPRJ-[A-Z0-9]{8}\b"),
        severity="high",
        confidence=90,
        action="block",
    ),
])
```

## Scope & Limitations

- Detection is regular-expression based. We do **not** claim comprehensive
  DLP; novel encodings, obfuscation, or non-text exfiltration channels may
  evade detection.
- Confidence scores are heuristic and not guarantees of correctness.
- Sensitive values are redacted in logs and persisted evidence; however,
  callers should avoid transmitting raw secrets to AgentShield where possible.
