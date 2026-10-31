# NeMo Guardrails Integration

AgentShield Offline optionally integrates NVIDIA NeMo Guardrails 0.10.1+
as an additional AI content-inspection layer.

## What NeMo adds

| Without NeMo | With NeMo |
|---|---|
| Local regex-based injection detection | Regex + NeMo configurable input/output rails |
| No LLM-backed content safety | LLM-backed jailbreak detection (model_backed profile) |
| Fixed detection patterns | Configurable Colang flows |
| Single-layer inspection | Chained inspection (local + NeMo + Person 1 future) |

## What NeMo does NOT replace

- Docker sandbox (terminal execution isolation)
- Filesystem workspace enforcement
- ClamAV malware scanning
- Secret broker and env isolation
- Audit logging
- Path traversal protection

NeMo is an **additional detection layer**. AgentShield's existing enforcement
remains authoritative. NeMo PASSED never grants a permission.

## Installation

```bash
pip install -e ".[nemo]"
```

## Quick enable

```bash
export AGENTSHIELD_NEMO_ENABLED=true
export AGENTSHIELD_NEMO_PROFILE=local   # no model required
python -m app.main
```

## Profiles

| Profile | Description | External network? |
|---------|-------------|-------------------|
| `local` | Heuristic/Colang rails only | No |
| `model_backed` | + LLM safety checks (OpenAI) | Yes |
| `production` | + LLM checks via local inference | No (self-hosted) |

## API changes

- New endpoint: `GET /offline/security/nemo/health`
- New endpoint: `GET /offline/security/nemo/config`
- All existing endpoints unchanged

## Disable NeMo

```bash
export AGENTSHIELD_NEMO_ENABLED=false
# or simply omit — false is the default
```

All existing capabilities work with NeMo disabled.

See `docs/nemo-integration/installation.md` for full setup guide.
