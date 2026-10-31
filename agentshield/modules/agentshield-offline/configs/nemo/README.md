# NeMo Guardrails Configuration

Three profiles are provided. Select with `AGENTSHIELD_NEMO_PROFILE`.

| Profile | Description | Model required? |
|---------|-------------|-----------------|
| `local` | Heuristic/regex rails only | No |
| `model_backed` | Heuristic + LLM-based safety | Yes (OpenAI or compatible) |
| `production` | Full rails with self-hosted model | Yes (local endpoint) |

## Quick start (local profile — no model needed)

```bash
export AGENTSHIELD_NEMO_ENABLED=true
export AGENTSHIELD_NEMO_PROFILE=local
python -m app.main
```

## Model-backed profile

```bash
export AGENTSHIELD_NEMO_ENABLED=true
export AGENTSHIELD_NEMO_PROFILE=model_backed
export OPENAI_API_KEY=sk-...   # never commit this
python -m app.main
```

## Production profile (self-hosted)

```bash
export AGENTSHIELD_NEMO_ENABLED=true
export AGENTSHIELD_NEMO_PROFILE=production
export NEMO_LLM_BASE_URL=http://your-inference-server/v1
python -m app.main
```

## Privacy reminder

The `local` profile sends no content to external services.
The `model_backed` and `production` profiles send document/terminal content
to the configured model provider. Review your data classification policy before
enabling these on confidential workloads. **Secrets are always redacted before
any content reaches NeMo** — this is enforced by the pipeline ordering in
`TerminalOutputInspector` and `DocumentGateway`.
