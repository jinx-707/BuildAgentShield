# NeMo Guardrails — Installation

## Prerequisites

- Python 3.11+
- AgentShield Offline module installed
- (For model_backed/production profiles) A compatible LLM provider

## Install

```bash
# From the agentshield-offline directory:
pip install -e ".[nemo]"

# Verify:
python -c "import nemoguardrails; print(nemoguardrails.__version__)"
```

The `nemo` optional extra installs `nemoguardrails==0.10.1` and its
transitive dependencies (langchain, annoy, lark, etc.).

## Telemetry opt-out

NeMo Guardrails collects anonymous usage statistics by default.
AgentShield automatically sets the following before NeMo is imported:

```python
os.environ["NEMO_GUARDRAILS_NO_USAGE_STATS"] = "1"
os.environ["DO_NOT_TRACK"] = "1"
```

This is controlled by `AGENTSHIELD_NEMO_TELEMETRY_DISABLED=true` (default).

**Important**: Disabling NeMo telemetry does not stop content from being
sent to a configured LLM provider (OpenAI etc.). That is a separate concern
controlled by your choice of NeMo profile.

## Configuration

Set these environment variables (or add to `.env`):

```bash
AGENTSHIELD_NEMO_ENABLED=true
AGENTSHIELD_NEMO_PROFILE=local          # local | model_backed | production
AGENTSHIELD_NEMO_TIMEOUT=30             # seconds per inspection
AGENTSHIELD_NEMO_FAIL_CLOSED=true       # deny on NeMo failure
AGENTSHIELD_NEMO_INSPECT_DOCUMENTS=true
AGENTSHIELD_NEMO_INSPECT_TERMINAL_OUTPUT=true
AGENTSHIELD_NEMO_MAX_CONTENT_CHARS=50000
AGENTSHIELD_NEMO_TELEMETRY_DISABLED=true
```

## Verify integration

```bash
# Start the API:
python -m app.main

# Check NeMo health:
curl http://localhost:8001/offline/security/nemo/health

# Run demo:
python examples/nemo_guardrails_health.py
python examples/nemo_document_inspection.py
```

## Run tests (no live NeMo required)

```bash
pytest tests/unit/test_nemo_inspector.py -v
pytest tests/integration/test_nemo_document_integration.py -v
pytest tests/adversarial/test_nemo_fail_closed.py -v
```
