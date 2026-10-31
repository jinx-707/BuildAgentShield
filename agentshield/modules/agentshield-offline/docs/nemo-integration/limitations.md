# NeMo Guardrails Integration — Known Limitations

## 1. Package installation requires network access
`nemoguardrails` has transitive dependencies (~15 packages including langchain).
In air-gapped environments, pre-download to a local mirror.

## 2. Tool-call rails not supported via check_async()
`check_async()` only runs input and output rails. Tool-call and tool-result
rails require `generate_async()` with declared tool schemas. This is a future
extension — see `docs/nemo-integration/input-output-rails.md`.

## 3. Local profile detection is heuristic only
The `local` profile uses Colang pattern matching without an LLM. It will miss
sophisticated, novel jailbreak attempts. For production use, configure
`model_backed` or `production` with a capable model.

## 4. Model-backed profile sends content to external provider
The `model_backed` profile sends document and terminal content to OpenAI (or
configured provider). Do not use this profile on confidential data without
reviewing your data classification policy and provider agreements.

## 5. NeMo PASSED is not a security clearance
NeMo returning PASSED does not grant any AgentShield permission. File access,
command execution, and secret retrieval remain controlled by AgentShield's own
enforcement independently of NeMo's result.

## 6. Content truncation
Content longer than `AGENTSHIELD_NEMO_MAX_CONTENT_CHARS` (default 50,000) is
truncated before NeMo inspection. Injections beyond this boundary are not
inspected by NeMo (but may still be caught by the local regex inspector).

## 7. NeMo startup time
The NeMo engine initialises at application startup. With a model-backed profile
and slow model loading, this may add 10–30 seconds to startup time.

## 8. Colang 1.0 syntax
The provided `rails.co` files use Colang 1.0 syntax. NeMo 0.10.x supports both
Colang 1.0 and 2.x. Check your installed version's defaults.
