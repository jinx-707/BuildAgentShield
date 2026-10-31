# AgentShield Browser Security — Documentation Index

**Date:** 2026-10-31  
**Repository:** `/Users/admin/whack/agentshield-browser-security`  
**Scope:** Browser and web-search security module, Phase E1/F completion and end-to-end verification.

## Status

The controlled demo stack is functional and the complete E2E suite passes:

- API default suite: **228 passed, 34 skipped** (E2E skipped by default).
- Full E2E suite with `RUN_E2E=1`: **262 passed**.
- Worker: **131 passed**.
- Proxy: **53 passed**.

Production readiness is **not** claimed. See `FINAL_ACCEPTANCE_REPORT.md` for the verdict and conditions.

## Document map

| Document | Purpose |
| --- | --- |
| `ARCHITECTURE.md` | Components, trust boundaries, request flows, and deployment topology |
| `API_REFERENCE.md` | Caller-facing HTTP contract and error behavior |
| `SECURITY_MATRIX.md` | Implemented controls, evidence, and residual risk |
| `THREAT_MODEL.md` | Current threats, mitigations, and assumptions |
| `DEPLOYMENT_GUIDE.md` | Local, Compose, and production deployment guidance |
| `ENVIRONMENT_REFERENCE.md` | Environment variables, defaults, and production requirements |
| `DEMO_GUIDE.md` | Reproducible DEMO 1–10 and load-test procedures |
| `TEST_REPORT.md` | Test inventory, commands, results, and coverage gaps |
| `PERFORMANCE_REPORT.md` | Bounded load-test methodology and measured results |
| `FINAL_VERIFICATION.md` | Requirement-to-evidence traceability |
| `FINAL_ACCEPTANCE_REPORT.md` | Final verdict, conditions, and sign-off checklist |

## Historical documents

These earlier documents are retained for traceability and may describe an older baseline:

- `BROWSER_MODULE_INVENTORY.md`
- `BROWSER_SECURITY_THREAT_MODEL.md`
- `EGRESS_ENFORCEMENT.md`
- `FINAL_BASELINE_AUDIT.md`
- `PHASE_2_SECURITY_AUDIT.md`
