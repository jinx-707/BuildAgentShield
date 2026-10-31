# AgentShield Cyber Range — Docker Compose Architecture

## Services

### Core Profile (always running)
- postgres
- redis
- api
- browser-worker
- egress-proxy
- frontend

### Lab Profile (simulation targets + orchestrator)
- simulation-controller
- prompt-injection-target
- phishing-target
- ssrf-target
- malicious-download-target
- resource-exhaustion-target
- dns-rebinding-target
- data-exfiltration-sink
- evidence-collector

### Observability Profile (optional)
- prometheus
- grafana
- loki
- promtail

## Networks

- `agentshield_control` — API, DB, Redis, Controller, Frontend (management)
- `agentshield_simulation` — Controller, Targets, Evidence Collector (isolated lab)
- `agentshield_egress` — Browser Worker, Egress Proxy, Targets (controlled egress)

## Communication Paths

```
Frontend → API (agentshield_control)
API ↔ Postgres/Redis (agentshield_control)
API ↔ Browser Worker (agentshield_control + workers internal)
Browser Worker ↔ Egress Proxy (workers internal + agentshield_egress)
Egress Proxy → Targets (agentshield_egress)
Controller → Targets (agentshield_simulation)
Controller → Evidence Collector (agentshield_simulation)
Targets → Evidence Collector (agentshield_simulation)
```

## Security Boundaries

- Targets CANNOT access: postgres, redis, api, frontend, host
- Targets CAN access: each other (simulation network), evidence collector, egress proxy (controlled)
- Controller CANNOT access: host, docker socket, privileged operations
- All containers: non-root, read-only fs, capability drop, resource limits