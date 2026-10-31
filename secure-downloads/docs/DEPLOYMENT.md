# Deployment Guide

## Required services

| Service | Required for | Notes |
|---|---|---|
| Python runtime | API | 3.11+; CI used 3.15.0 |
| Egress proxy | Production/staging | Must forward only approved destinations and attest `{"status":"ok","mode":"enforcing"}` at its health URL |
| ClamAV daemon (clamd) | Mandatory for approval | TCP 3310 on a private network; unauthenticated protocol |
| Database | Always | SQLite file for a single process; PostgreSQL requires `asyncpg` |
| Analysis provider | Only if `ANALYSIS_PROVIDER=http` | Contract v1; none selected in this repository |
| Filesystem volume | Always | Persistent, writable by the API user, protected (ideally encrypted) |
| TLS termination | Production | The app serves plain HTTP; terminate TLS in front of it and restrict network access |

The service has no built-in TLS listener, no authentication proxy, and no
cluster coordination. Put it behind your ingress and network policy.

## Local run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env           # edit values; never commit real credentials
ENVIRONMENT=development uvicorn api.app:app --host 127.0.0.1 --port 8000
```

Migrations run automatically at startup. `python -m pytest` runs the full
suite.

## Container build

```bash
docker build -t agentshield-secure-downloads:local .
docker run --rm -p 8000:8000 \
  -e ENVIRONMENT=development \
  -e API_AUTH_TOKEN="$(openssl rand -hex 32)" \
  -v "$PWD/storage:/var/secure-download-storage" \
  agentshield-secure-downloads:local
```

The image runs as an unprivileged user and includes `libmagic` for MIME
detection. It does **not** include a proxy, ClamAV, or a provider.

## Docker Compose (development/demo reference)

`docker-compose.yml` starts the API plus a ClamAV container and mounts a named
storage volume. It is a local/demo reference, **not a production deployment**:

- no egress proxy is bundled;
- `ENVIRONMENT` defaults to `development`, so production fail-closed rules do
  not apply;
- analysis defaults to `disabled`;
- a bearer token must be supplied (`API_AUTH_TOKEN` is required by Compose).

```bash
export API_AUTH_TOKEN="$(openssl rand -hex 32)"
docker compose up --build
curl -s localhost:8000/health/live
```

For a production-like stack, set `ENVIRONMENT=production`,
`REQUIRE_EGRESS_PROXY=true`, `EGRESS_PROXY_URL`, `EGRESS_PROXY_HEALTH_URL`,
`ALLOWED_DOMAINS`, `ANALYSIS_PROVIDER=http` (+ endpoint/token), and provide a
real proxy, a real clamd instance, PostgreSQL, and TLS termination. Startup
will refuse to run if those are missing or unsafe.

## Proxy requirements

The proxy must:

1. be the only route to the internet for this service (network policy);
2. enforce the same domain/allow-list/port policy as `ALLOWED_DOMAINS`,
   `BLOCKED_DOMAINS`, `ALLOWED_PORTS` — the service's checks are
   defence-in-depth, not the authoritative boundary when a proxy is used;
3. reject private/link-local/metadata destinations and unexpected ports;
4. expose a health endpoint returning `{"status":"ok","mode":"enforcing"}`;
5. require the service credential if `PROXY_AUTH_TOKEN` is configured
   (`Proxy-Authorization: Basic base64("agentshield:<token>")`).

If the proxy cannot be attested, downloads fail and readiness is `503`.

## ClamAV

Run clamd where the API can reach it over a private network. `clamd` traffic is
plaintext and unauthenticated — do not expose port 3310 beyond the host/network
that needs it. Keep signatures updated; a stale engine is a deployment defect
this service cannot detect. `/health/ready` checks reachability only, not
signature freshness.

## Database and migrations

- SQLite: use a file on a durable volume. One API process only.
- PostgreSQL: install `asyncpg`, set
  `DATABASE_URL=postgresql+asyncpg://user:password@host:5432/dbname`.
  Startup runs `alembic upgrade head`; ensure the role may create/alter tables.
- Two migrations exist: `0001` (downloads) and `0002` (analyses). Back up
  before upgrades.

## Storage volume

- Mount `STORAGE_ROOT` on persistent storage.
- The API creates `temporary/`, `quarantine/`, `approved/` with `0700`; files
  are `0600`.
- Approved files expire after `APPROVED_FILE_TTL_SECONDS`; quarantined files
  are retained until an operator deletes them.
- Size the volume for the maximum in-flight downloads
  (`MAX_CONCURRENT_DOWNLOADS_PER_TENANT` × tenants × `MAX_FILE_SIZE_BYTES`) plus
  retained quarantine. Monitor free space; disk-full failures are not
  automatically remediated.

## Health checks

| Probe | Use |
|---|---|
| `GET /health/live` | Container liveness; do not gate on dependencies |
| `GET /health/ready` | Load-balancer readiness; includes dependency + security gates |

Because readiness probes the database, storage, scanner, and proxy, a
dependency outage removes the instance from service. That is intentional for
the security gate; use liveness for restart decisions.

## Production checklist

- [ ] `ENVIRONMENT=production` (or `staging`), secrets injected, not committed
- [ ] `API_AUTH_TOKEN` set and rotated on a schedule
- [ ] Egress proxy configured, policy-matched, health endpoint attested
- [ ] `REQUIRE_EGRESS_PROXY=true`, `DNS_PREFLIGHT_ENABLED=true`,
      `ALLOW_PRIVATE_NETWORKS=false`
- [ ] `ALLOWED_DOMAINS`/`ALLOWED_PORTS` reviewed; `DEFAULT_DOMAIN_POLICY=deny`
- [ ] clamd reachable and signature updates monitored
- [ ] `STORAGE_ROOT` on a durable, protected, ideally encrypted volume
- [ ] Database backed up; migration plan reviewed
- [ ] `ANALYSIS_PROVIDER=http` only after a real provider acceptance test
- [ ] TLS termination and network policy in front of the API
- [ ] Log collection with access control; no secrets/content in logs
- [ ] Restore drill for DB and storage performed

## Upgrade and rollback

1. Back up the database and storage metadata.
2. Stop the service (or drain it behind the load balancer).
3. Deploy the new image; migrations run at startup.
4. Check `/health/live`, then `/health/ready` with all dependencies up.
5. Roll back by redeploying the previous image; migrations are forward-only —
   verify downgrade scripts before rolling back across a schema change.

## Known deployment gaps

- No multi-replica coordination (rate limits, scan locks, analysis queue,
  startup recovery assume one process).
- `asyncpg` is not bundled for PostgreSQL.
- No backup/restore automation.
- No secret-manager integration; environment variables only.
- No approved-file retrieval endpoint or object-store integration.
- Real provider and real ClamAV acceptance must be completed in staging before
  production claims (see [FINAL_VERIFICATION.md](FINAL_VERIFICATION.md)).
