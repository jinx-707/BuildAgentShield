# AgentShield — Docker Deployment Guide

**Date:** 2026-10-31
**Version:** 1.0.0

---

## Overview

This guide covers deploying the complete AgentShield platform using Docker Compose. The deployment includes:

- **Frontend** (React + Vite + Tailwind) — Port 3000
- **API** (FastAPI) — Port 8000
- **PostgreSQL** — Port 5432
- **Redis** — Port 6379
- **Browser Worker** (Puppeteer/Node.js) — Port 8080
- **Egress Proxy** (Node.js) — Port 3128

---

## Prerequisites

- Docker Engine 24+
- Docker Compose 2+
- 4GB+ RAM available
- 10GB+ disk space

---

## Quick Start

```bash
# Clone the repository
cd agentshield-browser-security

# Copy environment template
cp .env.example .env  # or use existing .env

# Build and start all services
docker compose build
docker compose up -d

# Verify all services are healthy
docker compose ps

# View logs
docker compose logs -f

# Stop services
docker compose down
```

---

## Service Architecture

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐
│  Frontend   │────▶│    API      │────▶│  PostgreSQL      │
│  (Port 3000)│     │  (Port 8000)│     │  (Port 5432)     │
└─────────────┘     └──────┬──────┘     └──────────────────┘
                           │
                    ┌──────▼──────┐     ┌──────────────────┐
                    │    Redis    │     │  Browser Worker  │
                    │  (Port 6379)│     │  (Port 8080)     │
                    └─────────────┘     └────────┬─────────┘
                                                │
                                        ┌───────▼────────┐
                                        │  Egress Proxy  │
                                        │  (Port 3128)   │
                                        └────────────────┘
```

### Network Topology

- **edge** — Frontend, API, PostgreSQL, Redis (external access)
- **worker-net** — API, Browser Worker, Egress Proxy (internal)
- **egress-net** — Egress Proxy (external internet access)

---

## Environment Configuration

### Required Variables (.env)

```bash
# Environment
ENVIRONMENT=production
LOG_LEVEL=INFO

# API
API_HOST=127.0.0.1
API_PORT=8000
JWT_SECRET=<strong-random-32-byte-hex>  # REQUIRED in production
API_AUTH_TOKEN=<random-token>            # Optional: simple token auth

# Database
POSTGRES_DB=agentshield
POSTGRES_USER=agentshield
POSTGRES_PASSWORD=<strong-password>
POSTGRES_PORT=5432
DATABASE_URL=postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}

# Redis
REDIS_PORT=6379
REDIS_URL=redis://redis:6379/0

# Browser Worker
BROWSER_WORKER_URL=http://browser-worker:8080
WORKER_HOST=0.0.0.0
WORKER_PORT=8080
BROWSER_HEADLESS=true
BROWSER_EXECUTABLE_PATH=
BROWSER_NAVIGATION_TIMEOUT_MS=20000
BROWSER_MAX_CONTENT_BYTES=524288
BROWSER_ALLOW_PRIVATE_NETWORKS=false
WORKER_AUTH_TOKEN=<random-token>

# Egress Proxy
EGRESS_PROXY_URL=http://egress-proxy:3128
EGRESS_PROXY_HEALTH_URL=http://egress-proxy:9090/health/ready
EGRESS_PROXY_HEALTH_TIMEOUT_MS=3000
EGRESS_PROXY_HEALTH_CACHE_MS=5000
PROXY_AUTH_TOKEN=<random-token>
REQUIRE_EGRESS_PROXY=true

PROXY_HOST=0.0.0.0
PROXY_PORT=3128
PROXY_HEALTH_HOST=0.0.0.0
PROXY_HEALTH_PORT=9090
PROXY_ALLOWED_DOMAINS=example.com,api.example.org
PROXY_BLOCKED_DOMAINS=
PROXY_DEFAULT_DOMAIN_POLICY=deny
PROXY_ALLOWED_PORTS=80,443
PROXY_ALLOW_PRIVATE_NETWORKS=false
PROXY_DNS_TIMEOUT_MS=5000
PROXY_CONNECT_TIMEOUT_MS=10000
PROXY_DNS_SERVER=1.1.1.1

# Policy
ALLOWED_DOMAINS=example.com,api.example.org
BLOCKED_DOMAINS=
DEFAULT_DOMAIN_POLICY=deny
ALLOWED_PORTS=80,443
MAX_REDIRECTS=5
BLOCK_HTTPS_DOWNGRADE=true
ALLOW_PRIVATE_NETWORKS=false
DNS_PREFLIGHT_ENABLED=true
POLICY_BACKEND=egress-policy
INSPECTION_BACKEND=prompt-injection

# Search (optional)
SEARCH_PROVIDER=brave
SEARCH_API_KEY=<api-key>

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_BACKEND=redis
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_FAIL_OPEN=false
RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# Frontend
NEXT_PUBLIC_API_BASE_URL=http://api:8000
VITE_AGENTSHIELD_API_URL=http://api:8000/v1
VITE_AGENTSHIELD_DEMO_EMAIL=admin@agentshield.dev
VITE_AGENTSHIELD_DEMO_PASSWORD=<password>
VITE_AGENTSHIELD_AUTO_CONNECT=false
FRONTEND_PORT=3000
```

### Generating Secure Secrets

```bash
# JWT Secret (32 bytes = 64 hex chars)
python3 -c "import secrets; print(secrets.token_hex(32))"

# API Auth Token
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Worker/Proxy Auth Tokens
python3 -c "import secrets; print(secrets.token_hex(32))"

# Database Password
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

---

## Deployment Steps

### 1. Prepare Environment

```bash
cd agentshield-browser-security

# Create .env from template
cat > .env << 'EOF'
# Paste the environment variables from above
# Replace all <...> placeholders with generated values
EOF

# Verify .env has all required values
grep -E '^(JWT_SECRET|API_AUTH_TOKEN|POSTGRES_PASSWORD|WORKER_AUTH_TOKEN|PROXY_AUTH_TOKEN)=' .env
```

### 2. Build Images

```bash
# Build all services (first time or after code changes)
docker compose build

# Or build specific service
docker compose build api
docker compose build frontend
docker compose build browser-worker
docker compose build egress-proxy
```

### 3. Start Services

```bash
# Start in background
docker compose up -d

# Or start with logs
docker compose up
```

### 4. Verify Deployment

```bash
# Check service status
docker compose ps

# Expected output: all services "healthy" or "running"
# NAME                        STATUS
# agentshield-browser-security-api-1       Up (healthy)
# agentshield-browser-security-browser-worker-1  Up (healthy)
# agentshield-browser-security-egress-proxy-1   Up (healthy)
# agentshield-browser-security-frontend-1     Up (healthy)
# agentshield-browser-security-postgres-1    Up (healthy)
# agentshield-browser-security-redis-1       Up (healthy)

# Check individual service logs
docker compose logs api
docker compose logs browser-worker
docker compose logs egress-proxy
docker compose logs frontend
docker compose logs postgres
docker compose logs redis

# Test API health
curl http://127.0.0.1:8000/health/ready
curl http://127.0.0.1:8000/health/live

# Test worker health
curl http://127.0.0.1:8080/health/ready
curl http://127.0.0.1:8080/health/live

# Test proxy health
curl http://127.0.0.1:9090/health/ready
curl http://127.0.0.1:9090/health/live

# Test frontend
curl http://127.0.0.1:3000/
```

### 5. Initialize Database (First Run)

The database is automatically initialized on API startup via `init_db()`. For manual initialization:

```bash
# Run migrations manually if needed
docker compose exec api python -m alembic upgrade head

# Or seed development data
docker compose exec api python scripts/seed_dev.py
```

---

## Service Management

### Restart Services

```bash
# Restart all
docker compose restart

# Restart specific service
docker compose restart api
docker compose restart browser-worker
```

### Scale Services

```bash
# Scale API (requires load balancer)
docker compose up -d --scale api=3

# Scale worker (not recommended without coordination)
docker compose up -d --scale browser-worker=2
```

### Update Services

```bash
# Pull latest code
git pull

# Rebuild and restart
docker compose build
docker compose up -d
```

---

## Health Checks

All services include health checks:

| Service | Health Endpoint | Interval |
|---------|-----------------|----------|
| PostgreSQL | `pg_isready` | 10s |
| Redis | `redis-cli ping` | 10s |
| API | `GET /health/ready` | 10s |
| Browser Worker | `GET /health/ready` | 30s |
| Egress Proxy | `GET /health/ready` | 10s |
| Frontend | `wget /` | 30s |

### Monitoring

```bash
# Watch health status
watch docker compose ps

# Check specific health
docker compose exec api python -c "
import urllib.request
response = urllib.request.urlopen('http://127.0.0.1:8000/health/ready')
print(response.status, response.read())
"
```

---

## Data Persistence

### Volumes

- `postgres_data` — PostgreSQL data directory
- `redis_data` — Redis data directory

### Backup

```bash
# Backup PostgreSQL
docker compose exec postgres pg_dump -U agentshield agentshield > backup_$(date +%Y%m%d).sql

# Backup Redis
docker compose exec redis redis-cli BGSAVE
docker cp agentshield-browser-security-redis-1:/data/dump.rdb ./redis_backup_$(date +%Y%m%d).rdb
```

### Restore

```bash
# Restore PostgreSQL
cat backup_20261031.sql | docker compose exec -T postgres psql -U agentshield agentshield

# Restore Redis
docker cp ./redis_backup_20261031.rdb agentshield-browser-security-redis-1:/data/dump.rdb
docker compose restart redis
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
docker compose logs <service-name>

# Common issues:
# - Port already in use: change port in .env
# - Database connection failed: check DATABASE_URL and postgres health
# - Worker browser not found: ensure puppeteer installed in worker image
# - Proxy DNS failed: check PROXY_DNS_SERVER
```

### Database Connection Issues

```bash
# Test database connectivity
docker compose exec api python -c "
from app.db.base import get_engine
engine = get_engine()
with engine.connect() as conn:
    print(conn.execute('SELECT 1').scalar())
"
```

### Worker Browser Issues

```bash
# Check worker browser installation
docker compose exec browser-worker npx puppeteer browsers list

# Reinstall browser
docker compose exec browser-worker npx puppeteer browsers install chrome
```

### Proxy Issues

```bash
# Test proxy directly
curl -x http://127.0.0.1:3128 http://httpbin.org/ip

# Check proxy logs
docker compose logs egress-proxy
```

### Frontend Build Issues

```bash
# Rebuild frontend
docker compose build frontend
docker compose up -d frontend

# Check build logs
docker compose logs frontend
```

---

## Security Hardening

### Production Checklist

- [ ] Change all default passwords/secrets
- [ ] Set `ENVIRONMENT=production`
- [ ] Set strong `JWT_SECRET`
- [ ] Set `API_AUTH_TOKEN`
- [ ] Set `WORKER_AUTH_TOKEN` and `PROXY_AUTH_TOKEN`
- [ ] Configure `PROXY_ALLOWED_DOMAINS` for your allowed destinations
- [ ] Set `DEFAULT_DOMAIN_POLICY=deny`
- [ ] Set `ALLOW_PRIVATE_NETWORKS=false`
- [ ] Enable `RATE_LIMIT_BACKEND=redis`
- [ ] Set `RATE_LIMIT_FAIL_OPEN=false`
- [ ] Configure `RATE_LIMIT_TRUSTED_PROXIES` for your load balancer
- [ ] Use TLS termination (reverse proxy with certs)
- [ ] Restrict Docker daemon access
- [ ] Enable Docker content trust
- [ ] Scan images for vulnerabilities: `docker scout cves agentshield-browser-security-api`

### Network Security

- All services run as non-root
- Read-only root filesystems
- Dropped capabilities
- No-new-privileges
- PID limits
- Memory limits
- Internal networks for worker communication

---

## Maintenance

### Log Rotation

Logs are sent to stdout/stderr. Configure Docker logging driver:

```yaml
# In docker-compose.yml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### Cleanup

```bash
# Remove stopped containers
docker compose down

# Remove containers and volumes (DELETES DATA)
docker compose down -v

# Remove images
docker compose down --rmi all
```

---

## Development vs Production

### Development

```bash
# Use development overrides
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Or run services locally
# Backend: cd api && python -m uvicorn app.main:app --reload
# Frontend: cd BuildAgentShield-main && npm run dev
# Worker: cd worker && npm run dev
```

### Production

```bash
# Use production settings
ENVIRONMENT=production
LOG_LEVEL=WARNING
# All security settings enabled
```

---

## Support

For issues:
1. Check service logs: `docker compose logs <service>`
2. Verify health endpoints
3. Check network connectivity between services
4. Review environment variables
5. Consult [GitHub Issues](https://github.com/agentshield/agentshield/issues)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-10-31 | Initial deployment guide |