# ARCHITECTURE_TARGET.md

## Current Architecture (As-Is)
```
AI Agent → FastAPI (8000) → Browser Worker (8080, internal) → Egress Proxy (3128/9090) → Internet
                              ↓
                          Puppeteer/Chromium
```

## Target Enterprise Architecture
Building on existing solid foundation, extend with:

### A. Control and API Layer (Extend existing FastAPI)
- Agent authentication (API keys/OAuth)
- Tenant authorization (RBAC/ABAC)
- Session orchestration (enhance existing)
- Policy management (CRUD API)
- Security events API
- Audit APIs
- User management

### B. Browser Execution Layer (Enhance existing Worker)
- Isolated sessions (already implemented)
- All operations (already implemented)
- Add resource quotas per tenant

### C. Network Security Layer (Enhance existing Proxy)
- All controls implemented
- Add centralized policy distribution

### D. Frontend (New/Enhanced)
- Next.js app added with dashboard
- Connect all pages to real APIs
- Add real-time updates
- Add forms for all operations

### E. Persistence
- PostgreSQL for durable records (tenants, users, policies, audit logs, sessions metadata)
- Redis for caching, rate limiting (distributed), ephemeral state, coordination
- Tenant isolation at DB level

### F. Attack Laboratory
- Isolated Docker environment
- Controlled targets
- Simulations
- Reports

### G. Hybrid Deployment
- Cloud control plane / customer-hosted data plane
- Authenticated control channel
- Signed policy sync
- Local enforcement during outages
