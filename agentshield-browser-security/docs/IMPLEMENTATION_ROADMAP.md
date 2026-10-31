# IMPLEMENTATION_ROADMAP.md

## Phase 0: Audit Complete (DONE)
- Audited entire repo, ran tests, created docs
- API: 228 passed, 34 skipped
- Worker: 131 passed  
- Proxy: 53 passed
- Frontend added with real API integration

## Phase 1: Enterprise Data Layer
**Priority:** Critical | **Dependencies:** None
- Add PostgreSQL models (tenants, users, agents, policies, audit_logs, security_events, sessions)
- Add Alembic migrations
- Add database session management
- Add Redis for caching/rate limiting coordination
- Migrate from in-memory where appropriate

**Acceptance:** DB connected, migrations run, models tested

## Phase 2: Authentication & Authorization
**Priority:** Critical | **Dependencies:** Phase 1
- User authentication (JWT/session)
- RBAC with roles/permissions
- Tenant isolation enforcement
- API key management for agents
- Permission-based rendering in frontend

**Acceptance:** Auth flows work, RBAC enforced, tenant isolation tested

## Phase 3: Security Events & Audit API
**Priority:** Critical | **Dependencies:** Phase 1
- Security events collection service
- Audit log API with search/filter/pagination
- Connect frontend events/audit pages to real APIs
- Structured event schema

**Acceptance:** Events flow from components to DB, queryable via API and UI

## Phase 4: Policy Management API
**Priority:** High | **Dependencies:** Phase 1, Phase 2
- CRUD APIs for policies
- Policy validation
- Connect frontend policies page
- Policy distribution

**Acceptance:** Policies manageable via UI/API

## Phase 5: Enhanced Dashboard & Real-time
**Priority:** High | **Dependencies:** Phase 3
- Connect all dashboard metrics to real data
- WebSocket/SSE for live updates
- Remove any mock data
- Add loading/error/empty states everywhere

**Acceptance:** Dashboard shows real metrics from DB/events

## Phase 6: Attack Laboratory Enhancement
**Priority:** High | **Dependencies:** All above
- Isolated Docker environment
- Controlled targets
- Automated test reports
- Connect to real scenarios

**Acceptance:** Attack lab runs real simulations

## Phase 7: Hybrid Deployment Support
**Priority:** Medium | **Dependencies:** Phase 1, Phase 4
- Control/data plane separation
- Authenticated control channel
- Signed policy sync
- Offline operation

**Acceptance:** Can operate in hybrid mode

## Phase 8: Testing & Hardening
**Priority:** Critical | **Dependencies:** All phases
- Unit, integration, API, authz, tenant isolation, negative security tests
- E2E tests
- Run all original tests after each change
- Security review

**Acceptance:** All tests pass, no security gaps
