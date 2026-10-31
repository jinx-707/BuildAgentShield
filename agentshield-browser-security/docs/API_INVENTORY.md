# API_INVENTORY.md

## FastAPI API (Port 8000)
### Health
- GET /health
- GET /health/live
- GET /health/ready

### Browser Operations (`/v1/browser`)
- POST /v1/browser/navigate
- POST /v1/browser/session
- GET /v1/browser/session/{session_id}
- DELETE /v1/browser/session/{session_id}
- POST /v1/browser/search
- POST /v1/browser/extract
- POST /v1/browser/action
- POST /v1/browser/screenshot
- GET /v1/browser/screenshot

All routes implemented in `api/app/api/browser.py`. Schemas in `api/app/schemas/`. Services in `api/app/services/`.

## Worker API (Port 8080, internal)
### Health
- GET /health, GET /health/live, GET /health/ready

### Operations
- POST /v1/navigate
- POST /v1/session, GET /v1/session/:id, DELETE /v1/session/:id
- POST /v1/search (if proxied?) - check
- POST /v1/extract
- POST /v1/actions
- POST /v1/screenshot

Routes in `worker/src/routes/`. Auth middleware applied.

## Proxy (Port 3128/9090)
HTTP proxy server, CONNECT for HTTPS, health on 9090.

## OpenAPI
Available at /docs when running.
