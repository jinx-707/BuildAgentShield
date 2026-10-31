"""Integration tests for health and readiness endpoints."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import ASGITransport, AsyncClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(app):
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={
            "Authorization": "Bearer dev-secret-token",
            "X-Tenant-ID": "test-tenant",
            "X-Agent-ID": "test-agent",
        },
    )


# ---------------------------------------------------------------------------
# Existing /health tests — contract must not change
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_health_check_endpoint(async_client: AsyncClient):
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "agentshield-email-security"
    assert data["database"] == "connected"
    assert "version" in data
    assert "environment" in data


# ---------------------------------------------------------------------------
# /health/ready — development mode (no Redis, no external services)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_readiness_endpoint_exists():
    """/health/ready must be registered (not 404)."""
    from app.main import create_app
    app = create_app()
    async with _make_client(app) as client:
        resp = await client.get("/health/ready")
    assert resp.status_code != 404


@pytest.mark.asyncio
async def test_readiness_development_mode_db_ok_returns_200(async_client: AsyncClient):
    """Development mode with DB connected and no Redis → 200 ready."""
    resp = await async_client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["redis"] == "not_configured"


@pytest.mark.asyncio
async def test_readiness_response_shape(async_client: AsyncClient):
    """Response must include status, service, and checks keys."""
    resp = await async_client.get("/health/ready")
    body = resp.json()
    assert "status" in body
    assert "service" in body
    assert body["service"] == "agentshield-email-security"
    assert "checks" in body
    assert isinstance(body["checks"], dict)


@pytest.mark.asyncio
async def test_readiness_development_redis_not_configured(async_client: AsyncClient):
    """Development limiter backend → redis check must be 'not_configured', not 'unavailable'."""
    resp = await async_client.get("/health/ready")
    body = resp.json()
    assert body["checks"]["redis"] == "not_configured"


# ---------------------------------------------------------------------------
# /health/ready — database unavailable → 503
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_readiness_database_unavailable_returns_503():
    """When the database raises, readiness must return HTTP 503."""
    from app.main import create_app

    app = create_app()

    with patch("app.api.health_routes._check_database", return_value="unavailable"):
        async with _make_client(app) as client:
            resp = await client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["database"] == "unavailable"


# ---------------------------------------------------------------------------
# /health/ready — Redis backend configured but unavailable → 503
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_readiness_redis_unavailable_returns_503():
    """When RATE_LIMITER_BACKEND=redis and Redis is unreachable → HTTP 503."""
    from app.main import create_app
    from app.middleware.rate_limit import RedisRateLimiter
    import fakeredis

    app = create_app()

    # Wire a Redis-backed limiter whose ping will fail
    broken_redis = fakeredis.FakeRedis()
    limiter = RedisRateLimiter(redis_client=broken_redis, limits={})
    limiter._redis = MagicMock()
    limiter._redis.ping.side_effect = ConnectionError("redis down")
    app.state.rate_limiter_backend = limiter

    with patch("app.api.health_routes.get_settings") as mock_settings:
        s = MagicMock()
        s.RATE_LIMITER_BACKEND = "redis"
        s.APP_ENV = "development"
        s.POLICY_SERVICE_URL = "http://policy"
        s.INSPECTION_SERVICE_URL = "http://inspect"
        mock_settings.return_value = s

        async with _make_client(app) as client:
            resp = await client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["redis"] == "unavailable"


@pytest.mark.asyncio
async def test_readiness_redis_available_returns_ok():
    """When RATE_LIMITER_BACKEND=redis and Redis responds to PING → redis check is 'ok'."""
    from app.main import create_app
    from app.middleware.rate_limit import RedisRateLimiter
    import fakeredis

    app = create_app()

    healthy_redis = fakeredis.FakeRedis()
    limiter = RedisRateLimiter(redis_client=healthy_redis, limits={})
    app.state.rate_limiter_backend = limiter

    with patch("app.api.health_routes.get_settings") as mock_settings:
        s = MagicMock()
        s.RATE_LIMITER_BACKEND = "redis"
        s.APP_ENV = "development"
        s.POLICY_SERVICE_URL = "http://policy"
        s.INSPECTION_SERVICE_URL = "http://inspect"
        mock_settings.return_value = s

        async with _make_client(app) as client:
            resp = await client.get("/health/ready")

    assert resp.status_code == 200
    body = resp.json()
    assert body["checks"]["redis"] == "ok"


# ---------------------------------------------------------------------------
# /health/ready — policy service
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_readiness_policy_service_not_configured_in_production_returns_503():
    """In production, missing POLICY_SERVICE_URL must cause 503."""
    from app.main import create_app

    app = create_app()

    with patch("app.api.health_routes.get_settings") as mock_settings:
        s = MagicMock()
        s.RATE_LIMITER_BACKEND = "development"
        s.APP_ENV = "production"
        s.POLICY_SERVICE_URL = ""
        s.INSPECTION_SERVICE_URL = "http://inspect"
        mock_settings.return_value = s

        async with _make_client(app) as client:
            resp = await client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["policy_service"] == "not_configured"


@pytest.mark.asyncio
async def test_readiness_policy_service_not_configured_in_dev_still_200():
    """In development, missing POLICY_SERVICE_URL is advisory — must not block readiness."""
    from app.main import create_app

    app = create_app()

    with patch("app.api.health_routes.get_settings") as mock_settings:
        s = MagicMock()
        s.RATE_LIMITER_BACKEND = "development"
        s.APP_ENV = "development"
        s.POLICY_SERVICE_URL = ""
        s.INSPECTION_SERVICE_URL = ""
        mock_settings.return_value = s

        async with _make_client(app) as client:
            resp = await client.get("/health/ready")

    assert resp.status_code == 200
    body = resp.json()
    assert body["checks"]["policy_service"] == "not_configured"


@pytest.mark.asyncio
async def test_readiness_inspection_service_not_configured_in_production_returns_503():
    """In production, missing INSPECTION_SERVICE_URL must cause 503."""
    from app.main import create_app

    app = create_app()

    with patch("app.api.health_routes.get_settings") as mock_settings:
        s = MagicMock()
        s.RATE_LIMITER_BACKEND = "development"
        s.APP_ENV = "production"
        s.POLICY_SERVICE_URL = "http://policy"
        s.INSPECTION_SERVICE_URL = ""
        mock_settings.return_value = s

        async with _make_client(app) as client:
            resp = await client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["checks"]["inspection_service"] == "not_configured"


# ---------------------------------------------------------------------------
# /health/ready — production mode with Redis limiter, all deps healthy → 200
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_readiness_production_all_deps_healthy_returns_200():
    """Production mode with Redis + all service URLs configured → 200 ready."""
    from app.main import create_app
    from app.middleware.rate_limit import RedisRateLimiter
    import fakeredis

    app = create_app()
    limiter = RedisRateLimiter(redis_client=fakeredis.FakeRedis(), limits={})
    app.state.rate_limiter_backend = limiter

    with patch("app.api.health_routes.get_settings") as mock_settings:
        s = MagicMock()
        s.RATE_LIMITER_BACKEND = "redis"
        s.APP_ENV = "production"
        s.POLICY_SERVICE_URL = "http://policy"
        s.INSPECTION_SERVICE_URL = "http://inspect"
        mock_settings.return_value = s

        async with _make_client(app) as client:
            resp = await client.get("/health/ready")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["redis"] == "ok"
    assert body["checks"]["policy_service"] == "configured"
    assert body["checks"]["inspection_service"] == "configured"


# ---------------------------------------------------------------------------
# /health/ready — no sensitive information leaked
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_readiness_no_credentials_in_response(async_client: AsyncClient):
    """Readiness response must not contain URLs, tokens, or exception traces."""
    resp = await async_client.get("/health/ready")
    text = resp.text
    # No URLs
    assert "http://" not in text
    assert "https://" not in text
    # No stack traces
    assert "Traceback" not in text
    assert "Exception" not in text
    # No token-like strings
    assert "secret" not in text.lower()
    assert "password" not in text.lower()
    assert "token" not in text.lower()


@pytest.mark.asyncio
async def test_readiness_503_no_credentials_in_response():
    """503 readiness response must not leak internal details."""
    from app.main import create_app

    app = create_app()

    with patch("app.api.health_routes._check_database", return_value="unavailable"):
        async with _make_client(app) as client:
            resp = await client.get("/health/ready")

    assert resp.status_code == 503
    text = resp.text
    assert "secret" not in text
    assert "postgresql" not in text
    assert "internal-host" not in text
    assert "Traceback" not in text
