# AgentShield Offline Security Module
# Multi-stage build for minimal production image

ARG PYTHON_VERSION=3.11

# ---- Build stage ----
FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY requirements.txt pyproject.toml ./

# Install dependencies into a prefix directory
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---- Runtime stage ----
FROM python:${PYTHON_VERSION}-slim AS runtime

# Install runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    clamav \
    clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r agentshield && useradd -r -g agentshield -d /app -s /sbin/nologin agentshield

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Set working directory
WORKDIR /app

# Copy application code
COPY app/ ./app/
COPY configs/ ./configs/
COPY pyproject.toml ./

# Create required directories with correct ownership
RUN mkdir -p /var/log/agentshield /var/agentshield/quarantine logs \
    && chown -R agentshield:agentshield /app /var/log/agentshield /var/agentshield

# Switch to non-root user
USER agentshield

# Environment defaults (override via .env or environment variables)
ENV AGENTSHIELD_ENVIRONMENT=production \
    AGENTSHIELD_API_HOST=0.0.0.0 \
    AGENTSHIELD_API_PORT=8001 \
    AGENTSHIELD_DEBUG=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8001/offline/health').raise_for_status()"

CMD ["python", "-m", "app.main"]
