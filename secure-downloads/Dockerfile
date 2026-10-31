FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# python-magic needs libmagic; no compiler/toolchain is required at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system app \
    && useradd --system --gid app --create-home app

WORKDIR /app

# Editable install keeps /app on sys.path so api.app can locate alembic.ini
# and migrations/ relative to the source tree at runtime.
COPY pyproject.toml alembic.ini ./
COPY api config integrations migrations models security services storage ./
RUN pip install -e .

RUN mkdir -p /var/secure-download-storage \
    && chown -R app:app /app /var/secure-download-storage

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import sys, urllib.request; r = urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3); sys.exit(0 if r.status == 200 else 1)"

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
