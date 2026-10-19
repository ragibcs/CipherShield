# CipherShield AI backend
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/ciphershield-api

# Non-root runtime user; data and key material live on mounted volumes.
RUN useradd --create-home --uid 10001 ciphershield \
    && mkdir -p /srv/ciphershield-api/data /var/lib/ciphershield \
    && chown -R ciphershield:ciphershield /srv/ciphershield-api /var/lib/ciphershield

COPY --chown=ciphershield:ciphershield pyproject.toml README.md ./
COPY --chown=ciphershield:ciphershield app ./app
RUN pip install --no-cache-dir .

USER ciphershield
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; p = os.environ.get('PORT', '8000'); urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=4)"

# Local-first default: external LLM calls stay disabled unless configured.
ENV ALLOW_EXTERNAL_LLM=false

# Render (and most PaaS) injects $PORT; local/Docker Compose default to 8000.
CMD ["sh", "-c", "uvicorn app.main:create_app --factory --host 0.0.0.0 --port ${PORT:-8000}"]
