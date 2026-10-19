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
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"

# Local-first default: external LLM calls stay disabled unless configured.
ENV ALLOW_EXTERNAL_LLM=false

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
