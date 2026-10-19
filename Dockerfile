# syntax=docker/dockerfile:1
# All-in-one demo image: FastAPI backend + Next.js UI in ONE container.
#
#   docker build -t ciphershield .
#   docker run --rm -p 3000:3000 -p 8000:8000 ciphershield
#   UI:  http://localhost:3000
#   API: http://localhost:8000/health
#
# Notes:
# - Same-origin by default: the browser calls relative /api/... paths,
#   which the Next server proxies to the co-located API (next.config rewrites).
#   Set NEXT_PUBLIC_API_URL only to point the browser at a DIFFERENT origin.
# - For the two-service setup (docker-compose.yml / render.yaml) use the
#   per-service images instead (services/api/Dockerfile, apps/web/Dockerfile).
# - External LLM calls stay disabled (mock provider) unless configured.

# ---------------------------------------------------------------- web build
FROM node:22-bookworm-slim AS web-builder
WORKDIR /build/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
ARG NEXT_PUBLIC_API_URL=""
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# --------------------------------------------------------------- api build
FROM python:3.12-slim AS api-builder
WORKDIR /build/api
COPY services/api/pyproject.toml services/api/README.md ./
COPY services/api/app ./app
# Install app + deps (uvicorn, cryptography, ...) into an isolated prefix.
RUN pip install --no-cache-dir --prefix=/install .

# ---------------------------------------------------------------- runtime
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000 \
    API_PORT=8000 \
    ALLOW_EXTERNAL_LLM=false \
    PYTHONPATH=/install/lib/python3.12/site-packages \
    PATH=/install/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Node runtime binary (both images are Debian/glibc; app deps are vendored
# inside .next/standalone by Next.js).
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node

RUN useradd --create-home --uid 10001 ciphershield \
    && mkdir -p /srv/ciphershield/data \
    && chown -R ciphershield:ciphershield /srv/ciphershield
WORKDIR /srv/ciphershield

COPY --from=api-builder --chown=ciphershield:ciphershield /install /install
COPY --chown=ciphershield:ciphershield services/api/app ./app
COPY --from=web-builder --chown=ciphershield:ciphershield /build/web/.next/standalone ./web/
COPY --from=web-builder --chown=ciphershield:ciphershield /build/web/.next/static ./web/.next/static
COPY --from=web-builder --chown=ciphershield:ciphershield /build/web/public ./web/public

USER ciphershield
EXPOSE 3000 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os, urllib.request; p = os.environ.get('API_PORT', '8000'); urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=4)"

# UI on $PORT (Next reads PORT), API on $API_PORT; each in its own scope.
CMD sh -c "node web/server.js & exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port ${API_PORT:-8000}"
