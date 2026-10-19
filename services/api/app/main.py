"""FastAPI application factory.

Run with: `uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000`

Error-handling rules (INV-10):
- Responses contain stable codes and static messages only.
- Validation errors never echo submitted content.
- Tracebacks are logged server-side (redacted), never returned.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.routes import analyze, audit, evaluation, health, lab, vault
from app.container import Services, build_services
from app.core.config import Settings, load_dotenv
from app.core.errors import CipherShieldError
from app.core.middleware import RateLimitMiddleware, RequestContextMiddleware

logger = logging.getLogger("ciphershield.api")


def _cors_origins() -> list[str]:
    raw = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    if settings is None:
        load_dotenv()
        settings = Settings.from_env()

    production = settings.app_env == "production"
    app = FastAPI(
        title="CipherShield AI API",
        version=__version__,
        description=("Local-first secret-isolating gateway for LLM-powered security analysis."),
        docs_url=None if production else "/docs",
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
    )

    selected = services if services is not None else build_services(settings)
    app.state.services = selected

    # Add order is reversed: last added runs first.
    app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["GET", "POST"],
        allow_headers=["X-Request-ID", "Content-Type"],
    )
    app.add_middleware(RequestContextMiddleware)

    @app.exception_handler(CipherShieldError)
    async def _known_error(_request: Request, exc: CipherShieldError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        # Never echo submitted content back inside validation messages.
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Request validation failed.",
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unexpected(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error: %s", type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": "Internal server error."}},
        )

    app.include_router(health.router)
    app.include_router(analyze.router)
    app.include_router(audit.router)
    app.include_router(vault.router)
    app.include_router(evaluation.router)
    app.include_router(lab.router)
    return app
