"""Liveness and configuration status endpoints.

Neither endpoint ever reveals key material, file paths, URLs, or environment
values (invariant INV-02; plan section 6).
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from app import __version__
from app.api.deps import get_services
from app.schemas import ConfigStatusResponse
from app.services.detection import SENSITIVE_CATEGORIES

router = APIRouter(tags=["system"])


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness only: no config values, no secrets."""
    return {"status": "ok"}


@router.get("/api/v1/config/status", response_model=ConfigStatusResponse)
def config_status(request: Request) -> ConfigStatusResponse:
    services = get_services(request)
    settings = services.settings
    return ConfigStatusResponse(
        app_env=settings.app_env,
        version=__version__,
        provider=services.provider.name,
        external_enabled=settings.allow_external_llm,
        provider_configured=settings.provider_configured,
        external_calls_enabled=settings.external_calls_enabled,
        restore_enabled=services.restore.enabled,
        detector_categories=sorted(SENSITIVE_CATEGORIES),
        max_input_chars=settings.max_input_chars,
        max_output_tokens=settings.max_output_tokens,
    )
