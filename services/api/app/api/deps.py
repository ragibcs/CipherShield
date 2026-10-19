"""Route dependencies."""

from __future__ import annotations

from fastapi import Request

from app.container import Services
from app.core.errors import CipherShieldError, PayloadTooLargeError

__all__ = ["get_request_id", "get_services", "require_size"]


def get_services(request: Request) -> Services:
    services = getattr(request.app.state, "services", None)
    if services is None:  # pragma: no cover - wiring bug, fail closed
        raise CipherShieldError()
    return services


def get_request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "") or "")


def require_size(services: Services, text: str) -> None:
    if len(text) > services.settings.max_input_chars:
        raise PayloadTooLargeError()
