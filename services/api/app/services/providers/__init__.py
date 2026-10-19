"""LLM provider package."""

from app.services.providers.base import LLMProvider, ProviderRequest, ProviderResponse
from app.services.providers.mock import MockProvider
from app.services.providers.openai_compat import OpenAICompatibleProvider

__all__ = [
    "LLMProvider",
    "MockProvider",
    "OpenAICompatibleProvider",
    "ProviderRequest",
    "ProviderResponse",
    "build_provider",
]


def build_provider(settings: object) -> LLMProvider:
    """Select the provider from configuration — never implicitly.

    - External calls explicitly enabled + valid config -> HTTP adapter.
    - External calls enabled but config invalid        -> hard error (no
      silent fallback to mock, so a misconfiguration cannot masquerade as a
      successful external run).
    - External calls disabled                          -> mock provider.
    """
    allow_external = bool(getattr(settings, "allow_external_llm", False))
    configured = bool(getattr(settings, "provider_configured", False))
    if allow_external and not configured:
        from app.core.errors import ProviderNotConfiguredError

        raise ProviderNotConfiguredError()
    if allow_external and configured:
        return OpenAICompatibleProvider(
            base_url=str(getattr(settings, "llm_base_url", "")),
            api_key=str(getattr(settings, "llm_api_key", "")),
            model=str(getattr(settings, "llm_model", "")),
            timeout_seconds=float(getattr(settings, "llm_timeout_seconds", 30.0)),
            max_output_tokens=int(getattr(settings, "max_output_tokens", 1200)),
            max_input_chars=int(getattr(settings, "max_input_chars", 20000)),
        )
    return MockProvider()
