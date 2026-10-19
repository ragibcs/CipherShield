"""OpenAI-compatible chat-completions adapter.

Safety properties:
- Credentials are attached server-side only and registered with the log
  scrubber; they never appear in error messages.
- Hard timeouts and bounded input/output sizes.
- Errors are normalized to content-free `ProviderError`s (no response bodies
  are propagated, because bodies can echo prompt content).
- No silent fallback: if this adapter is selected, it either answers or the
  caller sees a typed failure.
"""

from __future__ import annotations

import time

import httpx

from app.core.errors import PayloadTooLargeError, ProviderError, ProviderNotConfiguredError
from app.core.logging import get_scrubber
from app.services.providers.base import ProviderRequest, ProviderResponse

__all__ = ["OpenAICompatibleProvider"]


class OpenAICompatibleProvider:
    name = "openai-compatible"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float = 30.0,
        max_output_tokens: int = 1200,
        max_input_chars: int = 20000,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not base_url or not api_key or not model:
            raise ProviderNotConfiguredError()
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.max_input_chars = max_input_chars
        self._api_key = api_key
        self._call_count = 0
        # INV-02: the key is scrubbed from every log line for the process lifetime.
        get_scrubber().register(api_key)
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
            transport=transport,
            follow_redirects=False,
        )

    @property
    def call_count(self) -> int:
        return self._call_count

    def close(self) -> None:
        self._client.close()

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        content = request.user_content
        if len(content) > self.max_input_chars:
            raise PayloadTooLargeError()

        payload = {
            "model": request.model or self.model,
            "messages": request.messages,
            "max_tokens": min(request.max_tokens, self.max_output_tokens),
            "temperature": request.temperature,
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}

        started = time.perf_counter()
        try:
            response = self._client.post("/chat/completions", json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            raise ProviderError("The provider request timed out.") from exc
        except httpx.HTTPError as exc:
            # NOTE: message stays static — httpx errors can embed URLs/headers.
            raise ProviderError("The provider connection failed.") from exc
        latency_ms = (time.perf_counter() - started) * 1000

        if response.status_code >= 400:
            # Status only: response bodies may echo the prompt (INV-10).
            raise ProviderError(f"The provider returned HTTP {response.status_code}.")

        try:
            data = response.json()
            text = data["choices"][0]["message"]["content"]
            if not isinstance(text, str):
                raise TypeError
            usage = data.get("usage") or {}
            input_tokens = int(usage.get("prompt_tokens") or 0)
            output_tokens = int(usage.get("completion_tokens") or 0)
            model = str(data.get("model") or payload["model"])
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ProviderError("The provider returned an unexpected response shape.") from exc

        self._call_count += 1
        return ProviderResponse(
            text=text,
            provider=self.name,
            model=model,
            latency_ms=latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
