"""Deterministic mock provider: zero sockets, zero external dependencies.

Used for tests, demos, and whenever external calls are not explicitly
enabled. Output is derived only from the sanitized request, and the call
counter is what the evaluation uses to prove blocked requests never
reached any provider.
"""

from __future__ import annotations

import hashlib
import re
import time

from app.services.providers.base import ProviderRequest, ProviderResponse

__all__ = ["MockProvider"]

_PLACEHOLDER = re.compile(r"\[(?:SECRET|EMAIL|IP|USER_TEXT)_\d+\]")


class MockProvider:
    """Offline provider with deterministic, input-derived output."""

    name = "mock"

    def __init__(self) -> None:
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        started = time.perf_counter()
        self._call_count += 1
        content = request.user_content
        placeholders = _PLACEHOLDER.findall(content)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
        categories = sorted({p[1:].split("_")[0] for p in placeholders})
        text = (
            "[MOCK PROVIDER - offline, deterministic]\n"
            "Security analysis of the sanitized input:\n"
            f"- Sanitized size: {len(content)} characters\n"
            f"- Opaque placeholders observed: {len(placeholders)}"
            + (f" ({', '.join(categories)})" if categories else "")
            + "\n- No raw credential material was present in this context.\n"
            f"- Input digest: sha256:{digest}\n"
            "Recommendation: rotate any credential referenced by a placeholder, "
            "review the affected host, and confirm the audit trail for this request."
        )
        latency_ms = (time.perf_counter() - started) * 1000
        return ProviderResponse(
            text=text,
            provider=self.name,
            model=request.model or "mock-echo",
            latency_ms=latency_ms,
            input_tokens=max(1, len(content) // 4),
            output_tokens=max(1, len(text) // 4),
        )
