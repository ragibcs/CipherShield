"""Provider contract (decision 0003): one interface, mock and HTTP adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = ["LLMProvider", "ProviderRequest", "ProviderResponse"]

Role = str  # "system" | "user" | "assistant"


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    """Sanitized-only request. Nothing sensitive should ever be in here."""

    messages: list[dict[str, str]]
    model: str = ""
    max_tokens: int = 1200
    temperature: float = 0.0
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def user_content(self) -> str:
        for message in reversed(self.messages):
            if message.get("role") == "user":
                return message.get("content", "")
        return ""


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    text: str
    provider: str
    model: str
    latency_ms: float
    input_tokens: int = 0
    output_tokens: int = 0


@runtime_checkable
class LLMProvider(Protocol):
    """Every implementation must be side-effect free w.r.t. secrets: it only
    ever receives content that already passed the outbound policy gate."""

    name: str

    @property
    def call_count(self) -> int: ...

    def complete(self, request: ProviderRequest) -> ProviderResponse: ...
