"""Service container: wires components with explicit, injectable dependencies."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings
from app.core.logging import configure_logging, get_scrubber
from app.services.audit import AuditLog
from app.services.detection import SecretScanner
from app.services.policy import OutboundGate, PolicyConfig, ToolPolicy
from app.services.providers import LLMProvider, ProviderRequest, build_provider
from app.services.response_inspection import ResponseInspector
from app.services.tokenization import Tokenizer
from app.services.vault import KeyProvider, VaultStore, build_key_provider
from app.services.vault.restore import RestoreService

__all__ = ["Services", "build_services"]

SYSTEM_PROMPT = (
    "You are a security analysis assistant. The content below contains opaque "
    "placeholders such as [SECRET_01] that stand in for redacted values. Never "
    "ask for, guess, or attempt to reconstruct original values. Respond with a "
    "concise risk summary and recommended next steps based only on the text given."
)

DETECTOR_COVERAGE_NOTE = (
    "Regex detection is intentionally incomplete: values without a matching "
    "pattern are not redacted. See security/threat-model.md."
)


@dataclass
class Services:
    settings: Settings
    scanner: SecretScanner
    tokenizer: Tokenizer
    vault: VaultStore
    gate: OutboundGate
    tools: ToolPolicy
    provider: LLMProvider
    inspector: ResponseInspector
    audit: AuditLog
    restore: RestoreService

    def close(self) -> None:
        close = getattr(self.provider, "close", None)
        if callable(close):
            close()


def build_services(
    settings: Settings,
    *,
    key_provider: KeyProvider | None = None,
    provider: LLMProvider | None = None,
    db_path: str | None = None,
) -> Services:
    configure_logging()
    scanner = SecretScanner()
    path = db_path if db_path is not None else settings.sqlite_path
    keys = (
        key_provider
        if key_provider is not None
        else build_key_provider(settings.ciphershield_key_file)
    )
    vault = VaultStore(path, keys)
    audit = AuditLog(path)
    gate = OutboundGate(scanner, PolicyConfig.from_settings(settings))
    selected_provider = provider if provider is not None else build_provider(settings)
    # The provider API key must be scrubbed from every log line (INV-02).
    if settings.llm_api_key:
        get_scrubber().register(settings.llm_api_key)
    return Services(
        settings=settings,
        scanner=scanner,
        tokenizer=Tokenizer(scanner),
        vault=vault,
        gate=gate,
        tools=ToolPolicy(allowlist=frozenset()),  # MVP: deny all tools (INV-08)
        provider=selected_provider,
        inspector=ResponseInspector(scanner),
        audit=audit,
        restore=RestoreService(vault, audit, settings.vault_restore_token),
    )


def build_outbound_payload(*, model: str, sanitized_text: str, max_tokens: int) -> dict:
    """The exact request object that will be handed to the provider.

    The policy gate serializes this same object before the call; httpx may
    differ only in insignificant whitespace, which the gate's residue check
    normalizes away.
    """
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": sanitized_text},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.0,
    }


def payload_to_request(payload: dict) -> ProviderRequest:
    return ProviderRequest(
        messages=list(payload["messages"]),
        model=str(payload.get("model", "")),
        max_tokens=int(payload.get("max_tokens", 1200)),
        temperature=float(payload.get("temperature", 0.0)),
    )
