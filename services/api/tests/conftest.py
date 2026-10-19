"""Shared fixtures. All tests are offline and use synthetic secrets only."""

from __future__ import annotations

import os

import pytest

from app.services.audit import AuditLog
from app.services.detection import SecretScanner
from app.services.policy import OutboundGate, PolicyConfig, ToolPolicy
from app.services.tokenization import Tokenizer
from app.services.vault import StaticKeyProvider, VaultStore

TEST_KEY = bytes.fromhex("ab" * 32)


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests must never see real credentials or external-call opt-ins."""
    for var in (
        "ALLOW_EXTERNAL_LLM",
        "LLM_API_KEY",
        "LLM_BASE_URL",
        "LLM_MODEL",
        "CIPHERSHIELD_KEY",
        "VAULT_RESTORE_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def key_provider() -> StaticKeyProvider:
    return StaticKeyProvider(TEST_KEY)


@pytest.fixture
def db_path(tmp_path) -> str:
    return str(tmp_path / "test.db")


@pytest.fixture
def vault(db_path: str, key_provider: StaticKeyProvider) -> VaultStore:
    return VaultStore(db_path, key_provider)


@pytest.fixture
def audit(db_path: str) -> AuditLog:
    return AuditLog(db_path)


@pytest.fixture
def scanner() -> SecretScanner:
    return SecretScanner()


@pytest.fixture
def tokenizer(scanner: SecretScanner) -> Tokenizer:
    return Tokenizer(scanner)


@pytest.fixture
def gate(scanner: SecretScanner) -> OutboundGate:
    return OutboundGate(scanner, PolicyConfig(external_enabled=True))


@pytest.fixture
def tools() -> ToolPolicy:
    return ToolPolicy(
        allowlist=frozenset({"incident_lookup"}),
        argument_schema={"incident_lookup": frozenset({"incident_id"})},
    )


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    def _clear() -> None:
        for key in list(os.environ):
            if key.startswith(("LLM_", "ALLOW_", "CIPHERSHIELD", "VAULT_")):
                monkeypatch.delenv(key, raising=False)

    _clear()
    return _clear
