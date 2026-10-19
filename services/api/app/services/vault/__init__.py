"""Local encrypted vault package."""

from app.services.vault.crypto import open_record, seal
from app.services.vault.key_provider import (
    EnvKeyProvider,
    KeyFileProvider,
    KeyProvider,
    StaticKeyProvider,
    build_key_provider,
)
from app.services.vault.store import VaultRecordMeta, VaultStore

__all__ = [
    "EnvKeyProvider",
    "KeyFileProvider",
    "KeyProvider",
    "StaticKeyProvider",
    "VaultRecordMeta",
    "VaultStore",
    "build_key_provider",
    "open_record",
    "seal",
]
