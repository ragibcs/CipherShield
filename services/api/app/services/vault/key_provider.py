"""Key providers for the vault encryption key (VEK).

The interface exists so a production KMS/HSM implementation can be dropped in
without touching vault code. The MVP ships two local providers:

- `EnvKeyProvider`   — 64-char hex in `CIPHERSHIELD_KEY` (for CI/tests).
- `KeyFileProvider`  — base64 key file created with mode 0600 if missing.

Keys are never logged, never serialized into API responses, and never sent to
an LLM provider.
"""

from __future__ import annotations

import base64
import logging
import os
import stat
import sys
from pathlib import Path
from typing import Protocol, runtime_checkable

from app.core.errors import VaultError
from app.services.vault.crypto import KEY_SIZE

__all__ = ["EnvKeyProvider", "KeyFileProvider", "StaticKeyProvider", "build_key_provider"]

logger = logging.getLogger("ciphershield.vault")


@runtime_checkable
class KeyProvider(Protocol):
    def get_key(self) -> bytes: ...


class StaticKeyProvider:
    """Fixed key; intended for tests and in-memory demos only."""

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_SIZE:
            raise VaultError("Vault key must be a 32-byte value.")
        self._key = key

    def get_key(self) -> bytes:
        return self._key


class EnvKeyProvider:
    """Reads a 64-char hex key from an environment variable."""

    def __init__(self, var_name: str = "CIPHERSHIELD_KEY") -> None:
        self.var_name = var_name

    def get_key(self) -> bytes:
        raw = os.environ.get(self.var_name, "").strip()
        if not raw:
            raise VaultError("Vault key environment variable is not set.")
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise VaultError("Vault key environment variable is malformed.") from exc
        if len(key) != KEY_SIZE:
            raise VaultError("Vault key environment variable has the wrong length.")
        return key


class KeyFileProvider:
    """Local key file: created with restrictive permissions if absent."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    def get_key(self) -> bytes:
        try:
            if not self.path.exists():
                return self._generate()
            return self._read()
        except VaultError:
            raise
        except OSError as exc:
            raise VaultError("Vault key file could not be read.") from exc

    def _read(self) -> bytes:
        raw = self.path.read_text(encoding="ascii").strip()
        try:
            key = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise VaultError("Vault key file is malformed.") from exc
        if len(key) != KEY_SIZE:
            raise VaultError("Vault key file has the wrong length.")
        self._check_permissions()
        return key

    def _generate(self) -> bytes:
        key = os.urandom(KEY_SIZE)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = base64.b64encode(key).decode("ascii") + "\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(self.path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(payload)
        except FileExistsError:
            return self._read()
        except OSError as exc:
            raise VaultError("Vault key file could not be created.") from exc
        logger.warning("generated new local vault key file")
        return key

    def _check_permissions(self) -> None:
        if sys.platform == "win32":  # pragma: no cover - POSIX-only check
            return
        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode & 0o077:
            os.chmod(self.path, 0o600)
            logger.warning("vault key file permissions tightened to 0600")


def build_key_provider(key_file: str) -> KeyFileProvider | EnvKeyProvider:
    """Prefer an explicit env key (CI/tests) else the local key file."""
    if os.environ.get("CIPHERSHIELD_KEY", "").strip():
        return EnvKeyProvider()
    return KeyFileProvider(key_file)
