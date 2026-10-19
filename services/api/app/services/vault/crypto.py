"""AES-256-GCM record primitives (decision 0001).

Record layout: `ciphershield.v1` | 96-bit nonce | ciphertext||tag  (b64url).
Fresh random nonce per encryption. Any verification failure raises `VaultError`
so callers fail closed.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.errors import VaultError

__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "RECORD_PREFIX",
    "b64decode",
    "b64encode",
    "open_record",
    "seal",
]

RECORD_PREFIX = b"ciphershield.v1"
KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # 96-bit nonce, the GCM-recommended size
_AAD = b"ciphershield.vault.v1"


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise VaultError("Vault key must be a 32-byte value.")


def seal(key: bytes, plaintext: bytes) -> str:
    """Encrypt+authenticate `plaintext`; returns a b64url record string."""
    _validate_key(key)
    if not isinstance(plaintext, bytes):
        raise VaultError()
    nonce = os.urandom(NONCE_SIZE)  # fresh random nonce per operation (INV-05)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, _AAD)
    except Exception as exc:  # pragma: no cover - AESGCM only fails on bad key
        raise VaultError() from exc
    record = RECORD_PREFIX + nonce + ciphertext
    return base64.urlsafe_b64encode(record).decode("ascii")


def open_record(key: bytes, record: str) -> bytes:
    """Decrypt+verify a record. Tampering or a wrong key raises VaultError."""
    _validate_key(key)
    try:
        raw = base64.urlsafe_b64decode(record.encode("ascii"))
    except Exception as exc:
        raise VaultError() from exc
    prefix_len = len(RECORD_PREFIX)
    if len(raw) < prefix_len + NONCE_SIZE + 16 or not raw.startswith(RECORD_PREFIX):
        raise VaultError("Vault record format is invalid.")
    nonce = raw[prefix_len : prefix_len + NONCE_SIZE]
    ciphertext = raw[prefix_len + NONCE_SIZE :]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _AAD)
    except (InvalidTag, ValueError) as exc:
        # INV-06: modified ciphertext / tag / wrong key must be rejected.
        raise VaultError("Vault record failed authentication.") from exc


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data.encode("ascii"))
    except Exception as exc:
        raise VaultError() from exc
