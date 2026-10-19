"""AES-GCM vault: round-trip, tamper rejection, nonce freshness, disk hygiene."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from app.core.errors import VaultError
from app.services.vault import StaticKeyProvider, open_record, seal
from app.services.vault.crypto import KEY_SIZE, NONCE_SIZE, RECORD_PREFIX
from app.services.vault.key_provider import KeyFileProvider

SECRET = "sk-vault-fake-1234567890abcdef"
KEY = bytes.fromhex("cd" * 32)
OTHER_KEY = bytes.fromhex("ef" * 32)


def test_round_trip() -> None:
    record = seal(KEY, b"hello secret world")
    assert open_record(KEY, record) == b"hello secret world"


def test_nonce_is_fresh_per_encryption() -> None:
    # INV-05: same key, same plaintext -> different records (fresh nonce).
    records = {seal(KEY, b"same plaintext") for _ in range(50)}
    assert len(records) == 50
    nonces = {
        base64.urlsafe_b64decode(r.encode())[len(RECORD_PREFIX) : len(RECORD_PREFIX) + NONCE_SIZE]
        for r in records
    }
    assert len(nonces) == 50


def test_tampered_ciphertext_rejected() -> None:
    # INV-06
    raw = base64.urlsafe_b64decode(seal(KEY, b"payload").encode())
    tampered = bytearray(raw)
    tampered[-1] ^= 0x01  # flip one bit of the auth tag
    with pytest.raises(VaultError):
        open_record(KEY, base64.urlsafe_b64encode(bytes(tampered)).decode())


def test_tampered_payload_byte_rejected() -> None:
    raw = base64.urlsafe_b64decode(seal(KEY, b"payload-data").encode())
    tampered = bytearray(raw)
    prefix_len = len(RECORD_PREFIX)
    tampered[prefix_len + NONCE_SIZE] ^= 0xFF
    with pytest.raises(VaultError):
        open_record(KEY, base64.urlsafe_b64encode(bytes(tampered)).decode())


def test_wrong_key_rejected() -> None:
    # AB-13 / INV-06
    record = seal(KEY, b"payload")
    with pytest.raises(VaultError):
        open_record(OTHER_KEY, record)


def test_malformed_records_rejected() -> None:
    for bad in ("", "not-base64!!", base64.urlsafe_b64encode(b"short").decode()):
        with pytest.raises(VaultError):
            open_record(KEY, bad)


def test_invalid_key_size_rejected() -> None:
    with pytest.raises(VaultError):
        seal(b"short", b"data")


def test_store_never_persists_plaintext(vault, db_path: str) -> None:
    # INV-07: originals must not be readable from the database file.
    vault.put("req_1", {"[SECRET_01]": SECRET, "[EMAIL_01]": "a@example.org"})
    on_disk = Path(db_path).read_bytes()
    assert SECRET.encode() not in on_disk
    assert b"a@example.org" not in on_disk
    assert b"[SECRET_01]" not in on_disk  # mapping itself is sealed too


def test_store_round_trip(vault) -> None:
    mapping = {"[SECRET_01]": SECRET, "[IP_01]": "10.0.0.5"}
    vault.put("req_2", mapping, category="api_token")
    assert vault.get("req_2") == mapping
    records = vault.list_records()
    assert records and records[0].record_id == "req_2"
    assert records[0].encrypted is True
    assert records[0].entry_count == 2


def test_store_unknown_record_fails_closed(vault) -> None:
    with pytest.raises(VaultError):
        vault.get("does-not-exist")


def test_store_tampered_row_fails_closed(vault, db_path: str) -> None:
    import sqlite3

    vault.put("req_3", {"[SECRET_01]": SECRET})
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT ciphertext FROM vault_records WHERE record_id='req_3'").fetchone()
    raw = bytearray(base64.urlsafe_b64decode(row[0].encode()))
    raw[-1] ^= 0x01
    conn.execute(
        "UPDATE vault_records SET ciphertext=? WHERE record_id='req_3'",
        (base64.urlsafe_b64encode(bytes(raw)).decode(),),
    )
    conn.commit()
    conn.close()
    with pytest.raises(VaultError):
        vault.get("req_3")


def test_key_file_created_with_restrictive_permissions(tmp_path) -> None:
    key_path = tmp_path / "secrets" / "master.key"
    provider = KeyFileProvider(key_path)
    key = provider.get_key()
    assert len(key) == KEY_SIZE
    if os.name == "posix":
        assert (key_path.stat().st_mode & 0o777) == 0o600
    # Re-reading yields the same key (no rotation surprise).
    assert KeyFileProvider(key_path).get_key() == key


def test_static_provider_validates_length() -> None:
    with pytest.raises(VaultError):
        StaticKeyProvider(b"nope")
