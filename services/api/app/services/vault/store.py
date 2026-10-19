"""Encrypted vault store.

Only ciphertext lives on disk: mappings are JSON-serialized, sealed with
AES-256-GCM, and stored as b64url records (INV-07). Decryption failures are
surfaced as `VaultError` and never include the plaintext.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

from app.core.db import connect
from app.core.errors import VaultError
from app.services.vault.crypto import open_record, seal
from app.services.vault.key_provider import KeyProvider

__all__ = ["VaultRecordMeta", "VaultStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_records (
    record_id   TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    ciphertext  TEXT NOT NULL
)
"""


@dataclass(frozen=True, slots=True)
class VaultRecordMeta:
    """Metadata shown in the UI — contains no plaintext values."""

    record_id: str
    category: str
    created_at: str
    entry_count: int
    encrypted: bool = True


class VaultStore:
    def __init__(self, db_path: str, key_provider: KeyProvider) -> None:
        self.db_path = db_path
        self.key_provider = key_provider
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(_SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return connect(self.db_path)

    def put(self, record_id: str, mapping: dict[str, str], category: str = "mixed") -> None:
        """Seal and persist a placeholder -> original mapping."""
        if not mapping:
            return
        payload = json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ciphertext = seal(self.key_provider.get_key(), payload)
        created_at = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vault_records (record_id, category, created_at, entry_count, ciphertext)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(record_id) DO UPDATE SET
                    ciphertext = excluded.ciphertext,
                    entry_count = excluded.entry_count
                """,
                (record_id, category, created_at, len(mapping), ciphertext),
            )
            conn.commit()

    def get(self, record_id: str) -> dict[str, str]:
        """Open a record. Wrong key, tampered ciphertext, or unknown id -> VaultError."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT ciphertext FROM vault_records WHERE record_id = ?", (record_id,)
            ).fetchone()
        if row is None:
            raise VaultError("Vault record was not found.")
        plaintext = open_record(self.key_provider.get_key(), row["ciphertext"])
        try:
            data = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultError("Vault record content is invalid.") from exc
        if not isinstance(data, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in data.items()
        ):
            raise VaultError("Vault record content is invalid.")
        return data

    def list_records(self, limit: int = 100) -> list[VaultRecordMeta]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT record_id, category, created_at, entry_count FROM vault_records "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            VaultRecordMeta(
                record_id=row["record_id"],
                category=row["category"],
                created_at=row["created_at"],
                entry_count=row["entry_count"],
                encrypted=True,
            )
            for row in rows
        ]

    def delete(self, record_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM vault_records WHERE record_id = ?", (record_id,))
            conn.commit()
            return cursor.rowcount > 0

    def count(self) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM vault_records").fetchone()
        return int(row["n"]) if row else 0
