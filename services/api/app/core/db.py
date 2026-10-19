"""SQLite helpers (stdlib only) shared by the vault and audit stores."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from app.core.errors import VaultError

__all__ = ["connect", "ensure_parent"]


def ensure_parent(db_path: str) -> None:
    if db_path == ":memory:":
        return
    try:
        Path(db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:  # pragma: no cover - environment specific
        raise VaultError() from exc


def connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with sane, failure-tolerant defaults."""
    ensure_parent(db_path)
    try:
        conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except sqlite3.Error as exc:
        raise VaultError() from exc
