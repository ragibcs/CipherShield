"""Secret-free, hash-chained audit log.

Design notes (documented honestly):
- Events are fixed-field dataclasses: raw prompt text, model output, secrets,
  keys, and vault mappings structurally cannot appear (INV-02).
- Each row stores `prev_hash` and `event_hash = sha256(prev_hash || canonical)`
  so edits/deletions are tamper-*evident* on verification.
- A hash chain does NOT stop an administrator from rewriting the entire log;
  that requires an external anchor and is out of scope (threat model).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.db import connect

__all__ = ["AuditEvent", "AuditLog", "AuditRecord", "verify_chain"]

_GENESIS = "0" * 64
_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    decision    TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    categories  TEXT NOT NULL,
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    latency_ms  REAL,
    outcome     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    event_hash  TEXT NOT NULL
)
"""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Fixed, secret-free event fields."""

    event_type: str
    decision: str
    reason_code: str
    request_id: str = ""
    categories: dict[str, int] = field(default_factory=dict)
    provider: str = "mock"
    model: str = ""
    latency_ms: float | None = None
    outcome: str = ""
    timestamp: str = ""

    def ensure_request_id(self) -> AuditEvent:
        if self.request_id:
            return self
        return AuditEvent(
            event_type=self.event_type,
            decision=self.decision,
            reason_code=self.reason_code,
            request_id=f"req_{uuid.uuid4().hex[:16]}",
            categories=dict(self.categories),
            provider=self.provider,
            model=self.model,
            latency_ms=self.latency_ms,
            outcome=self.outcome,
            timestamp=self.timestamp,
        )


@dataclass(frozen=True, slots=True)
class AuditRecord:
    id: int
    request_id: str
    timestamp: str
    event_type: str
    decision: str
    reason_code: str
    categories: dict[str, int]
    provider: str
    model: str
    latency_ms: float | None
    outcome: str
    prev_hash: str
    event_hash: str


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _payload(event: AuditEvent, timestamp: str) -> dict[str, Any]:
    data = asdict(event)
    data["timestamp"] = timestamp
    data["categories"] = dict(sorted(event.categories.items()))
    return data


class AuditLog:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(_SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return connect(self.db_path)

    def append(self, event: AuditEvent) -> AuditRecord:
        event = event.ensure_request_id()
        timestamp = event.timestamp or datetime.now(UTC).isoformat()
        payload = _payload(event, timestamp)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = row["event_hash"] if row else _GENESIS
            event_hash = hashlib.sha256(
                (prev_hash + _canonical(payload)).encode("utf-8")
            ).hexdigest()
            cursor = conn.execute(
                """
                    INSERT INTO audit_events
                    (request_id, timestamp, event_type, decision, reason_code, categories,
                     provider, model, latency_ms, outcome, prev_hash, event_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                (
                    event.request_id,
                    timestamp,
                    event.event_type,
                    event.decision,
                    event.reason_code,
                    _canonical({"counts": dict(sorted(event.categories.items()))}),
                    event.provider,
                    event.model,
                    event.latency_ms,
                    event.outcome,
                    prev_hash,
                    event_hash,
                ),
            )
            conn.commit()
            record_id = int(cursor.lastrowid or 0)
        return AuditRecord(
            id=record_id,
            request_id=event.request_id,
            timestamp=timestamp,
            event_type=event.event_type,
            decision=event.decision,
            reason_code=event.reason_code,
            categories=dict(event.categories),
            provider=event.provider,
            model=event.model,
            latency_ms=event.latency_ms,
            outcome=event.outcome,
            prev_hash=prev_hash,
            event_hash=event_hash,
        )

    def list_events(self, limit: int = 50) -> list[AuditRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._to_record(row) for row in rows]

    def verify(self) -> bool:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
        return verify_chain(rows)

    @staticmethod
    def _to_record(row: sqlite3.Row) -> AuditRecord:
        try:
            counts = json.loads(row["categories"]).get("counts", {})
        except (json.JSONDecodeError, AttributeError):
            counts = {}
        return AuditRecord(
            id=row["id"],
            request_id=row["request_id"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            decision=row["decision"],
            reason_code=row["reason_code"],
            categories=counts if isinstance(counts, dict) else {},
            provider=row["provider"],
            model=row["model"],
            latency_ms=row["latency_ms"],
            outcome=row["outcome"],
            prev_hash=row["prev_hash"],
            event_hash=row["event_hash"],
        )


def verify_chain(rows: list[sqlite3.Row]) -> bool:
    """Recompute the chain; any edit, deletion, or reordering breaks it."""
    prev_hash = _GENESIS
    for row in rows:
        if row["prev_hash"] != prev_hash:
            return False
        payload = {
            "event_type": row["event_type"],
            "decision": row["decision"],
            "reason_code": row["reason_code"],
            "request_id": row["request_id"],
            "categories": {},
            "provider": row["provider"],
            "model": row["model"],
            "latency_ms": row["latency_ms"],
            "outcome": row["outcome"],
            "timestamp": row["timestamp"],
        }
        # Rebuild categories from the stored canonical JSON.
        try:
            stored = json.loads(row["categories"])
            payload["categories"] = stored.get("counts", {}) if isinstance(stored, dict) else {}
        except json.JSONDecodeError:
            return False
        recomputed = hashlib.sha256((prev_hash + _canonical(payload)).encode("utf-8")).hexdigest()
        if recomputed != row["event_hash"]:
            return False
        prev_hash = row["event_hash"]
    return True
