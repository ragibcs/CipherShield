"""Audit log: secret-free structure and tamper-evident hash chain."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict

from app.services.audit import AuditEvent, AuditLog
from app.services.audit import AuditLog as Log
from app.services.audit.logger import verify_chain

RAW_PROMPT = "password=hunter2sekrit and key sk-audit-fake-1234567890"


def test_append_and_list(audit: AuditLog) -> None:
    record = audit.append(
        AuditEvent(
            event_type="analyze",
            decision="allowed",
            reason_code="ok",
            categories={"api_token": 1, "email": 2},
            provider="mock",
            model="mock-echo",
            latency_ms=12.5,
            outcome="completed",
        )
    )
    assert record.request_id.startswith("req_")
    events = audit.list_events()
    assert len(events) == 1
    assert events[0].decision == "allowed"
    assert events[0].categories == {"api_token": 1, "email": 2}


def test_events_have_no_free_text_fields(audit: AuditLog) -> None:
    """INV-02: raw prompt/output/secrets have nowhere to live in an event."""
    audit.append(
        AuditEvent(event_type="analyze", decision="blocked", reason_code="forbidden_category")
    )
    row = audit.list_events()[0]
    serialized = json.dumps(asdict(row))
    for leak in ("password", "hunter2sekrit", "prompt", "output_text"):
        assert leak not in serialized.lower()

    # And the schema itself has no content column.
    conn = audit._connect()  # noqa: SLF001 - structural assertion
    columns = [r[1] for r in conn.execute("PRAGMA table_info(audit_events)")]
    conn.close()
    assert "prompt" not in columns and "content" not in columns and "output" not in columns


def test_hash_chain_verifies(audit: AuditLog) -> None:
    for index in range(5):
        audit.append(
            AuditEvent(
                event_type="analyze",
                decision="allowed" if index % 2 == 0 else "blocked",
                reason_code="ok",
            )
        )
    assert audit.verify() is True


def test_chain_detects_tampering(audit: AuditLog) -> None:
    for _ in range(3):
        audit.append(
            AuditEvent(event_type="analyze", decision="blocked", reason_code="secret_residue")
        )
    conn = audit._connect()  # noqa: SLF001
    conn.execute("UPDATE audit_events SET decision='allowed' WHERE id=1")
    conn.commit()
    conn.close()
    assert audit.verify() is False


def test_chain_detects_deletion(audit: AuditLog) -> None:
    for _ in range(3):
        audit.append(AuditEvent(event_type="analyze", decision="allowed", reason_code="ok"))
    conn = audit._connect()  # noqa: SLF001
    conn.execute("DELETE FROM audit_events WHERE id=1")
    conn.commit()
    conn.close()
    assert audit.verify() is False


def test_verify_chain_helper_on_raw_rows(db_path: str) -> None:
    log = Log(db_path)
    log.append(AuditEvent(event_type="analyze", decision="allowed", reason_code="ok"))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    conn.close()
    assert verify_chain(rows) is True
    assert RAW_PROMPT not in str(rows[0])
