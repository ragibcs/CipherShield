"""Restore flow (INV-12): explicit, authorized, audited."""

from __future__ import annotations

from dataclasses import asdict

import pytest

from app.core.errors import RestoreAuthorizationError, VaultError
from app.services.audit import AuditEvent, AuditLog
from app.services.vault import VaultStore
from app.services.vault.restore import RestoreService

MAPPING = {"[SECRET_01]": "sk-restore-fake-1234567890", "[EMAIL_01]": "a@example.org"}


def _seed(vault: VaultStore) -> None:
    vault.put("req_restore", MAPPING)


def test_restore_disabled_by_default(vault: VaultStore, audit: AuditLog) -> None:
    service = RestoreService(vault, audit, auth_token="")
    assert service.enabled is False
    with pytest.raises(RestoreAuthorizationError):
        service.restore(record_id="req_restore", placeholders=["[SECRET_01]"], token="anything")
    assert audit.list_events()[0].reason_code == "restore_disabled"


def test_restore_rejects_bad_token(vault: VaultStore, audit: AuditLog) -> None:
    _seed(vault)
    service = RestoreService(vault, audit, auth_token="correct-token")
    with pytest.raises(RestoreAuthorizationError):
        service.restore(record_id="req_restore", placeholders=["[SECRET_01]"], token="wrong")
    with pytest.raises(RestoreAuthorizationError):
        service.restore(record_id="req_restore", placeholders=["[SECRET_01]"], token=None)
    assert all(e.decision == "denied" for e in audit.list_events())
    assert vault.count() == 1  # nothing destroyed or leaked


def test_restore_with_valid_token_returns_selected_values(
    vault: VaultStore, audit: AuditLog
) -> None:
    _seed(vault)
    service = RestoreService(vault, audit, auth_token="correct-token")
    values = service.restore(
        record_id="req_restore", placeholders=["[SECRET_01]"], token="correct-token"
    )
    assert values == {"[SECRET_01]": MAPPING["[SECRET_01]"]}
    events = audit.list_events()
    assert events[0].decision == "allowed"
    assert events[0].event_type == "vault_restore"
    # Audit records the action without recording the restored value.
    assert MAPPING["[SECRET_01]"] not in str(asdict(events[0]))


def test_restore_unknown_placeholder_denied(vault: VaultStore, audit: AuditLog) -> None:
    _seed(vault)
    service = RestoreService(vault, audit, auth_token="correct-token")
    with pytest.raises(VaultError):
        service.restore(
            record_id="req_restore", placeholders=["[SECRET_99]"], token="correct-token"
        )
    assert audit.list_events()[0].reason_code == "unknown_placeholder"


def test_restore_missing_record_denied(vault: VaultStore, audit: AuditLog) -> None:
    service = RestoreService(vault, audit, auth_token="correct-token")
    with pytest.raises(VaultError):
        service.restore(record_id="nope", placeholders=["[SECRET_01]"], token="correct-token")
    assert audit.list_events()[0].decision == "denied"


def test_audit_events_structurally_secret_free(audit: AuditLog) -> None:
    audit.append(
        AuditEvent(
            event_type="analyze",
            decision="blocked",
            reason_code="forbidden_category",
            categories={"api_token": 2},
        )
    )
    rendered = str(asdict(audit.list_events()[0]))
    for forbidden in ("prompt", "content", "output", "password", "sk-"):
        assert forbidden not in rendered.lower()
