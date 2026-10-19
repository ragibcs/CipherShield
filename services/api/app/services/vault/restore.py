"""Explicit, authorized, audited placeholder restoration (INV-12).

Restore is disabled entirely unless a restore token is configured, and it is
audited on both success and failure. Callers must pass the token; comparison
is constant-time.
"""

from __future__ import annotations

import secrets

from app.core.errors import RestoreAuthorizationError, VaultError
from app.services.audit import AuditEvent, AuditLog
from app.services.vault.store import VaultStore

__all__ = ["RestoreService"]

_MAX_PLACEHOLDERS = 500


class RestoreService:
    def __init__(self, vault: VaultStore, audit: AuditLog, auth_token: str = "") -> None:
        self.vault = vault
        self.audit = audit
        self.auth_token = auth_token

    @property
    def enabled(self) -> bool:
        return bool(self.auth_token)

    def restore(
        self,
        *,
        record_id: str,
        placeholders: list[str],
        token: str | None,
        request_id: str = "",
    ) -> dict[str, str]:
        if not self.enabled:
            self._audit("denied", "restore_disabled", request_id)
            raise RestoreAuthorizationError("Restore is disabled on this instance.")
        if not token or not secrets.compare_digest(token, self.auth_token):
            self._audit("denied", "restore_bad_token", request_id)
            raise RestoreAuthorizationError()
        if len(placeholders) > _MAX_PLACEHOLDERS:
            self._audit("denied", "restore_too_many", request_id)
            raise RestoreAuthorizationError("Too many placeholders requested.")

        try:
            mapping = self.vault.get(record_id)
        except VaultError:
            self._audit("denied", "vault_error", request_id)
            raise

        missing = [p for p in placeholders if p not in mapping]
        if missing:
            # Unknown/stale placeholders are rejected rather than guessed.
            self._audit("denied", "unknown_placeholder", request_id)
            raise VaultError("Requested placeholders were not found in the record.")

        values = {p: mapping[p] for p in placeholders}
        self._audit("allowed", "ok", request_id, count=len(values))
        return values

    def _audit(self, decision: str, reason: str, request_id: str, count: int = 0) -> None:
        self.audit.append(
            AuditEvent(
                event_type="vault_restore",
                decision=decision,
                reason_code=reason,
                request_id=request_id,
                categories={"restored_values": count} if count else {},
                outcome="restore_denied" if decision == "denied" else "restore_completed",
            )
        )
