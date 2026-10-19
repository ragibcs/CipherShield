"""Safe error types.

Messages are static strings by design: they must never embed request
content, secrets, keys, or stack traces (invariant INV-10).
"""

from __future__ import annotations

__all__ = [
    "CipherShieldError",
    "PayloadTooLargeError",
    "PolicyEvaluationError",
    "ProviderError",
    "ProviderNotConfiguredError",
    "RestoreAuthorizationError",
    "VaultError",
]


class CipherShieldError(Exception):
    """Base error with a stable, content-free message and HTTP status."""

    code: str = "internal_error"
    status_code: int = 500
    default_message: str = "The request could not be completed."

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.default_message)
        self.message = message or self.default_message


class PayloadTooLargeError(CipherShieldError):
    code = "payload_too_large"
    status_code = 413
    default_message = "Input exceeds the configured maximum size."


class PolicyEvaluationError(CipherShieldError):
    """Policy could not be evaluated -> the caller must fail closed."""

    code = "policy_error"
    status_code = 503
    default_message = "Policy evaluation failed; the request was blocked."


class ProviderNotConfiguredError(CipherShieldError):
    code = "provider_not_configured"
    status_code = 503
    default_message = "External provider is not configured or not enabled."


class ProviderError(CipherShieldError):
    code = "provider_error"
    status_code = 502
    default_message = "The provider request failed."


class VaultError(CipherShieldError):
    code = "vault_error"
    status_code = 500
    default_message = "Vault operation failed."


class RestoreAuthorizationError(CipherShieldError):
    code = "restore_not_authorized"
    status_code = 403
    default_message = "Restore authorization missing or invalid."
