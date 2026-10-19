"""Outbound policy gate (decision 0002): fail closed, always.

The gate re-scans the **exact serialized** request body immediately before
send. Any error or ambiguity results in a blocked decision — never a send.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from app.services.detection.base import DEFAULT_DENY_CATEGORIES, SENSITIVE_CATEGORIES
from app.services.detection.scanner import SecretScanner

__all__ = [
    "CODE_EXTERNAL_DISABLED",
    "CODE_FORBIDDEN_CATEGORY",
    "CODE_OK",
    "CODE_PAYLOAD_TOO_LARGE",
    "CODE_POLICY_ERROR",
    "CODE_SECRET_RESIDUE",
    "OutboundGate",
    "PolicyConfig",
    "PolicyDecision",
    "ToolDecision",
    "ToolPolicy",
]

CODE_OK = "ok"
CODE_FORBIDDEN_CATEGORY = "forbidden_category"
CODE_SECRET_RESIDUE = "secret_residue"
CODE_EXTERNAL_DISABLED = "external_disabled"
CODE_PAYLOAD_TOO_LARGE = "payload_too_large"
CODE_POLICY_ERROR = "policy_error"

# Tool-policy codes
CODE_UNKNOWN_TOOL = "unknown_tool"
CODE_UNKNOWN_ARGUMENT = "unknown_argument"
CODE_INVALID_ARGUMENTS = "invalid_arguments"

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str
    counts: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {"allowed": self.allowed, "code": self.code, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    # Categories allowed to leave the boundary in raw form (default: none).
    allowed_categories: frozenset[str] = frozenset()
    # Categories blocked regardless of the allowlist.
    deny_categories: frozenset[str] = DEFAULT_DENY_CATEGORIES
    external_enabled: bool = False
    max_body_chars: int = 40000

    @classmethod
    def from_settings(cls, settings: object) -> PolicyConfig:
        """Build from a `Settings`-like object without importing config here."""
        max_chars = int(getattr(settings, "max_input_chars", 20000)) * 4
        return cls(
            external_enabled=bool(getattr(settings, "external_calls_enabled", False)),
            max_body_chars=max(40000, max_chars),
        )


def _normalize(text: str) -> str:
    """Whitespace-stripped form used to catch secrets split across delimiters."""
    return _WHITESPACE.sub("", text)


class OutboundGate:
    def __init__(
        self, scanner: SecretScanner | None = None, config: PolicyConfig | None = None
    ) -> None:
        self.scanner = scanner if scanner is not None else SecretScanner()
        self.config = config if config is not None else PolicyConfig()

    def evaluate(
        self,
        *,
        body: str,
        known_secrets: dict[str, str] | None = None,
        external: bool = False,
    ) -> PolicyDecision:
        """Decide whether `body` may be sent. Fails closed on any exception."""
        try:
            return self._evaluate(body=body, known_secrets=known_secrets or {}, external=external)
        except Exception:  # noqa: BLE001 - INV-13: any failure blocks the send
            return PolicyDecision(
                allowed=False,
                code=CODE_POLICY_ERROR,
                reason="Policy evaluation failed; request blocked.",
            )

    def _evaluate(
        self, *, body: str, known_secrets: dict[str, str], external: bool
    ) -> PolicyDecision:
        if len(body) > self.config.max_body_chars:
            return PolicyDecision(
                allowed=False,
                code=CODE_PAYLOAD_TOO_LARGE,
                reason="Serialized request exceeds the maximum size.",
            )

        # 1. Residual sensitive values in the exact outbound bytes.
        scan = self.scanner.scan(body)
        if scan.findings:
            for finding in scan.findings:
                if (
                    finding.category in self.config.deny_categories
                    or finding.category not in self.config.allowed_categories
                ):
                    return PolicyDecision(
                        allowed=False,
                        code=CODE_FORBIDDEN_CATEGORY,
                        reason=(
                            f"Unsanitized value of category '{finding.category}' remains outbound."
                        ),
                        counts=scan.counts,
                    )

        # 2. Known original secrets (this request's mapping) must not appear.
        normalized = _normalize(body)
        for secret in known_secrets.values():
            if not secret:
                continue
            if secret in body or _normalize(secret) in normalized:
                return PolicyDecision(
                    allowed=False,
                    code=CODE_SECRET_RESIDUE,
                    reason="A known secret remains in the outbound payload.",
                    counts=scan.counts,
                )

        # 3. External sending requires explicit opt-in (INV-14).
        if external and not self.config.external_enabled:
            return PolicyDecision(
                allowed=False,
                code=CODE_EXTERNAL_DISABLED,
                reason="External provider calls are disabled by configuration.",
                counts=scan.counts,
            )

        return PolicyDecision(
            allowed=True,
            code=CODE_OK,
            reason="Payload passed the outbound policy gate.",
            counts=scan.counts,
        )


@dataclass(frozen=True, slots=True)
class ToolDecision:
    allowed: bool
    code: str
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {"allowed": self.allowed, "code": self.code, "reason": self.reason}


class ToolPolicy:
    """Deny-by-default tool policy (INV-08).

    - Unknown tool names are denied.
    - Arguments must be a JSON object of scalar/string values within bounds.
    - If a tool declares allowed argument keys, unknown keys are denied.
    """

    def __init__(
        self,
        allowlist: frozenset[str] | None = None,
        argument_schema: dict[str, frozenset[str]] | None = None,
        max_args: int = 25,
        max_arg_chars: int = 512,
    ) -> None:
        self.allowlist = allowlist if allowlist is not None else frozenset()
        self.argument_schema = argument_schema or {}
        self.max_args = max_args
        self.max_arg_chars = max_arg_chars

    def evaluate(self, name: str, arguments: dict[str, object] | None) -> ToolDecision:
        if not isinstance(name, str) or not name:
            return ToolDecision(False, CODE_INVALID_ARGUMENTS, "Tool name is invalid.")
        if name not in self.allowlist:
            return ToolDecision(False, CODE_UNKNOWN_TOOL, "Tool is not on the allowlist.")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return ToolDecision(False, CODE_INVALID_ARGUMENTS, "Tool arguments must be an object.")
        if len(arguments) > self.max_args:
            return ToolDecision(False, CODE_INVALID_ARGUMENTS, "Too many tool arguments.")

        allowed_keys = self.argument_schema.get(name)
        for key, value in arguments.items():
            if not isinstance(key, str):
                return ToolDecision(
                    False, CODE_INVALID_ARGUMENTS, "Argument names must be strings."
                )
            if allowed_keys is not None and key not in allowed_keys:
                return ToolDecision(
                    False, CODE_UNKNOWN_ARGUMENT, f"Argument '{key}' is not allowed for this tool."
                )
            if not isinstance(value, str | int | float | bool | type(None)):
                return ToolDecision(
                    False, CODE_INVALID_ARGUMENTS, "Argument values must be scalars."
                )
            if isinstance(value, str) and len(value) > self.max_arg_chars:
                return ToolDecision(False, CODE_INVALID_ARGUMENTS, "Argument value is too long.")

        # Round-trip through JSON to guarantee serializability before any use.
        try:
            json.dumps(arguments)
        except (TypeError, ValueError):
            return ToolDecision(
                False, CODE_INVALID_ARGUMENTS, "Tool arguments are not serializable."
            )
        return ToolDecision(True, "ok", "Tool call allowed by policy.")


def sensitive_categories() -> frozenset[str]:
    return SENSITIVE_CATEGORIES
