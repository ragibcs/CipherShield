"""Policy gate + tool policy: default deny, residue checks, fail-closed."""

from __future__ import annotations

import json

from app.services.detection import SecretScanner
from app.services.policy import (
    CODE_EXTERNAL_DISABLED,
    CODE_FORBIDDEN_CATEGORY,
    CODE_OK,
    CODE_PAYLOAD_TOO_LARGE,
    CODE_POLICY_ERROR,
    CODE_SECRET_RESIDUE,
    OutboundGate,
    PolicyConfig,
    ToolPolicy,
)
from app.services.policy.gate import CODE_UNKNOWN_ARGUMENT, CODE_UNKNOWN_TOOL

FAKE_TOKEN = "sk-policy-fake-0987654321abcdef"


def test_clean_sanitized_payload_allowed(gate: OutboundGate) -> None:
    body = json.dumps({"messages": [{"role": "user", "content": "Summarize [SECRET_01] incident"}]})
    decision = gate.evaluate(body=body, known_secrets={"[SECRET_01]": FAKE_TOKEN}, external=True)
    assert decision.allowed and decision.code == CODE_OK


def test_forbidden_category_blocks(gate: OutboundGate) -> None:
    body = json.dumps({"content": f"raw token {FAKE_TOKEN} in the clear"})
    decision = gate.evaluate(body=body, external=True)
    assert not decision.allowed
    assert decision.code == CODE_FORBIDDEN_CATEGORY


def test_email_default_denied_unless_policy_allows(scanner: SecretScanner) -> None:
    open_gate = OutboundGate(scanner, PolicyConfig(external_enabled=True))
    allow_mail = OutboundGate(
        scanner,
        PolicyConfig(allowed_categories=frozenset({"email"}), external_enabled=True),
    )
    body = "owner alice@example.org reported the issue"
    assert open_gate.evaluate(body=body, external=True).code == CODE_FORBIDDEN_CATEGORY
    assert allow_mail.evaluate(body=body, external=True).allowed


def test_known_secret_residue_blocks_even_when_detector_would_miss(
    gate: OutboundGate,
) -> None:
    # Residue check is independent of pattern coverage: the gate knows this
    # request's originals from the vault mapping.
    body = json.dumps({"note": "value was hunter2sekrit per ticket"})
    decision = gate.evaluate(
        body=body, known_secrets={"[SECRET_01]": "hunter2sekrit"}, external=True
    )
    assert not decision.allowed and decision.code == CODE_SECRET_RESIDUE


def test_secret_split_across_whitespace_blocks(gate: OutboundGate) -> None:
    body = "key: sk-policy-fake-\n     0987654321abcdef"
    decision = gate.evaluate(body=body, known_secrets={"[SECRET_01]": FAKE_TOKEN}, external=True)
    assert not decision.allowed
    assert decision.code in (CODE_SECRET_RESIDUE, CODE_FORBIDDEN_CATEGORY)


def test_split_secret_without_detector_shape_caught_by_residue(gate: OutboundGate) -> None:
    # Detector cannot see this value (no pattern), but the gate compares the
    # exact outbound bytes against this request's known originals.
    body = "rotation notes: hunter2sek\n     rit per ticket"
    decision = gate.evaluate(
        body=body, known_secrets={"[SECRET_01]": "hunter2sekrit"}, external=True
    )
    assert not decision.allowed and decision.code == CODE_SECRET_RESIDUE


def test_external_disabled_blocks_external_send(scanner: SecretScanner) -> None:
    disabled = OutboundGate(scanner, PolicyConfig(external_enabled=False))
    decision = disabled.evaluate(body="benign content", external=True)
    assert not decision.allowed and decision.code == CODE_EXTERNAL_DISABLED
    # Local (mock) processing still allowed.
    assert disabled.evaluate(body="benign content", external=False).allowed


def test_oversized_body_blocks(gate: OutboundGate) -> None:
    decision = gate.evaluate(body="x" * 50_000, external=True)
    assert not decision.allowed and decision.code == CODE_PAYLOAD_TOO_LARGE


def test_policy_error_fails_closed() -> None:
    class ExplodingScanner:
        def scan(self, text: str) -> object:  # pragma: no cover - exercised below
            raise RuntimeError("boom")

    broken = OutboundGate(ExplodingScanner(), PolicyConfig(external_enabled=True))  # type: ignore[arg-type]
    decision = broken.evaluate(body="anything", external=True)
    assert not decision.allowed and decision.code == CODE_POLICY_ERROR


def test_unknown_tool_denied(tools: ToolPolicy) -> None:
    # AB-05 / INV-08: shell/fetch/exec are not on the allowlist.
    for name in ("shell", "exec", "fetch_url", "read_file", "run_python"):
        decision = tools.evaluate(name, {"cmd": "rm -rf /"})
        assert not decision.allowed and decision.code == CODE_UNKNOWN_TOOL


def test_unknown_argument_denied(tools: ToolPolicy) -> None:
    decision = tools.evaluate("incident_lookup", {"incident_id": "INC-1", "extra": "x"})
    assert not decision.allowed and decision.code == CODE_UNKNOWN_ARGUMENT


def test_allowlisted_tool_with_valid_args_allowed(tools: ToolPolicy) -> None:
    decision = tools.evaluate("incident_lookup", {"incident_id": "INC-1"})
    assert decision.allowed


def test_empty_allowlist_denies_everything() -> None:
    default_tools = ToolPolicy()
    decision = default_tools.evaluate("incident_lookup", {})
    assert not decision.allowed and decision.code == CODE_UNKNOWN_TOOL


def test_non_serializable_arguments_denied(tools: ToolPolicy) -> None:
    decision = tools.evaluate("incident_lookup", {"incident_id": object()})  # type: ignore[dict-item]
    assert not decision.allowed
