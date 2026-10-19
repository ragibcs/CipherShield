"""Deterministic placeholder tokenization with spoof defense.

Rules:
- IDs are sequential per category within one call: `[SECRET_01]`, `[EMAIL_01]`,
  `[IP_01]` — the same input always tokenizes the same way.
- The original values live only in the returned mapping, which the caller must
  seal in the vault; nothing else may persist them.
- Placeholder-looking text typed by the user is rewritten to `[USER_TEXT_n]`
  before scanning so it can never collide with a real mapping (AB-09).
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field

from app.services.detection.base import Finding
from app.services.detection.scanner import SecretScanner

__all__ = ["TokenizationResult", "TokenizedFinding", "Tokenizer"]

_PLACEHOLDER_LOOKALIKE = re.compile(r"\[(?:SECRET|EMAIL|IP)_\d+\]")

#: Placeholder prefix per detection category (category -> prefix).
_PREFIX_BY_CATEGORY: dict[str, str] = {
    "api_token": "SECRET",
    "bearer_token": "SECRET",
    "password_kv": "SECRET",
    "email": "EMAIL",
    "ipv4": "IP",
}


def _prefix_for(category: str) -> str:
    return _PREFIX_BY_CATEGORY.get(category, "SECRET")


@dataclass(slots=True)
class TokenizedFinding:
    finding: Finding
    placeholder: str


@dataclass(slots=True)
class TokenizationResult:
    sanitized_text: str
    original_text: str = field(repr=False, default="")
    tokens: list[TokenizedFinding] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def mapping(self) -> dict[str, str]:
        """placeholder -> original value. Handle as secret material."""
        return {token.placeholder: token.finding.value for token in self.tokens}


class Tokenizer:
    """Applies `SecretScanner` findings as deterministic opaque placeholders."""

    def __init__(self, scanner: SecretScanner | None = None) -> None:
        self.scanner = scanner if scanner is not None else SecretScanner()

    def tokenize(self, text: str) -> TokenizationResult:
        neutralized = self._neutralize_placeholders(text)
        scan = self.scanner.scan(neutralized)

        counters: dict[str, int] = {}
        tokens: list[TokenizedFinding] = []
        for finding in scan.findings:
            prefix = _prefix_for(finding.category)
            if prefix not in counters:
                counters[prefix] = 0
            # Deterministic per-category sequence: SECRET_01, SECRET_02, ...
            index = counters[prefix] + 1
            counters[prefix] = index
            placeholder = f"[{prefix}_{index:02d}]"
            tokens.append(TokenizedFinding(finding=finding, placeholder=placeholder))

        sanitized = self._replace(neutralized, tokens)
        return TokenizationResult(
            sanitized_text=sanitized,
            original_text=text,
            tokens=tokens,
            counts=dict(scan.counts),
        )

    @staticmethod
    def _neutralize_placeholders(text: str) -> str:
        """Rewrite user-typed placeholder tokens so they cannot spoof mappings."""
        counter = itertools.count(1)
        return _PLACEHOLDER_LOOKALIKE.sub(lambda _m: f"[USER_TEXT_{next(counter):02d}]", text)

    @staticmethod
    def _replace(text: str, tokens: list[TokenizedFinding]) -> str:
        # Right-to-left so earlier offsets stay valid.
        for token in sorted(tokens, key=lambda t: t.finding.start, reverse=True):
            start = token.finding.start
            end = token.finding.end
            text = text[:start] + token.placeholder + text[end:]
        return text
