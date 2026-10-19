"""Detector contract and shared finding types.

Detectors are deliberately small and pluggable: adding a category means
adding a class and a test, nothing else.
"""

from __future__ import annotations

import re
from abc import ABC
from dataclasses import dataclass
from typing import ClassVar

__all__ = [
    "CATEGORY_API_TOKEN",
    "CATEGORY_BEARER_TOKEN",
    "CATEGORY_EMAIL",
    "CATEGORY_IPV4",
    "CATEGORY_PASSWORD",
    "DEFAULT_DENY_CATEGORIES",
    "SENSITIVE_CATEGORIES",
    "BaseDetector",
    "Finding",
]

CATEGORY_API_TOKEN = "api_token"
CATEGORY_BEARER_TOKEN = "bearer_token"
CATEGORY_PASSWORD = "password_kv"
CATEGORY_EMAIL = "email"
CATEGORY_IPV4 = "ipv4"

#: Categories the gateway knows how to detect.
SENSITIVE_CATEGORIES: frozenset[str] = frozenset(
    {
        CATEGORY_API_TOKEN,
        CATEGORY_BEARER_TOKEN,
        CATEGORY_PASSWORD,
        CATEGORY_EMAIL,
        CATEGORY_IPV4,
    }
)

#: Categories that must never leave the boundary even if a policy is lax.
DEFAULT_DENY_CATEGORIES: frozenset[str] = frozenset(
    {CATEGORY_API_TOKEN, CATEGORY_BEARER_TOKEN, CATEGORY_PASSWORD}
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One detected sensitive value and its span in the scanned text."""

    category: str
    detector: str
    value: str
    start: int
    end: int


class BaseDetector(ABC):
    """Regex detector with an optional value-span hook and keep filter."""

    name: ClassVar[str]
    category: ClassVar[str]
    pattern: ClassVar[re.Pattern[str]]
    #: Run this detector against the whitespace-compacted copy as well, which
    #: catches secrets split across whitespace or common delimiters (AB-07).
    scan_compact: ClassVar[bool] = False

    def value_span(self, match: re.Match[str]) -> tuple[int, int]:
        """Span of the sensitive value inside the full match (default: all)."""
        return match.start(), match.end()

    def keep(self, match: re.Match[str], text: str) -> bool:
        """Filter obviously invalid matches (kept overridable)."""
        return bool(match.group(0))

    def find(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in self.pattern.finditer(text):
            if not self.keep(match, text):
                continue
            start, end = self.value_span(match)
            findings.append(
                Finding(
                    category=self.category,
                    detector=self.name,
                    value=text[start:end],
                    start=start,
                    end=end,
                )
            )
        return findings
