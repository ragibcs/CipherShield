"""Built-in detectors.

Honest limitation: these patterns are intentionally transparent and tested,
not exhaustive. Unknown secret formats are out of reach for this MVP and are
documented in the threat model.
"""

from __future__ import annotations

import re

from app.services.detection.base import (
    CATEGORY_API_TOKEN,
    CATEGORY_BEARER_TOKEN,
    CATEGORY_EMAIL,
    CATEGORY_IPV4,
    CATEGORY_PASSWORD,
    BaseDetector,
)

__all__ = [
    "ApiTokenDetector",
    "BearerTokenDetector",
    "EmailDetector",
    "HexTokenDetector",
    "Ipv4Detector",
    "KeyValueSecretDetector",
    "default_detectors",
]


class ApiTokenDetector(BaseDetector):
    """Vendor-shaped API tokens (OpenAI, GitHub, AWS, Google, Slack)."""

    name = "api_token_common"
    category = CATEGORY_API_TOKEN
    pattern = re.compile(
        r"\b(?:"
        r"(?:sk|rk)-[A-Za-z0-9_\-]{16,}"
        r"|gh[pousr]_[A-Za-z0-9]{16,}"
        r"|AKIA[0-9A-Z]{16}"
        r"|AIza[0-9A-Za-z_\-]{20,}"
        r"|xox[baprs]-[A-Za-z0-9\-]{10,}"
        r")\b"
    )
    scan_compact = True


class HexTokenDetector(BaseDetector):
    """Long hex blobs (session identifiers, hashed secrets)."""

    name = "hex_token"
    category = CATEGORY_API_TOKEN
    pattern = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
    scan_compact = True


class BearerTokenDetector(BaseDetector):
    """`Authorization: Bearer <token>` — the token value is redacted, the
    scheme keyword is kept so the sanitized text stays readable."""

    name = "bearer_token"
    category = CATEGORY_BEARER_TOKEN
    pattern = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=\-]{8,})")
    scan_compact = True

    def value_span(self, match: re.Match[str]) -> tuple[int, int]:
        return match.start(1), match.end(1)


class KeyValueSecretDetector(BaseDetector):
    """password=/api_key:/token=... in common key/value shapes."""

    name = "password_kv"
    category = CATEGORY_PASSWORD
    pattern = re.compile(
        r"(?i)\b(?:password|passwd|pwd|pw|secret|api[_-]?key|apikey|token|access[_-]?key)"
        r"(\s*[:=]\s*)([\"']?)([^\s\"',;]{4,})"
    )
    scan_compact = True

    def value_span(self, match: re.Match[str]) -> tuple[int, int]:
        return match.start(3), match.end(3)


class EmailDetector(BaseDetector):
    name = "email"
    category = CATEGORY_EMAIL
    pattern = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


class Ipv4Detector(BaseDetector):
    """IPv4 with octet validation so `999.1.2.3` and versions are ignored."""

    name = "ipv4"
    category = CATEGORY_IPV4
    pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def keep(self, match: re.Match[str], text: str) -> bool:
        parts = match.group(0).split(".")
        if len(parts) != 4:
            return False
        # `isdecimal` (not `isdigit`) so Unicode digits like "²" never reach int().
        # Private/version addresses are valid findings, so no extra filtering here.
        return all(part.isdecimal() and int(part) <= 255 for part in parts)


def default_detectors() -> list[BaseDetector]:
    """Default detector set; tests may inject narrower lists."""
    return [
        ApiTokenDetector(),
        HexTokenDetector(),
        BearerTokenDetector(),
        KeyValueSecretDetector(),
        EmailDetector(),
        Ipv4Detector(),
    ]
