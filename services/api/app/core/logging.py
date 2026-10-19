"""Redacting logging: no secret, key, or mapping value may reach a log line.

A `SecretScrubber` collects runtime-sensitive values (vault keys, provider
keys, known original secrets) and common credential shapes, then scrubs the
fully formatted message before it is emitted.
"""

from __future__ import annotations

import logging
import re
import threading

__all__ = ["SecretScrubber", "RedactingFormatter", "configure_logging", "get_scrubber"]

_MIN_REGISTER_LEN = 6

_PATTERNS: tuple[re.Pattern[str], ...] = (
    # OpenAI/GitHub/Google/AWS-style tokens
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{8,}"),
    # key/value credential shapes: password=..., api_key: ..., "token": "..."
    re.compile(
        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?key)"
        r"(\s*[:=]\s*)([\"']?)[^\s\"',;]{3,}"
    ),
    # Authorization headers
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}"),
)


class SecretScrubber:
    """Scrubs registered values and credential-shaped substrings."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: set[str] = set()

    def register(self, value: str | None) -> None:
        """Register a runtime-sensitive value to redact from all log output."""
        if not value or len(value) < _MIN_REGISTER_LEN:
            return
        with self._lock:
            self._values.add(value)

    def clear(self) -> None:
        with self._lock:
            self._values.clear()

    def scrub(self, text: str) -> str:
        if not text:
            return text
        with self._lock:
            values = sorted(self._values, key=len, reverse=True)
        for value in values:
            if value in text:
                text = text.replace(value, "[REDACTED]")
        for pattern in _PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text


_scrubber = SecretScrubber()


def get_scrubber() -> SecretScrubber:
    return _scrubber


class RedactingFormatter(logging.Formatter):
    """Formats then scrubs every record."""

    def format(self, record: logging.LogRecord) -> str:
        return _scrubber.scrub(super().format(record))


def configure_logging(level: int = logging.INFO) -> None:
    """Install a single redacting handler on the app logger (idempotent)."""
    logger = logging.getLogger("ciphershield")
    logger.setLevel(level)
    if any(isinstance(h.formatter, RedactingFormatter) for h in logger.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
