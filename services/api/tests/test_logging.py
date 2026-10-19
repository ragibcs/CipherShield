"""Log hygiene: registered values and credential shapes never reach a log line."""

from __future__ import annotations

import logging

from app.core.logging import RedactingFormatter, SecretScrubber

SECRET = "sk-log-fake-1234567890abcdef"


def test_registered_values_are_scrubbed() -> None:
    scrubber = SecretScrubber()
    scrubber.register(SECRET)
    line = scrubber.scrub(f"failed while sending {SECRET} to provider")
    assert SECRET not in line
    assert "[REDACTED]" in line


def test_credential_shapes_scrubbed_without_registration() -> None:
    scrubber = SecretScrubber()
    line = scrubber.scrub("auth header Bearer abc123def456ghi789 and password=hunter2sekrit")
    assert "abc123def456ghi789" not in line
    assert "hunter2sekrit" not in line


def test_short_values_are_not_registered() -> None:
    scrubber = SecretScrubber()
    scrubber.register("abc")  # too short: would cause false redactions
    assert "abc" in scrubber.scrub("abc def")


def test_formatter_redacts_log_records() -> None:
    formatter = RedactingFormatter("%(message)s")
    record = logging.LogRecord(
        name="ciphershield",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="key=%s",
        args=(SECRET,),
        exc_info=None,
    )
    rendered = formatter.format(record)
    assert SECRET not in rendered
