"""Response inspection (INV-09): mask or block known-secret disclosure."""

from __future__ import annotations

from app.services.detection import SecretScanner
from app.services.detection.base import BaseDetector, Finding
from app.services.response_inspection import ResponseInspector

SECRET = "sk-response-fake-1234567890abcdef"


def test_known_secret_in_response_masked() -> None:
    inspector = ResponseInspector()
    result = inspector.inspect(
        f"Sure! The key was {SECRET} as requested.",
        known_secrets={"[SECRET_01]": SECRET},
    )
    assert SECRET not in result.text
    assert "[REDACTED_SECRET]" in result.text
    assert result.leak_detected is True
    assert result.action == "mask"
    assert result.masked_count == 1


def test_detector_visible_secret_in_response_masked() -> None:
    inspector = ResponseInspector()
    # Not in this request's mapping, but pattern-visible (e.g. a sibling secret).
    result = inspector.inspect(f"leaked credential: {SECRET}")
    assert SECRET not in result.text
    assert "[REDACTED_API_TOKEN]" in result.text
    assert result.action == "mask"


def test_clean_response_allowed_unchanged() -> None:
    inspector = ResponseInspector()
    text = "Risk summary: rotate credentials referenced by [SECRET_01] and review host logs."
    result = inspector.inspect(text, known_secrets={"[SECRET_01]": SECRET})
    assert result.action == "allow"
    assert result.text == text
    assert result.leak_detected is False
    assert result.masked_count == 0


def test_multiple_occurrences_all_masked() -> None:
    inspector = ResponseInspector()
    result = inspector.inspect(
        f"{SECRET} again {SECRET} done",
        known_secrets={"[SECRET_01]": SECRET},
    )
    assert SECRET not in result.text
    assert result.masked_count >= 2


class _UnmaskableDetector(BaseDetector):
    """Pathological detector whose finding can never be replaced (paranoia path)."""

    name = "unmaskable"
    category = "api_token"
    pattern = __import__("re").compile(r"IMPOSSIBLE_MATCH_XYZ")

    def find(self, text: str) -> list[Finding]:
        return [Finding(category=self.category, detector=self.name, value="GHOST", start=0, end=1)]


def test_fail_closed_block_when_masking_cannot_remove_finding() -> None:
    inspector = ResponseInspector(SecretScanner([_UnmaskableDetector()]))
    result = inspector.inspect("harmless looking output")
    assert result.action == "block"
    assert result.leak_detected is True
    assert "[BLOCKED]" in result.text
