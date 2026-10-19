"""Detector behavior: categories, overlaps, split secrets, false-positive guards."""

from app.services.detection import SecretScanner
from app.services.detection.base import (
    CATEGORY_API_TOKEN,
    CATEGORY_BEARER_TOKEN,
    CATEGORY_EMAIL,
    CATEGORY_IPV4,
    CATEGORY_PASSWORD,
)
from app.services.detection.patterns import default_detectors

FAKE_TOKEN = "sk-a1b2c3d4e5f6g7h8i9j0"
FAKE_GITHUB = "ghp_abcdef0123456789abcdef0123456789abcdef"
FAKE_PASSWORD = "hunter2sekrit"
FAKE_EMAIL = "analyst@example.org"
FAKE_IP = "192.168.10.42"


def _categories(scanner: SecretScanner, text: str) -> set[str]:
    return {f.category for f in scanner.scan(text).findings}


def test_detects_api_tokens(scanner: SecretScanner) -> None:
    findings = scanner.scan(f"key={FAKE_TOKEN} alt={FAKE_GITHUB}").findings
    assert {f.category for f in findings} == {CATEGORY_API_TOKEN}
    assert FAKE_TOKEN in {f.value for f in findings}
    assert FAKE_GITHUB in {f.value for f in findings}


def test_detects_bearer_token_value_only(scanner: SecretScanner) -> None:
    # A JWT-shaped bearer value: no other detector competes for this span.
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcd1234efgh"
    text = f"Authorization: Bearer {token}"
    findings = scanner.scan(text).findings
    assert findings and findings[0].category == CATEGORY_BEARER_TOKEN
    assert findings[0].value == token  # scheme keyword kept, value redacted
    assert token not in text.replace(findings[0].value, "")  # span sanity


def test_detects_password_key_value(scanner: SecretScanner) -> None:
    for text in (f"password={FAKE_PASSWORD}", f'password: "{FAKE_PASSWORD}"'):
        findings = scanner.scan(text).findings
        assert findings, text
        assert findings[0].category == CATEGORY_PASSWORD
        assert findings[0].value == FAKE_PASSWORD


def test_detects_email_and_ipv4(scanner: SecretScanner) -> None:
    cats = _categories(scanner, f"owner {FAKE_EMAIL} from {FAKE_IP}")
    assert cats == {CATEGORY_EMAIL, CATEGORY_IPV4}


def test_invalid_ipv4_ignored(scanner: SecretScanner) -> None:
    assert scanner.scan("bad 999.10.1.1 and 1.2.3").findings == ()


def test_multiple_secrets_same_category_get_distinct_findings(scanner: SecretScanner) -> None:
    text = f"{FAKE_EMAIL} cc {FAKE_EMAIL} also other.person@example.com"
    emails = [f for f in scanner.scan(text).findings if f.category == CATEGORY_EMAIL]
    assert len(emails) == 3
    assert len({f.start for f in emails}) == 3


def test_overlap_resolution_no_shared_characters(scanner: SecretScanner) -> None:
    # Bearer value is also an sk- token: only the longer/earlier span survives.
    text = f"Bearer {FAKE_TOKEN}"
    findings = scanner.scan(text).findings
    spans = [(f.start, f.end) for f in findings]
    for i, (s1, e1) in enumerate(spans):
        for s2, e2 in spans[i + 1 :]:
            assert e1 <= s2 or e2 <= s1, "overlapping findings survived"


def test_secret_split_across_whitespace_is_detected(scanner: SecretScanner) -> None:
    # AB-07: token broken across a line wrap must still be caught.
    split = FAKE_TOKEN[:12] + "\n  " + FAKE_TOKEN[12:]
    findings = scanner.scan(f"leaked:\n{split}").findings
    assert any(f.category == CATEGORY_API_TOKEN for f in findings)


def test_benign_text_has_no_findings(scanner: SecretScanner) -> None:
    text = "The service restarted twice at 14:02 and the deploy finished cleanly."
    assert scanner.scan(text).findings == ()


def test_detector_set_is_modular() -> None:
    detectors = default_detectors()
    assert len(detectors) >= 5
    assert all(hasattr(d, "category") for d in detectors)
