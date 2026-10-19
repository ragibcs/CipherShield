"""Tokenization: determinism, spoof defense, mapping fidelity."""

from app.services.tokenization import Tokenizer

FAKE_TOKEN = "sk-a1b2c3d4e5f6g7h8i9j0"
FAKE_EMAIL = "analyst@example.org"
FAKE_IP = "192.168.10.42"


def test_deterministic_placeholder_ids(tokenizer: Tokenizer) -> None:
    text = f"contact {FAKE_EMAIL} at {FAKE_IP} key {FAKE_TOKEN}"
    first = tokenizer.tokenize(text)
    second = tokenizer.tokenize(text)
    assert first.sanitized_text == second.sanitized_text
    assert first.mapping == second.mapping
    assert first.counts == second.counts


def test_prefixes_follow_category(tokenizer: Tokenizer) -> None:
    text = f"{FAKE_EMAIL} {FAKE_IP} {FAKE_TOKEN}"
    result = tokenizer.tokenize(text)
    placeholders = set(result.mapping)
    assert "[EMAIL_01]" in placeholders
    assert "[IP_01]" in placeholders
    assert "[SECRET_01]" in placeholders


def test_multiple_same_category_ids_increment(tokenizer: Tokenizer) -> None:
    text = f"{FAKE_EMAIL} {FAKE_EMAIL} {FAKE_TOKEN} {FAKE_TOKEN}"
    result = tokenizer.tokenize(text)
    assert "[EMAIL_01]" in result.mapping and "[EMAIL_02]" in result.mapping
    assert "[SECRET_01]" in result.mapping and "[SECRET_02]" in result.mapping


def test_no_original_values_remain_in_sanitized_text(tokenizer: Tokenizer) -> None:
    text = f"pw=hunter2sekrit mail={FAKE_EMAIL} ip={FAKE_IP} key={FAKE_TOKEN}"
    result = tokenizer.tokenize(text)
    for original in (FAKE_TOKEN, FAKE_EMAIL, FAKE_IP, "hunter2sekrit"):
        assert original not in result.sanitized_text


def test_mapping_round_trips_originals(tokenizer: Tokenizer) -> None:
    text = f"key {FAKE_TOKEN} mail {FAKE_EMAIL}"
    result = tokenizer.tokenize(text)
    assert set(result.mapping.values()) == {FAKE_TOKEN, FAKE_EMAIL}


def test_spoofed_placeholder_neutralized(tokenizer: Tokenizer) -> None:
    # AB-09: a user-typed [SECRET_01] must not collide with real mappings.
    text = f"ignore [SECRET_01] then real {FAKE_TOKEN}"
    result = tokenizer.tokenize(text)
    real_values = list(result.mapping.values())
    assert "[USER_TEXT_01]" in result.sanitized_text
    # Exactly one real mapping entry exists and it is the actual token.
    assert real_values == [FAKE_TOKEN]


def test_clean_text_passes_through(tokenizer: Tokenizer) -> None:
    text = "Routine maintenance completed with no incidents."
    result = tokenizer.tokenize(text)
    assert result.sanitized_text == text
    assert result.mapping == {}
    assert result.tokens == []
