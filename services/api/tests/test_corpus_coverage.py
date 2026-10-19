"""Corpus integrity: declared secrets must be detectable by the default stack.

This is the regression guard for the evaluation's leakage metric - if a
corpus secret ever stops matching a detector, this test fails before any
report is generated.
"""

from __future__ import annotations

import sys
from pathlib import Path

from app.services.detection import SecretScanner
from app.services.tokenization import Tokenizer

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import generate_demo_data  # noqa: E402


def test_corpus_structure() -> None:
    corpus = generate_demo_data.build_corpus()
    documents = corpus["documents"]
    kinds = {document["kind"] for document in documents}
    assert kinds == {"benign", "secret", "attack"}
    ids = [document["id"] for document in documents]
    assert len(ids) == len(set(ids)), "corpus ids must be unique"
    assert "synthetic" in corpus["note"].lower()


def test_every_declared_secret_is_detected_and_redacted() -> None:
    tokenizer = Tokenizer(SecretScanner())
    corpus = generate_demo_data.build_corpus()
    for document in corpus["documents"]:
        if document["kind"] != "secret":
            continue
        result = tokenizer.tokenize(document["text"])
        redacted_values = set(result.mapping.values())
        for secret in document["known_secrets"]:
            assert secret in document["text"], document["id"]
            assert secret in redacted_values, (
                f"{document['id']}: detector missed declared secret "
                f"(evaluation would report leakage)"
            )
            assert secret not in result.sanitized_text, document["id"]


def test_benign_values_are_not_redacted() -> None:
    tokenizer = Tokenizer(SecretScanner())
    corpus = generate_demo_data.build_corpus()
    for document in corpus["documents"]:
        if document["kind"] != "benign":
            continue
        result = tokenizer.tokenize(document["text"])
        for value in document.get("benign_values", []):
            assert value in result.sanitized_text, (
                f"{document['id']}: benign value '{value}' was redacted (false positive)"
            )


def test_attack_documents_have_success_conditions() -> None:
    corpus = generate_demo_data.build_corpus()
    attacks = [d for d in corpus["documents"] if d["kind"] == "attack"]
    assert len(attacks) >= 5
    for document in attacks:
        assert document.get("attack"), document["id"]
        assert document.get("success_condition"), document["id"]
