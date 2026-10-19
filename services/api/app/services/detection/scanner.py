"""Scanner: runs detectors, resolves overlaps, tolerates split secrets."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.detection.base import BaseDetector, Finding
from app.services.detection.patterns import default_detectors

__all__ = ["ScanResult", "SecretScanner", "compact_with_map"]


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[Finding, ...]
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return len(self.findings)


def compact_with_map(text: str) -> tuple[str, list[int]]:
    """Collapse whitespace runs into a single `-`, recording original offsets.

    The joiner is chosen deliberately:
    - it is a word-boundary character for `\\b` (unlike a plain deletion,
      which glues `credential` to `sk-...` and silently defeats the pattern),
    - it is inside the token character classes, so a secret split across
      whitespace rejoins into one match (AB-07).

    Each output character maps back to one original offset.
    """
    chars: list[str] = []
    index_map: list[int] = []
    in_whitespace = False
    for index, char in enumerate(text):
        if char.isspace():
            if in_whitespace:
                continue
            in_whitespace = True
            chars.append("-")
            index_map.append(index)
        else:
            in_whitespace = False
            chars.append(char)
            index_map.append(index)
    return "".join(chars), index_map


class SecretScanner:
    """Aggregates detectors into an ordered, overlap-free finding list."""

    def __init__(self, detectors: list[BaseDetector] | None = None) -> None:
        self.detectors: list[BaseDetector] = (
            detectors if detectors is not None else default_detectors()
        )

    def scan(self, text: str) -> ScanResult:
        raw: list[Finding] = []
        for detector in self.detectors:
            raw.extend(detector.find(text))
            if detector.scan_compact and text:
                raw.extend(self._scan_compact(detector, text))
        ordered = _resolve_overlaps(raw, text)
        counts: dict[str, int] = {}
        for finding in ordered:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return ScanResult(findings=tuple(ordered), counts=counts)

    @staticmethod
    def _scan_compact(detector: BaseDetector, text: str) -> list[Finding]:
        compact, index_map = compact_with_map(text)
        if compact == text:  # no whitespace present: raw scan already covered it
            return []
        findings: list[Finding] = []
        for finding in detector.find(compact):
            start = index_map[finding.start]
            end = index_map[finding.end - 1] + 1
            if end <= start:
                continue
            value = text[start:end]
            if not value.strip():
                continue
            findings.append(
                Finding(
                    category=finding.category,
                    detector=finding.detector + "_split",
                    value=value,
                    start=start,
                    end=end,
                )
            )
        return findings


# A whitespace-compacted finding may only replace an exact finding when it
# covers it fully, crosses at most ONE whitespace run (a genuine split point -
# more runs mean distinct words were glued together), and extends the redacted
# span meaningfully.
SPLIT_MIN_GAIN = 8
SPLIT_SUFFIX = "_split"
_WHITESPACE_RUN = re.compile(r"\s+")


def _greedy(findings: list[Finding]) -> list[Finding]:
    kept: list[Finding] = []
    last_end = -1
    for finding in sorted(findings, key=lambda f: (f.start, -(f.end - f.start), f.detector)):
        if finding.start >= last_end:
            kept.append(finding)
            last_end = finding.end
    return kept


def _resolve_overlaps(findings: list[Finding], text: str) -> list[Finding]:
    """Resolve overlaps so no two findings share a character.

    Exact (raw) findings take priority over whitespace-compacted (`*_split`)
    findings at the same position, because compaction can greedily glue
    distinct words or separate secrets together. A split finding wins only
    when ALL of the following hold:

    1. it fully covers exactly ONE conflicting exact finding - two complete
       secrets side by side must stay separate (a merge would silently drop
       one),
    2. its span crosses at most ONE whitespace run - a genuine split point;
       more runs mean we glued distinct words (precision over recall), and
    3. it extends the exact match by `SPLIT_MIN_GAIN`+ characters - a real
       secret tail, not a stray neighboring word (AB-07).
    """
    exact = [f for f in findings if not f.detector.endswith(SPLIT_SUFFIX)]
    split = [f for f in findings if f.detector.endswith(SPLIT_SUFFIX)]

    kept = _greedy(exact)
    for candidate in sorted(split, key=lambda f: (f.start, -(f.end - f.start))):
        conflicts = [k for k in kept if k.start < candidate.end and candidate.start < k.end]
        if not conflicts:
            kept.append(candidate)
            continue
        covers = all(candidate.start <= k.start and candidate.end >= k.end for k in conflicts)
        gain = max(candidate.end - k.end for k in conflicts)
        runs = len(_WHITESPACE_RUN.findall(text[candidate.start : candidate.end]))
        if covers and len(conflicts) == 1 and runs <= 1 and gain >= SPLIT_MIN_GAIN:
            kept = [k for k in kept if k not in conflicts]
            kept.append(candidate)
    return sorted(kept, key=lambda f: (f.start, -(f.end - f.start)))


_PLACEHOLDER_TOKEN = re.compile(r"\[(?:SECRET|EMAIL|IP|USER_TEXT)_\d+\]")


def find_placeholder_lookalikes(text: str) -> list[tuple[int, int]]:
    """Locate user-typed placeholder-looking tokens (AB-09 spoof defense)."""
    return [(m.start(), m.end()) for m in _PLACEHOLDER_TOKEN.finditer(text)]
