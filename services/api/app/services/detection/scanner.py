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
    """Remove whitespace while recording original offsets (AB-07 support)."""
    chars: list[str] = []
    index_map: list[int] = []
    for index, char in enumerate(text):
        if not char.isspace():
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
        ordered = _resolve_overlaps(raw)
        counts: dict[str, int] = {}
        for finding in ordered:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return ScanResult(findings=tuple(ordered), counts=counts)

    @staticmethod
    def _scan_compact(detector: BaseDetector, text: str) -> list[Finding]:
        compact, index_map = compact_with_map(text)
        if len(compact) == len(text):  # no whitespace: already scanned
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
# covers it fully AND extends the redacted span meaningfully; otherwise the
# exact (precision-safe) match wins.
SPLIT_MIN_GAIN = 8
_SPLIT_SUFFIX = "_split"


def _greedy(findings: list[Finding]) -> list[Finding]:
    kept: list[Finding] = []
    last_end = -1
    for finding in sorted(findings, key=lambda f: (f.start, -(f.end - f.start), f.detector)):
        if finding.start >= last_end:
            kept.append(finding)
            last_end = finding.end
    return kept


def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Resolve overlaps so no two findings share a character.

    Exact (raw) findings take priority over whitespace-compacted (`*_split`)
    findings at the same position, because compaction can greedily swallow the
    following word. A split finding still wins when it fully covers an exact
    match and extends it by `SPLIT_MIN_GAIN`+ characters — that is the genuine
    split-secret case (AB-07), where leaving the tail would leak part of it.
    """
    exact = [f for f in findings if not f.detector.endswith(_SPLIT_SUFFIX)]
    split = [f for f in findings if f.detector.endswith(_SPLIT_SUFFIX)]

    kept = _greedy(exact)
    for candidate in sorted(split, key=lambda f: (f.start, -(f.end - f.start))):
        conflicts = [k for k in kept if k.start < candidate.end and candidate.start < k.end]
        if not conflicts:
            kept.append(candidate)
            continue
        covers = all(candidate.start <= k.start and candidate.end >= k.end for k in conflicts)
        gain = max(candidate.end - k.end for k in conflicts)
        if covers and gain >= SPLIT_MIN_GAIN:
            kept = [k for k in kept if k not in conflicts]
            kept.append(candidate)
    return sorted(kept, key=lambda f: (f.start, -(f.end - f.start)))


_PLACEHOLDER_TOKEN = re.compile(r"\[(?:SECRET|EMAIL|IP|USER_TEXT)_\d+\]")


def find_placeholder_lookalikes(text: str) -> list[tuple[int, int]]:
    """Locate user-typed placeholder-looking tokens (AB-09 spoof defense)."""
    return [(m.start(), m.end()) for m in _PLACEHOLDER_TOKEN.finditer(text)]
