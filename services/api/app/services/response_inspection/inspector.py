"""Response inspection: mask known-secret disclosure before it reaches a user.

INV-09: model output is scanned for this request's original secret values and
for any configured detector patterns. Matches are masked; if a known original
somehow survives masking (paranoia path), the whole response is blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.services.detection.scanner import SecretScanner

__all__ = ["InspectionResult", "ResponseInspector"]

_BLOCKED_TEXT = (
    "[BLOCKED] The provider response was withheld because it appeared to "
    "disclose sensitive material."
)


@dataclass(frozen=True, slots=True)
class InspectionResult:
    action: str  # "allow" | "mask" | "block"
    text: str
    leak_detected: bool
    masked_count: int
    counts: dict[str, int] = field(default_factory=dict)


class ResponseInspector:
    def __init__(self, scanner: SecretScanner | None = None) -> None:
        self.scanner = scanner if scanner is not None else SecretScanner()

    def inspect(self, text: str, known_secrets: dict[str, str] | None = None) -> InspectionResult:
        known = [value for value in (known_secrets or {}).values() if value]
        out = text
        masked = 0
        leak = False

        # 1. Exact originals first (highest severity).
        for secret in known:
            occurrences = out.count(secret)
            if occurrences:
                out = out.replace(secret, "[REDACTED_SECRET]")
                masked += occurrences
                leak = True

        # 2. Any detector-visible sensitive value in the output.
        scan = self.scanner.scan(out)
        counts = dict(scan.counts)
        for finding in scan.findings:
            occurrences = out.count(finding.value)
            if occurrences:
                out = out.replace(finding.value, f"[REDACTED_{finding.category.upper()}]")
                masked += occurrences

        # 3. Verification pass: fail closed if anything known still remains.
        for secret in known:
            if secret in out:
                return InspectionResult(
                    action="block",
                    text=_BLOCKED_TEXT,
                    leak_detected=True,
                    masked_count=masked,
                    counts=counts,
                )

        residual = self.scanner.scan(out)
        if residual.findings:
            for finding in residual.findings:
                occurrences = out.count(finding.value)
                if occurrences:
                    out = out.replace(finding.value, f"[REDACTED_{finding.category.upper()}]")
                    masked += occurrences
            if self.scanner.scan(out).findings:
                return InspectionResult(
                    action="block",
                    text=_BLOCKED_TEXT,
                    leak_detected=True,
                    masked_count=masked,
                    counts=counts,
                )

        return InspectionResult(
            action="mask" if masked else "allow",
            text=out,
            leak_detected=leak,
            masked_count=masked,
            counts=counts,
        )
