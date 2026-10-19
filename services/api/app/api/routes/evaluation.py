"""Evaluation summary endpoint.

Serves *only* the file produced by `scripts/run_security_eval.py`. If no run
exists, the endpoint says so — numbers are never fabricated (plan section 9).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, Request

from app.schemas import EvaluationSummaryResponse

router = APIRouter(prefix="/api/v1/evaluation", tags=["evaluation"])

_CANDIDATES = (
    "eval/results/summary.json",
    "../../eval/results/summary.json",
    "../eval/results/summary.json",
)

_NOTE_MISSING = (
    "No evaluation run found. Run `python scripts/run_security_eval.py` to "
    "generate metrics from real test results."
)


def _find_summary() -> Path | None:
    override = os.environ.get("EVAL_SUMMARY_PATH", "").strip()
    if override:
        path = Path(override)
        return path if path.is_file() else None
    for candidate in _CANDIDATES:
        path = Path(candidate)
        if path.is_file():
            return path
    return None


@router.get("/summary", response_model=EvaluationSummaryResponse)
def evaluation_summary(request: Request) -> EvaluationSummaryResponse:
    # `request` keeps the route consistent with the dependency style used
    # elsewhere; no service state is required to serve a file-backed report.
    del request
    path = _find_summary()
    if path is None:
        return EvaluationSummaryResponse(status="not_generated", note=_NOTE_MISSING)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return EvaluationSummaryResponse(
            status="not_generated",
            note="Evaluation file exists but could not be read safely.",
        )
    if not isinstance(data, dict):
        return EvaluationSummaryResponse(
            status="not_generated",
            note="Evaluation file has an unexpected shape.",
        )
    metrics = data.get("metrics")
    return EvaluationSummaryResponse(
        status="ready",
        generated_at=str(data.get("generated_at") or "") or None,
        source=str(data.get("source") or "") or None,
        metrics=metrics if isinstance(metrics, dict) else {},
        note=str(data.get("note") or "Measured output from a recorded evaluation run."),
    )
