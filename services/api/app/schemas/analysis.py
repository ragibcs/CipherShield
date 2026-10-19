"""Pydantic schemas for the public API.

Note on preview fields: `value` echoes spans of the *caller's own submitted
text* back to the caller so they can review proposed redactions (MVP
requirement). Vault mappings, keys, and provider credentials are never part
of these schemas.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

__all__ = [
    "AnalyzeRequest",
    "AnalyzeResponse",
    "AuditEventOut",
    "AuditListResponse",
    "ConfigStatusResponse",
    "EvaluationSummaryResponse",
    "FindingOut",
    "PolicyInfo",
    "PreviewRequest",
    "PreviewResponse",
    "ResponseInspectionOut",
    "RestoreRequest",
    "RestoreResponse",
    "VaultRecordOut",
]

# Generous hard backstops; the live limit is settings.max_input_chars (413).
_MAX_TEXT = 1_000_000


class PreviewRequest(BaseModel):
    text: str = Field(min_length=1, max_length=_MAX_TEXT)


class FindingOut(BaseModel):
    category: str
    placeholder: str
    value: str
    start: int
    end: int


class PreviewResponse(BaseModel):
    request_id: str
    counts: dict[str, int]
    findings: list[FindingOut]
    sanitized_text: str
    detector_coverage_note: str


class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=_MAX_TEXT)


class PolicyInfo(BaseModel):
    allowed: bool
    code: str
    reason: str


class ResponseInspectionOut(BaseModel):
    action: Literal["allow", "mask", "block"]
    masked_count: int
    leak_detected: bool
    counts: dict[str, int]


class AnalyzeResponse(BaseModel):
    status: Literal["completed", "blocked"]
    request_id: str
    counts: dict[str, int]
    sanitized_text: str
    policy: PolicyInfo
    provider: str | None = None
    model: str | None = None
    latency_ms: float | None = None
    output: str | None = None
    response_inspection: ResponseInspectionOut | None = None
    outbound_body: str | None = None
    provider_calls: int = 0


class RestoreRequest(BaseModel):
    record_id: str = Field(min_length=1, max_length=128)
    placeholders: list[str] = Field(min_length=1, max_length=500)
    token: str | None = Field(default=None, max_length=512)


class RestoreResponse(BaseModel):
    record_id: str
    values: dict[str, str]


class VaultRecordOut(BaseModel):
    record_id: str
    category: str
    created_at: str
    entry_count: int
    encrypted: bool


class AuditEventOut(BaseModel):
    id: int
    request_id: str
    timestamp: str
    event_type: str
    decision: str
    reason_code: str
    categories: dict[str, int]
    provider: str
    model: str
    latency_ms: float | None
    outcome: str
    event_hash: str


class AuditListResponse(BaseModel):
    events: list[AuditEventOut]
    chain_valid: bool


class ConfigStatusResponse(BaseModel):
    app_env: str
    version: str
    provider: str
    external_enabled: bool
    provider_configured: bool
    external_calls_enabled: bool
    restore_enabled: bool
    detector_categories: list[str]
    max_input_chars: int
    max_output_tokens: int


class EvaluationSummaryResponse(BaseModel):
    status: Literal["ready", "not_generated"]
    generated_at: str | None = None
    source: str | None = None
    metrics: dict[str, float | int | dict[str, float]] = Field(default_factory=dict)
    note: str = ""


class ScenarioMetaOut(BaseModel):
    id: str
    title: str
    description: str
    expected: str
    abuse_case: str


class ScenarioListResponse(BaseModel):
    scenarios: list[ScenarioMetaOut]


class ScenarioRunRequest(BaseModel):
    scenario_id: str = Field(min_length=1, max_length=64)


class ScenarioRunResponse(BaseModel):
    scenario_id: str
    title: str
    expected: str
    actual: str
    passed: bool
    evidence: dict[str, object] = Field(default_factory=dict)
    ran_at: str
