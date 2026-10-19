"""Analyze endpoints: preview redaction, then policy-gated provider call.

Pipeline (plan section 4):
validate -> detect -> tokenize -> vault -> serialize -> policy gate ->
provider -> response inspection -> audit.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request

from app.api.deps import get_request_id, get_services, require_size
from app.container import DETECTOR_COVERAGE_NOTE, build_outbound_payload, payload_to_request
from app.core.errors import CipherShieldError
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    FindingOut,
    PolicyInfo,
    PreviewRequest,
    PreviewResponse,
    ResponseInspectionOut,
)
from app.services.audit import AuditEvent

router = APIRouter(prefix="/api/v1/analyze", tags=["analyze"])


@router.post("/preview", response_model=PreviewResponse)
def preview(body: PreviewRequest, request: Request) -> PreviewResponse:
    services = get_services(request)
    require_size(services, body.text)
    request_id = get_request_id(request)

    result = services.tokenizer.tokenize(body.text)
    findings = [
        FindingOut(
            category=token.finding.category,
            placeholder=token.placeholder,
            value=token.finding.value,
            start=token.finding.start,
            end=token.finding.end,
        )
        for token in result.tokens
    ]
    services.audit.append(
        AuditEvent(
            event_type="preview",
            decision="allowed",
            reason_code="ok",
            request_id=request_id,
            categories=result.counts,
            provider="-",
            model="-",
            outcome="preview_generated",
        )
    )
    return PreviewResponse(
        request_id=request_id,
        counts=result.counts,
        findings=findings,
        sanitized_text=result.sanitized_text,
        detector_coverage_note=DETECTOR_COVERAGE_NOTE,
    )


@router.post("", response_model=AnalyzeResponse)
def analyze(body: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    services = get_services(request)
    require_size(services, body.text)
    request_id = get_request_id(request)
    settings = services.settings

    # 1. Detect + tokenize; mapping is sealed in the vault, never returned.
    result = services.tokenizer.tokenize(body.text)
    if result.mapping:
        services.vault.put(request_id, result.mapping, category="mixed")

    # 2. Build the exact outbound payload and gate the serialized form.
    model = settings.llm_model or "mock-echo"
    payload = build_outbound_payload(
        model=model,
        sanitized_text=result.sanitized_text,
        max_tokens=settings.max_output_tokens,
    )
    serialized = json.dumps(payload)
    decision = services.gate.evaluate(
        body=serialized,
        known_secrets=result.mapping,
        external=settings.external_calls_enabled,
    )

    if not decision.allowed:
        services.audit.append(
            AuditEvent(
                event_type="analyze",
                decision="blocked",
                reason_code=decision.code,
                request_id=request_id,
                categories=decision.counts or result.counts,
                provider=services.provider.name,
                model=model,
                outcome="blocked_before_provider",
            )
        )
        return AnalyzeResponse(
            status="blocked",
            request_id=request_id,
            counts=result.counts,
            sanitized_text=result.sanitized_text,
            policy=PolicyInfo(**decision.as_dict()),  # type: ignore[arg-type]
            outbound_body=None,
            provider_calls=services.provider.call_count,
        )

    # 3. Provider call (mock unless external calls are explicitly enabled).
    try:
        response = services.provider.complete(payload_to_request(payload))
    except CipherShieldError as exc:
        services.audit.append(
            AuditEvent(
                event_type="analyze",
                decision="error",
                reason_code=exc.code,
                request_id=request_id,
                categories=result.counts,
                provider=services.provider.name,
                model=model,
                outcome="provider_failure",
            )
        )
        raise

    # 4. Inspect the response for known-secret disclosure (INV-09).
    inspection = services.inspector.inspect(response.text, known_secrets=result.mapping)

    # 5. Secret-free audit event.
    services.audit.append(
        AuditEvent(
            event_type="analyze",
            decision="allowed",
            reason_code="ok",
            request_id=request_id,
            categories=result.counts,
            provider=response.provider,
            model=response.model,
            latency_ms=response.latency_ms,
            outcome="response_masked" if inspection.action != "allow" else "completed",
        )
    )
    return AnalyzeResponse(
        status="completed",
        request_id=request_id,
        counts=result.counts,
        sanitized_text=result.sanitized_text,
        policy=PolicyInfo(**decision.as_dict()),  # type: ignore[arg-type]
        provider=response.provider,
        model=response.model,
        latency_ms=response.latency_ms,
        output=inspection.text,
        response_inspection=ResponseInspectionOut(
            action=inspection.action,  # type: ignore[arg-type]
            masked_count=inspection.masked_count,
            leak_detected=inspection.leak_detected,
            counts=inspection.counts,
        ),
        outbound_body=serialized,
        provider_calls=services.provider.call_count,
    )
