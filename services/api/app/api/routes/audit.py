"""Audit endpoints: sanitized events plus hash-chain verification status."""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from app.api.deps import get_services
from app.schemas import AuditEventOut, AuditListResponse

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("", response_model=AuditListResponse)
def list_audit(request: Request, limit: int = Query(default=50, ge=1, le=500)) -> AuditListResponse:
    services = get_services(request)
    events = services.audit.list_events(limit)
    return AuditListResponse(
        events=[
            AuditEventOut(
                id=event.id,
                request_id=event.request_id,
                timestamp=event.timestamp,
                event_type=event.event_type,
                decision=event.decision,
                reason_code=event.reason_code,
                categories=event.categories,
                provider=event.provider,
                model=event.model,
                latency_ms=event.latency_ms,
                outcome=event.outcome,
                event_hash=event.event_hash,
            )
            for event in events
        ],
        chain_valid=services.audit.verify(),
    )
