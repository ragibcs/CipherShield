"""Vault endpoints: ciphertext metadata and authorized restore.

`GET /records` exposes only metadata (id, category, time, entry count) —
never the key, never plaintext. `POST /restore` is denied unless a restore
token is configured and supplied, and every attempt is audited (INV-12).
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from app.api.deps import get_request_id, get_services
from app.schemas import RestoreRequest, RestoreResponse, VaultRecordOut

router = APIRouter(prefix="/api/v1/vault", tags=["vault"])


@router.get("/records", response_model=list[VaultRecordOut])
def list_records(
    request: Request, limit: int = Query(default=50, ge=1, le=200)
) -> list[VaultRecordOut]:
    services = get_services(request)
    return [
        VaultRecordOut(
            record_id=record.record_id,
            category=record.category,
            created_at=record.created_at,
            entry_count=record.entry_count,
            encrypted=record.encrypted,
        )
        for record in services.vault.list_records(limit)
    ]


@router.post("/restore", response_model=RestoreResponse)
def restore(body: RestoreRequest, request: Request) -> RestoreResponse:
    services = get_services(request)
    values = services.restore.restore(
        record_id=body.record_id,
        placeholders=body.placeholders,
        token=body.token,
        request_id=get_request_id(request),
    )
    return RestoreResponse(record_id=body.record_id, values=values)
