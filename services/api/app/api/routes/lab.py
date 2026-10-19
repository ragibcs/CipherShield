"""Security Lab endpoints: list scenarios and run them against real components."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.api.deps import get_request_id, get_services
from app.schemas import (
    ScenarioListResponse,
    ScenarioMetaOut,
    ScenarioRunRequest,
    ScenarioRunResponse,
)
from app.services.audit import AuditEvent
from app.services.lab import run_scenario, scenario_metadata

router = APIRouter(prefix="/api/v1/lab", tags=["lab"])


@router.get("/scenarios", response_model=ScenarioListResponse)
def list_scenarios() -> ScenarioListResponse:
    return ScenarioListResponse(scenarios=[ScenarioMetaOut(**meta) for meta in scenario_metadata()])


@router.post("/run", response_model=ScenarioRunResponse)
def run(body: ScenarioRunRequest, request: Request) -> ScenarioRunResponse:
    services = get_services(request)
    request_id = get_request_id(request)
    result = run_scenario(services, body.scenario_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "unknown_scenario", "message": "Unknown scenario."},
        )
    services.audit.append(
        AuditEvent(
            event_type="lab_run",
            decision="passed" if result.passed else "failed",
            reason_code=result.scenario_id,
            request_id=request_id,
            provider="-",
            model="-",
            outcome=result.scenario_id,
        )
    )
    return ScenarioRunResponse(
        scenario_id=result.scenario_id,
        title=result.title,
        expected=result.expected,
        actual=result.actual,
        passed=result.passed,
        evidence=result.evidence,
        ran_at=result.ran_at,
    )
