"""Security Lab: every scenario runs against real components and must pass."""

from __future__ import annotations

import json

from conftest import TEST_KEY

from app.container import Services, build_services
from app.core.config import Settings
from app.main import create_app
from app.services.lab import SCENARIOS, run_scenario, scenario_metadata
from app.services.providers import MockProvider
from app.services.vault import StaticKeyProvider


def _services(tmp_path) -> Services:
    settings = Settings(
        app_env="development",
        database_url=f"sqlite:///{tmp_path / 'lab.db'}",
        ciphershield_key_file=str(tmp_path / "master.key"),
        llm_api_key="sk-lab-config-fake-0123456789abcdef",
    )
    return build_services(
        settings, key_provider=StaticKeyProvider(TEST_KEY), provider=MockProvider()
    )


def test_all_scenarios_defined() -> None:
    ids = [s.id for s in SCENARIOS]
    assert ids == [
        "secret_in_prompt",
        "prompt_injection",
        "forbidden_field",
        "tampered_ciphertext",
        "unauthorized_tool",
        "malicious_model_output",
    ]
    assert len(scenario_metadata()) == len(SCENARIOS)


def test_every_scenario_passes(tmp_path) -> None:
    services = _services(tmp_path)
    for scenario in SCENARIOS:
        result = run_scenario(services, scenario.id)
        assert result is not None, scenario.id
        assert result.passed, f"{scenario.id} failed: {result.actual}"
        assert result.expected and result.actual and result.ran_at
        # Evidence must stay sanitized.
        assert "sk-lab-fake-1234567890abcdef" not in json.dumps(result.evidence)
    services.close()


def test_unknown_scenario_returns_none(tmp_path) -> None:
    services = _services(tmp_path)
    assert run_scenario(services, "does_not_exist") is None
    services.close()


def test_lab_endpoints(tmp_path) -> None:
    from fastapi.testclient import TestClient

    services = _services(tmp_path)
    app = create_app(settings=services.settings, services=services)
    with TestClient(app, raise_server_exceptions=False) as client:
        listing = client.get("/api/v1/lab/scenarios")
        assert listing.status_code == 200
        assert len(listing.json()["scenarios"]) == len(SCENARIOS)

        response = client.post("/api/v1/lab/run", json={"scenario_id": "tampered_ciphertext"})
        assert response.status_code == 200
        data = response.json()
        assert data["passed"] is True
        assert "rejected" in data["actual"]

        unknown = client.post("/api/v1/lab/run", json={"scenario_id": "nope"})
        assert unknown.status_code == 404

        # Runs are audited, secret-free.
        events = client.get("/api/v1/audit").json()["events"]
        lab_events = [e for e in events if e["event_type"] == "lab_run"]
        assert lab_events and lab_events[0]["decision"] == "passed"
        assert "sk-lab-fake" not in json.dumps(events)
    services.close()
