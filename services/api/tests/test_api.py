"""Integration tests: preview -> tokenization -> policy -> provider -> scan.

Run entirely offline (sockets blocked by conftest) with the mock provider.
"""

from __future__ import annotations

import json

import pytest
from conftest import TEST_KEY
from fastapi.testclient import TestClient

from app.container import Services, build_services
from app.core.config import Settings
from app.main import create_app
from app.services.detection import SecretScanner
from app.services.detection.patterns import ApiTokenDetector
from app.services.providers import MockProvider, OpenAICompatibleProvider
from app.services.tokenization import Tokenizer
from app.services.vault import StaticKeyProvider

FAKE_TOKEN = "sk-api-fake-1234567890abcdef"
FAKE_EMAIL = "oncall@example.org"
FAKE_IP = "10.20.30.40"
API_KEY = "sk-configured-fake-0987654321abcd"

INCIDENT = (
    f"Incident INC-42: auth failures from {FAKE_IP}. "
    f"Service account key {FAKE_TOKEN} was in the ticket. "
    f"Owner: {FAKE_EMAIL}."
)


def make_settings(tmp_path, **overrides) -> Settings:
    base: dict[str, object] = {
        "app_env": "development",
        "database_url": f"sqlite:///{tmp_path / 'api.db'}",
        "ciphershield_key_file": str(tmp_path / "master.key"),
        "allow_external_llm": False,
        "rate_limit_per_minute": 1000,
    }
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def services(tmp_path) -> Services:
    return build_services(
        make_settings(tmp_path),
        key_provider=StaticKeyProvider(TEST_KEY),
        provider=MockProvider(),
    )


@pytest.fixture
def client(services: Services):  # type: ignore[no-untyped-def]
    app = create_app(settings=services.settings, services=services)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    services.close()


def test_health_and_status_leak_nothing(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}
    status = client.get("/api/v1/config/status")
    assert status.status_code == 200
    body = status.text
    assert API_KEY not in body
    assert "master.key" not in body
    assert "sqlite" not in body
    data = status.json()
    assert data["external_enabled"] is False
    assert data["provider"] == "mock"


def test_preview_reports_findings_and_sanitized_text(client: TestClient) -> None:
    response = client.post("/api/v1/analyze/preview", json={"text": INCIDENT})
    assert response.status_code == 200
    data = response.json()
    categories = {f["category"] for f in data["findings"]}
    assert {"api_token", "email", "ipv4"} <= categories
    assert FAKE_TOKEN not in data["sanitized_text"]
    assert FAKE_EMAIL not in data["sanitized_text"]
    assert "[SECRET_01]" in data["sanitized_text"]
    assert "[EMAIL_01]" in data["sanitized_text"]
    assert "[IP_01]" in data["sanitized_text"]
    assert data["request_id"].startswith("req_")
    assert "incomplete" in data["detector_coverage_note"].lower()


def test_preview_is_audited_without_content(client: TestClient) -> None:
    client.post("/api/v1/analyze/preview", json={"text": INCIDENT})
    events = client.get("/api/v1/audit").json()["events"]
    preview_events = [e for e in events if e["event_type"] == "preview"]
    assert preview_events
    assert FAKE_TOKEN not in json.dumps(events)


def test_analyze_completes_via_mock_with_sanitized_outbound(
    client: TestClient, services: Services
) -> None:
    response = client.post("/api/v1/analyze", json={"text": INCIDENT})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["provider"] == "mock"
    assert data["policy"]["allowed"] is True

    # INV-01/INV-03: outbound body carries placeholders only.
    outbound = data["outbound_body"]
    assert FAKE_TOKEN not in outbound
    assert FAKE_EMAIL not in outbound
    assert "[SECRET_01]" in outbound
    assert API_KEY not in outbound

    # Response inspection ran; output exists and stays sanitized.
    assert data["output"]
    assert FAKE_TOKEN not in data["output"]
    assert data["response_inspection"]["action"] in {"allow", "mask"}
    assert data["provider_calls"] == 1

    # Mapping is sealed server-side: restore works, but the analyze response
    # never contains the mapping itself.
    assert services.vault.get(data["request_id"]) == {
        "[SECRET_01]": FAKE_TOKEN,
        "[EMAIL_01]": FAKE_EMAIL,
        "[IP_01]": FAKE_IP,
    }
    assert FAKE_TOKEN not in response.text


def test_analyze_blocked_when_forbidden_value_remains(tmp_path) -> None:
    """INV-04: a forbidden residue blocks the send; provider count stays 0."""
    settings = make_settings(tmp_path)
    provider = MockProvider()
    services = build_services(settings, key_provider=StaticKeyProvider(TEST_KEY), provider=provider)
    # Simulate a tokenizer narrower than policy (defense-in-depth scenario):
    # only api tokens get redacted, but policy denies every raw category.
    services.tokenizer = Tokenizer(SecretScanner([ApiTokenDetector()]))
    app = create_app(settings=settings, services=services)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/api/v1/analyze", json={"text": INCIDENT})
    data = response.json()
    assert data["status"] == "blocked"
    assert data["policy"]["allowed"] is False
    assert data["outbound_body"] is None
    assert provider.call_count == 0  # no provider request occurred
    assert data["provider_calls"] == 0
    services.close()


def test_analyze_rejects_oversized_input(client: TestClient, services: Services) -> None:
    huge = "x" * (services.settings.max_input_chars + 1)
    response = client.post("/api/v1/analyze", json={"text": huge})
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_blocked_request_is_audited_without_raw_text(
    client: TestClient, services: Services
) -> None:
    services.tokenizer = Tokenizer(SecretScanner([ApiTokenDetector()]))
    client.post("/api/v1/analyze", json={"text": INCIDENT})
    events = client.get("/api/v1/audit").json()["events"]
    blocked = [e for e in events if e["decision"] == "blocked"]
    assert blocked and blocked[0]["outcome"] == "blocked_before_provider"
    assert FAKE_TOKEN not in json.dumps(events)


def test_restore_flow_end_to_end(client: TestClient, services: Services) -> None:
    request_id = "req_restore_e2e"
    analyzed = client.post(
        "/api/v1/analyze",
        json={"text": INCIDENT},
        headers={"X-Request-ID": request_id},
    )
    assert analyzed.status_code == 200
    record_id = analyzed.json()["request_id"]
    assert record_id == request_id

    # Restore is disabled without a configured token (INV-12).
    denied = client.post(
        "/api/v1/vault/restore",
        json={"record_id": record_id, "placeholders": ["[SECRET_01]"], "token": "x"},
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "restore_not_authorized"

    records = client.get("/api/v1/vault/records").json()
    assert records[0]["record_id"] == request_id
    assert records[0]["encrypted"] is True
    assert FAKE_TOKEN not in json.dumps(records)


def test_no_key_in_any_endpoint_response(tmp_path) -> None:
    settings = make_settings(
        tmp_path,
        llm_api_key=API_KEY,
        llm_base_url="https://api.openai.com/v1",
        llm_model="gpt-4o-mini",
        allow_external_llm=True,
    )
    services = build_services(
        settings, key_provider=StaticKeyProvider(TEST_KEY), provider=MockProvider()
    )
    app = create_app(settings=settings, services=services)
    with TestClient(app, raise_server_exceptions=False) as client:
        responses = [
            client.get("/health"),
            client.get("/api/v1/config/status"),
            client.get("/api/v1/audit"),
            client.get("/api/v1/vault/records"),
            client.get("/api/v1/evaluation/summary"),
            client.post("/api/v1/analyze/preview", json={"text": INCIDENT}),
        ]
    for response in responses:
        assert API_KEY not in response.text, response.request.url
    services.close()


def test_validation_errors_do_not_echo_input(client: TestClient) -> None:
    response = client.post(
        "/api/v1/vault/restore",
        json={
            "record_id": "r1",
            "placeholders": ["[SECRET_01]"],
            "token": {"leak": "password=hunter2sekrit"},
        },
    )
    assert response.status_code == 422
    body = response.text
    assert "hunter2sekrit" not in body
    assert response.json()["error"]["message"] == "Request validation failed."


def test_evaluation_summary_reports_missing_run(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVAL_SUMMARY_PATH", str(tmp_path / "missing-summary.json"))
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'eval.db'}",
        ciphershield_key_file=str(tmp_path / "master.key"),
    )
    app = create_app(settings=settings)
    with TestClient(app, raise_server_exceptions=False) as client:
        data = client.get("/api/v1/evaluation/summary").json()
    assert data["status"] == "not_generated"
    assert "run_security_eval" in data["note"]


def test_rate_limit_blocks_floods(tmp_path) -> None:
    settings = make_settings(tmp_path, rate_limit_per_minute=3)
    services = build_services(
        settings, key_provider=StaticKeyProvider(TEST_KEY), provider=MockProvider()
    )
    app = create_app(settings=settings, services=services)
    with TestClient(app, raise_server_exceptions=False) as client:
        codes = [
            client.post("/api/v1/analyze/preview", json={"text": "benign"}).status_code
            for _ in range(5)
        ]
    assert codes[:3] == [200, 200, 200]
    assert 429 in codes[3:]
    services.close()


def test_malicious_provider_response_is_masked_before_ui(tmp_path) -> None:
    """B5/INV-09 (integration): a provider that repeats a known original
    secret gets masked by response inspection before it reaches the client."""
    from app.services.providers.base import ProviderResponse

    class _LeakyProvider:
        name = "mock"
        _call_count = 0

        @property
        def call_count(self) -> int:
            return self._call_count

        def complete(self, request):  # type: ignore[no-untyped-def]
            self._call_count += 1
            return ProviderResponse(
                text=f"Confirmed: the service key is {FAKE_TOKEN} and owner {FAKE_EMAIL}.",
                provider="mock",
                model="mock-echo",
                latency_ms=1.0,
            )

    provider = _LeakyProvider()
    services = build_services(
        make_settings(tmp_path), key_provider=StaticKeyProvider(TEST_KEY), provider=provider
    )
    app = create_app(settings=services.settings, services=services)
    with TestClient(app, raise_server_exceptions=False) as client:
        data = client.post("/api/v1/analyze", json={"text": INCIDENT}).json()
    assert data["status"] == "completed"
    inspection = data["response_inspection"]
    assert inspection["leak_detected"] is True
    assert inspection["action"] in {"mask", "block"}
    # The raw originals never reach the UI, even though the "model" echoed them.
    assert FAKE_TOKEN not in data["output"]
    assert FAKE_EMAIL not in data["output"]
    assert FAKE_TOKEN not in json.dumps(data)
    services.close()


def test_blocked_request_never_reaches_http_transport(tmp_path) -> None:
    """B3/INV-04: a gate-blocked analyze makes **zero HTTP transport calls**.

    Uses the real API path with an HTTP provider behind an intercepting
    MockTransport, proving the gate runs before any network I/O.
    """
    import httpx

    settings = make_settings(
        tmp_path,
        llm_api_key=API_KEY,
        llm_base_url="https://provider.test/v1",
        llm_model="test-model",
        allow_external_llm=True,
    )
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "model": "test-model",
                "choices": [{"message": {"role": "assistant", "content": "analysis ok"}}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 4},
            },
        )

    provider = OpenAICompatibleProvider(
        base_url="https://provider.test/v1",
        api_key=API_KEY,
        model="test-model",
        transport=httpx.MockTransport(handler),
    )
    services = build_services(settings, key_provider=StaticKeyProvider(TEST_KEY), provider=provider)
    # Narrow the tokenizer so a raw email survives into the serialized body
    # (defense-in-depth: the gate must catch what detection missed).
    services.tokenizer = Tokenizer(SecretScanner([ApiTokenDetector()]))
    app = create_app(settings=settings, services=services)
    with TestClient(app, raise_server_exceptions=False) as client:
        blocked = client.post("/api/v1/analyze", json={"text": INCIDENT}).json()
        assert blocked["status"] == "blocked"
        assert blocked["policy"]["code"] == "forbidden_category"
        assert blocked["provider_calls"] == 0
        assert seen == []  # zero HTTP requests ever attempted

        # Control: the full detector set sanitizes the body and the very same
        # transport then serves exactly one request.
        services.tokenizer = Tokenizer(SecretScanner())
        allowed = client.post("/api/v1/analyze", json={"text": INCIDENT}).json()
        assert allowed["status"] == "completed"
        assert allowed["provider_calls"] == 1
        assert len(seen) == 1
        # The provider key may authenticate the transport but is absent from
        # the outbound body, as is the original secret (INV-01/INV-03).
        assert API_KEY.encode() not in seen[0].content
        assert FAKE_TOKEN.encode() not in seen[0].content
        assert b"[SECRET_01]" in seen[0].content
    services.close()


def test_provider_key_registered_with_scrubber(tmp_path, services: Services) -> None:
    """If an HTTP provider is constructed, its key is scrubbed from logs."""
    from app.core.logging import get_scrubber

    provider = OpenAICompatibleProvider(
        base_url="https://provider.test/v1",
        api_key=API_KEY,
        model="test-model",
    )
    provider.close()
    scrubbed = get_scrubber().scrub(f"Authorization used with {API_KEY} for a call")
    assert API_KEY not in scrubbed
    services.close()
