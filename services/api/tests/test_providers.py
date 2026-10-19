"""Provider behavior: offline mock, opt-in gating, HTTP adapter safety.

Every test here runs with sockets blocked (INV-11).
"""

from __future__ import annotations

import socket

import httpx
import pytest

from app.core.config import Settings
from app.core.errors import PayloadTooLargeError, ProviderError, ProviderNotConfiguredError
from app.services.providers import (
    MockProvider,
    OpenAICompatibleProvider,
    ProviderRequest,
    build_provider,
)


def _request(content: str = "Analyze [SECRET_01] incident") -> ProviderRequest:
    return ProviderRequest(messages=[{"role": "user", "content": content}], max_tokens=256)


class _BlockedSocket:
    """Guard used by individual tests that must prove zero network usage."""

    def __enter__(self) -> _BlockedSocket:
        self._original = socket.socket.connect

        def _blocked(*args: object, **kwargs: object) -> None:
            raise AssertionError("network access attempted")

        socket.socket.connect = _blocked  # type: ignore[method-assign]
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket.connect = self._original  # type: ignore[method-assign]


def test_mock_provider_is_deterministic_and_offline() -> None:
    provider = MockProvider()
    with _BlockedSocket():
        first = provider.complete(_request())
        second = provider.complete(_request())
    assert first.text == second.text
    assert first.provider == "mock"
    assert provider.call_count == 2


def test_mock_output_reflects_placeholders_only() -> None:
    provider = MockProvider()
    response = provider.complete(_request("Summary [SECRET_01] and [EMAIL_01] and [IP_01]"))
    assert "3" in response.text  # three placeholders counted
    assert "hunter2sekrit" not in response.text


def test_default_build_selects_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALLOW_EXTERNAL_LLM", raising=False)
    provider = build_provider(Settings.from_env())
    assert isinstance(provider, MockProvider)


def test_external_opt_in_without_valid_config_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "true")
    monkeypatch.setenv("LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("LLM_API_KEY", "")  # invalid: no key
    with pytest.raises(ProviderNotConfiguredError):
        build_provider(Settings.from_env())


def test_configured_and_enabled_builds_http_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "true")
    monkeypatch.setenv("LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("LLM_API_KEY", "sk-test-abcdefghijklmnop")
    provider = build_provider(Settings.from_env())
    assert isinstance(provider, OpenAICompatibleProvider)
    provider.close()


def test_http_adapter_success_via_mock_transport() -> None:
    key = "sk-transport-fake-0123456789abcdef"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {key}"
        return httpx.Response(
            200,
            json={
                "model": "test-model",
                "choices": [{"message": {"role": "assistant", "content": "analysis ok"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    provider = OpenAICompatibleProvider(
        base_url="https://provider.test/v1",
        api_key=key,
        model="test-model",
        transport=httpx.MockTransport(handler),
    )
    with _BlockedSocket():
        response = provider.complete(_request())
    assert response.text == "analysis ok"
    assert response.provider == "openai-compatible"
    assert provider.call_count == 1
    provider.close()


def test_http_adapter_normalizes_errors_without_leaking(monkeypatch: pytest.MonkeyPatch) -> None:
    secret_body = "raw secret leak password=hunter2sekrit"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text=secret_body)

    provider = OpenAICompatibleProvider(
        base_url="https://provider.test/v1",
        api_key="sk-error-fake-0123456789abcdef",
        model="test-model",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderError) as excinfo:
        provider.complete(_request())
    # Error message must not echo provider response bodies (INV-10).
    assert "hunter2sekrit" not in str(excinfo.value)
    assert provider.call_count == 0  # failed calls are not counted as completed
    provider.close()


def test_http_adapter_timeout_is_normalized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("connection timed out to https://secret-host.internal")

    provider = OpenAICompatibleProvider(
        base_url="https://provider.test/v1",
        api_key="sk-timeout-fake-0123456789abcdef",
        model="test-model",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderError) as excinfo:
        provider.complete(_request())
    assert "secret-host" not in str(excinfo.value)
    provider.close()


def test_http_adapter_bounds_input_size() -> None:
    provider = OpenAICompatibleProvider(
        base_url="https://provider.test/v1",
        api_key="sk-size-fake-0123456789abcdef",
        model="test-model",
        max_input_chars=100,
        transport=httpx.MockTransport(lambda request: httpx.Response(200)),
    )
    with pytest.raises(PayloadTooLargeError):
        provider.complete(_request("x" * 500))
    assert provider.call_count == 0
    provider.close()


def test_http_adapter_requires_configuration() -> None:
    with pytest.raises(ProviderNotConfiguredError):
        OpenAICompatibleProvider(base_url="", api_key="", model="")
