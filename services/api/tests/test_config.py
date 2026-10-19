"""INV-14 + configuration safety: external calls off by default, no key exposure."""

from app.core.config import Settings, load_dotenv


def test_external_calls_disabled_by_default() -> None:
    settings = Settings.from_env()
    assert settings.allow_external_llm is False
    assert settings.external_calls_enabled is False
    assert settings.provider_configured is False


def test_external_requires_explicit_flag_and_valid_config(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("LLM_API_KEY", "sk-test-12345678901234567890")
    # Flag still off -> no external calls.
    assert Settings.from_env().external_calls_enabled is False

    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "true")
    assert Settings.from_env().external_calls_enabled is True


def test_template_values_are_not_treated_as_configured(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "true")
    monkeypatch.setenv("LLM_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("LLM_MODEL", "your-model-name")
    monkeypatch.setenv("LLM_API_KEY", "sk-test-12345678901234567890")
    settings = Settings.from_env()
    assert settings.provider_configured is False
    assert settings.external_calls_enabled is False


def test_status_never_contains_key_or_paths(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    secret_key = "sk-supersecret-abcdef123456"
    monkeypatch.setenv("LLM_API_KEY", secret_key)
    monkeypatch.setenv("LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("CIPHERSHIELD_KEY_FILE", "/srv/secrets/hidden.key")
    settings = Settings.from_env()
    serialized = str(settings.status())
    assert secret_key not in serialized
    assert "hidden.key" not in serialized
    assert "openai" not in serialized


def test_load_dotenv_reads_file_without_overriding_real_env(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    env_file = tmp_path / ".env"
    env_file.write_text("MAX_INPUT_CHARS=1234\n# comment\nALLOW_EXTERNAL_LLM=no\n")
    monkeypatch.setenv("MAX_INPUT_CHARS", "9999")
    load_dotenv(env_file)
    settings = Settings.from_env()
    assert settings.max_input_chars == 9999  # real env wins
    assert settings.allow_external_llm is False
