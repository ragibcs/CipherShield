"""Application settings loaded from the environment and an optional `.env` file.

Security rules enforced here:
- External LLM calls are disabled unless explicitly enabled AND the provider
  configuration validates (invariant INV-14).
- No helper on this module ever returns key material; the only exposure of
  `llm_api_key` is via direct attribute access inside the backend process.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_TRUE = {"1", "true", "yes", "on"}
_PLACEHOLDER_MARKERS = ("example.com", "your-model-name", "changeme", "placeholder")

__all__ = ["Settings", "load_dotenv"]


def load_dotenv(path: str | Path = ".env") -> None:
    """Minimal `.env` loader: `KEY=VALUE` lines. Existing env vars win."""
    file_path = Path(path)
    if not file_path.is_file():
        return
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    database_url: str = "sqlite:///./data/ciphershield.db"
    llm_base_url: str = ""
    llm_model: str = ""
    llm_api_key: str = ""
    llm_timeout_seconds: float = 30.0
    allow_external_llm: bool = False
    ciphershield_key_file: str = "./secrets/local-master.key"
    max_input_chars: int = 20000
    max_output_tokens: int = 1200
    vault_restore_token: str = ""
    rate_limit_per_minute: int = 60

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            app_env=os.environ.get("APP_ENV", "development"),
            backend_host=os.environ.get("BACKEND_HOST", "127.0.0.1"),
            backend_port=_get_int("BACKEND_PORT", 8000),
            database_url=os.environ.get("DATABASE_URL", "sqlite:///./data/ciphershield.db"),
            llm_base_url=os.environ.get("LLM_BASE_URL", "").strip(),
            llm_model=os.environ.get("LLM_MODEL", "").strip(),
            llm_api_key=os.environ.get("LLM_API_KEY", "").strip(),
            llm_timeout_seconds=_get_float("LLM_TIMEOUT_SECONDS", 30.0),
            allow_external_llm=_get_bool("ALLOW_EXTERNAL_LLM", False),
            ciphershield_key_file=os.environ.get(
                "CIPHERSHIELD_KEY_FILE", "./secrets/local-master.key"
            ),
            max_input_chars=_get_int("MAX_INPUT_CHARS", 20000),
            max_output_tokens=_get_int("MAX_OUTPUT_TOKENS", 1200),
            vault_restore_token=os.environ.get("VAULT_RESTORE_TOKEN", "").strip(),
            rate_limit_per_minute=_get_int("RATE_LIMIT_PER_MINUTE", 60),
        )

    @property
    def sqlite_path(self) -> str:
        """Map `sqlite:///relative/or/absolute.db` to a filesystem path."""
        url = self.database_url
        prefix = "sqlite:///"
        if url.startswith(prefix):
            return url[len(prefix) :] or "./data/ciphershield.db"
        if url in {"sqlite://", ":memory:"}:
            return ":memory:"
        return "./data/ciphershield.db"

    @property
    def provider_configured(self) -> bool:
        """True only when every provider field is set and not a template value."""
        fields = (self.llm_base_url, self.llm_model, self.llm_api_key)
        if not all(fields):
            return False
        joined = " ".join(fields).lower()
        return not any(marker in joined for marker in _PLACEHOLDER_MARKERS)

    @property
    def external_calls_enabled(self) -> bool:
        """INV-14: external sending requires explicit opt-in AND valid config."""
        return self.allow_external_llm and self.provider_configured

    def status(self) -> dict[str, bool | str]:
        """Safe status view: booleans only — no URLs, paths, or key material."""
        return {
            "app_env": self.app_env,
            "external_enabled": self.allow_external_llm,
            "provider_configured": self.provider_configured,
            "external_calls_enabled": self.external_calls_enabled,
            "restore_enabled": bool(self.vault_restore_token),
        }
