# CipherShield AI — Backend API

FastAPI service implementing the local-first secret-isolating gateway:
detection, tokenization, AES-256-GCM vault, outbound policy gate, provider
adapters, response inspection, and the hash-chained audit log.

## Run

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000
```

## Checks

```bash
ruff check . && ruff format --check .
mypy app
pytest -q
```

See `../../CLAUDE.md` for commands and security invariants.
