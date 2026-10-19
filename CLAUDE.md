# CLAUDE.md — CipherShield AI

Local-first secret-isolating AI gateway. Backend: Python/FastAPI. Frontend: Next.js/TypeScript.

Governing specs: `CipherShield_AI_Merged_Claude_Code_Implementation_Plan.md`
(merged competition-compliance update + original plan). Final mapping of
requirements → tests/evidence: `docs/compliance-matrix.md`. Key roles and
rotation: `security/key-management.md`.

## Commands

```bash
# Backend
cd services/api
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest                 # unit + integration + adversarial
ruff check . && ruff format --check .
mypy app
uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend
cd apps/web
npm install
npm run dev            # http://localhost:3000
npm run build && npm run lint
npm test               # vitest

# Evaluation (writes eval/results/summary.json)
cd services/api && python ../../scripts/run_security_eval.py
```

## Repository layout

- `apps/web` — Next.js UI (untrusted; no secrets ever reach it).
- `services/api` — FastAPI backend: `app/services/{detection,tokenization,vault,providers,policy,response_inspection,audit}`, `app/api/routes`, `app/schemas`, `app/core`.
- `security/` — threat model (incl. per-hop protections §2b), security invariants, abuse cases, evaluation protocol, key management.
- `docs/` — architecture, decisions, demo script, submission checklist, compliance matrix.
- `scripts/` — demo data generator and evaluation runner.
- `eval/` — measured evaluation output (generated, then committed as evidence).

## Non-negotiable security invariants

1. Provider API keys and vault keys stay server-side; they must never appear in API responses, frontend bundles, audit events, or logs.
2. External LLM calls are disabled by default (`ALLOW_EXTERNAL_LLM=false`) and enabled only explicitly.
3. Detected secrets are tokenized (`[SECRET_01]`, `[EMAIL_01]`, `[IP_01]`) before any external call.
4. The outbound policy gate inspects the exact serialized request and **fails closed**.
5. AES-256-GCM from the `cryptography` package with a fresh random nonce per encryption; tampered ciphertext must be rejected.
6. Never log raw prompts, raw model output, secrets, keys, or token mappings.
7. Mock provider must work with no network access; tests must not hit the internet.
8. Tools are deny-by-default with an explicit allowlist; no shell/filesystem/network/code-execution tools exist in the MVP.
9. Model output is scanned for known-secret disclosure and masked/blocked.
10. Placeholder restoration is explicit, authorized, and audited — off by default.

## Conventions

- Keep modules small: detection, crypto, providers, policy, and audit must not merge into one service class.
- Pydantic models validate every request; enforce `MAX_INPUT_CHARS`.
- Commit only after tests pass. Never commit `.env`, keys, vault files, or raw prompts.
- Write measured numbers only where a script produced them; label synthetic demo data as such.
- Do not claim "zero leakage" beyond the tested corpus, or formal verification.
