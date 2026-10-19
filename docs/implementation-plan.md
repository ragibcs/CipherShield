# Implementation Plan — CipherShield AI

Phased build derived from `CipherShield_AI_Claude_Code_Implementation_Plan.md`.
Each phase ends at a gate: tests + lint pass before the phase is committed.

| Phase | Deliverable | Gate |
|---|---|---|
| 0 | Monorepo scaffold, `.gitignore`, `.env.example`, `CLAUDE.md`, threat model, invariants, abuse cases, evaluation protocol, architecture docs | Docs consistent with plan; no secrets tracked by Git |
| 1 | Backend security core: schemas, detectors, tokenization, AES-GCM vault, key provider, policy gate, audit events + unit tests | Unit tests pass; key/secret leakage checks exist |
| 2 | Provider adapters (OpenAI-compatible + mock), explicit external opt-in, timeouts, exact payload inspection + tests | All tests pass with network access disabled |
| 3 | Response scanner, authorized restore, API routes, request IDs, safe logging + integration tests | No raw secrets in API responses, logs, audit events |
| 4 | Next.js dashboard: Overview, Analyze, Vault, Security Lab, Audit & Evaluation; typed API client; state handling | No API key or vault key in browser source or network payloads |
| 5 | Synthetic corpus, attack scenarios, evaluation runner, metrics from real output, exportable report | Every metric links to a reproducible test result |
| 6 | Docker Compose, GitHub Actions, `.env.example`, README, demo script, submission checklist | Clean clone runs mock demo with documented commands |

## Decision records

- `docs/decisions/0001-aes-256-gcm-vault.md` — established primitives only.
- `docs/decisions/0002-fail-closed-policy-gate.md` — deny on error.
- `docs/decisions/0003-provider-adapter-boundary.md` — one interface, mock and HTTP implementations.

## Priority when time runs short

Correct security boundary → reproducible tests → working demo → polished UI →
optional features. Optional cuts: hash-chain audit, Docker, Playwright E2E,
rate limiting.
