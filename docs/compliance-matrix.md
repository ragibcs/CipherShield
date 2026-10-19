# Compliance Matrix — CipherShield AI (merged plan)

Maps every requirement of `CipherShield_AI_Merged_Claude_Code_Implementation_Plan.md`
to its implementation, evidence, result, and remaining limitation.
Results reflect the verification run recorded in
`eval/results/summary.json` (offline, sockets blocked; `generated_at` in
that file is the run date; produced by `scripts/run_security_eval.py`).

## A. Updated objective (AI Pipeline secret-isolation track)

| Requirement | Implementation | Test / evidence | Result | Remaining limitation |
|---|---|---|---|---|
| Real hosted LLM API for ≥1 documented end-to-end run | `app/services/providers/openai_compat.py` (configurable base URL/model/timeout, server-side key); opt-in via `ALLOW_EXTERNAL_LLM` | `test_providers.py` (MockTransport success/timeout/error/shape); README "Enabling a real provider" | **Code ready; live run pending** — no provider credential available in this environment; never faked | Requires the user's own key: one live run must be recorded before submission (see submission checklist) |
| Keep master/vault key + provider credential out of prompt, provider request, frontend, responses, logs, audit | Key provider (`key_provider.py`), log scrubber (`core/logging.py`), gate, secret-free audit | INV-01, INV-02 rows in `security/security-invariants.md` (all mapped tests pass) | **Pass** | Assumes uncompromised backend host |
| Protect original input inside a documented trusted boundary | `security/threat-model.md` §2b (per-hop table + plaintext/ciphertext lifecycle), `docs/architecture.md` "Data states" | Doc review + INV-07 (vault ciphertext only) | **Pass** | Browser→backend leg is loopback/TLS; the backend itself must read plaintext to analyze it (stated, not hidden) |
| Send only an approved, sanitized prompt | `app/api/routes/analyze.py` pipeline; `app/services/policy/gate.py` on exact serialized body | `test_api.py::test_analyze_completes_via_mock_with_sanitized_outbound` | **Pass** | Detector coverage is regex-based; residue/known-secret checks are the backstop |
| Reproducible tests + short video | 116 offline tests, `scripts/run_security_eval.py`, `docs/demo-script.md` | CI (`.github/workflows/ci.yml`), eval summary | **Tests pass; video = user task** | Video must use synthetic data only |
| Clean website with security-focused UX | Five screens (`apps/web/app/*`), mode labels, disclosure text | Vitest component tests + live headless-browser verification | **Pass** | — |
| Technical honesty: no encrypted-inference claim | README claim scope, `security/threat-model.md` §4 "Encrypted inference" out-of-scope | Doc review | **Pass** | Provider reads the sanitized prompt; that is disclosed, not concealed |

## B1. Encrypted input envelope & trust-boundary documentation

| Requirement | Implementation | Test / evidence | Result | Remaining limitation |
|---|---|---|---|---|
| Per-hop protection documented | `security/threat-model.md` §2b | Doc review | **Pass** | — |
| Stored mapping encrypted at rest (authenticated) | AES-256-GCM vault (`vault/crypto.py`, `vault/store.py`) | `test_vault.py` (round-trip, tamper, wrong key, no-plaintext) | **Pass** | — |
| Plaintext exists briefly in backend, never logged | Tokenizer→vault seal before send; logging scrubber | `test_audit.py::test_events_have_no_free_text_fields`, `test_logging.py` | **Pass** | Compromised process memory out of scope |
| No invented crypto; established libraries | `cryptography` AESGCM only; no custom schemes | Code review + `docs/decisions/*` | **Pass** | — |
| Do not imply envelope protects plaintext from backend | Explicit honesty statements (threat model §2b, README) | Doc review | **Pass** | — |
| Fail closed on decryption/sanitization/policy/inspection failure | `gate.evaluate` catches all → block; vault `VaultError`; inspector fail-closed mask/block | `test_policy.py::test_policy_error_fails_closed`, `test_response_inspection.py::test_fail_closed_block_when_masking_cannot_remove_finding` | **Pass** | — |

## B2. Key separation and management

| Requirement | Implementation | Test / evidence | Result | Remaining limitation |
|---|---|---|---|---|
| Distinguish master key, VEK, provider credential | `security/key-management.md` (three roles; no hierarchy claimed) | Doc + `test_config.py::test_status_never_contains_key_or_paths` | **Pass** | No separate application master key exists in the MVP (documented, not pretended) |
| Never send any key to the LLM | Gate + payload builder exclude keys | INV-01 tests incl. transport-level content assertions | **Pass** | — |
| CSPRNG generation, no hardcoded/committed keys | `os.urandom`; `.gitignore`; every `.dockerignore` excludes `.env*`/key files; git-history scan | Submission checklist "no real secrets in Git history" | **Pass** | — |
| Restrictive file permissions | `KeyFileProvider` creates/repairs `0600` | `test_vault.py::test_key_file_created_with_restrictive_permissions` | **Pass** | POSIX only |
| Rotation/invalid-key behavior documented | `security/key-management.md` rotation table | `test_vault.py::test_wrong_key_rejected`, `test_invalid_key_size_rejected`, lab `tampered_ciphertext` | **Pass** | Automated re-seal rotation out of MVP scope (documented) |
| Fresh nonce per encryption; tamper/tag/wrong-key/malformed-nonce/malformed-envelope tests | `vault/crypto.py` | `test_vault.py::test_nonce_is_fresh_per_encryption`, `test_tampered_ciphertext_rejected`, `test_tampered_payload_byte_rejected`, `test_wrong_key_rejected`, `test_malformed_records_rejected` | **Pass** | — |
| No compromised-host protection claim | `security/threat-model.md` §4 | Doc review | **Pass** | — |

## B3. Exact outbound request gate

| Requirement | Implementation | Test / evidence | Result | Remaining limitation |
|---|---|---|---|---|
| Inspect exact serialized request before network I/O | `analyze.py` serializes the same object handed to the provider; `gate.evaluate(body=serialized)` immediately before `provider.complete` | `test_api.py::test_blocked_request_never_reaches_http_transport` | **Pass** | httpx whitespace may differ; residue check normalizes (documented in `container.py`) |
| Reject remaining secrets, key material, forbidden fields, tokens | Residue + known-secret + deny-category checks in `gate.py` | `test_policy.py` (7 gate tests) | **Pass** | Regex coverage incomplete by design |
| Check all content-carrying fields incl. tool arguments | Payload = model/messages/max_tokens/temperature; `ToolPolicy.evaluate` serializes and checks arguments | `test_policy.py::test_unknown_argument_denied`, `test_empty_allowlist_denies_everything` | **Pass** | MVP has no tool-carrying provider path (deny-all allowlist) |
| Blocked ⇒ zero provider calls, proven with mock transport | `test_blocked_request_never_reaches_http_transport` (intercepting `httpx.MockTransport`, `seen == []`) | Same | **Pass** | — |
| Secret-free audit metadata only | `AuditEvent`: request ID, decision, reason code, categories, provider/model, latency, outcome | `test_audit.py::test_events_have_no_free_text_fields`, `test_api.py::test_blocked_request_is_audited_without_raw_text` | **Pass** | — |
| Document detector coverage and residual risk | `DETECTOR_COVERAGE_NOTE`, threat model §5 | `test_preview...` asserts note surfaced | **Pass** | — |

## B4. Real hosted LLM evidence

| Requirement | Implementation | Test / evidence | Result | Remaining limitation |
|---|---|---|---|---|
| Retain deterministic mock provider | `providers/mock.py` | `test_providers.py::test_mock_provider_is_deterministic_and_offline` | **Pass** | — |
| Configurable OpenAI-compatible adapter, server-side key | `providers/openai_compat.py` | timeout/error/shape/size/no-config tests | **Pass** | — |
| Disabled by default; explicit opt-in | `ALLOW_EXTERNAL_LLM=false` default; build fails closed without full config | `test_config.py::test_external_calls_disabled_by_default`, `test_providers.py::test_external_opt_in_without_valid_config_fails_closed` | **Pass** | — |
| ≥1 real end-to-end run before submission | Documented in README/`docs/deploy-render.md` | — | **Pending user credential** | Run with your key; record provider/model + sanitized request; never label a mock run as live |
| Capture provider/model config + sanitized request as evidence | Eval summary `config` + `evidence.serialized_request` (with measured absence checks) | `eval/results/summary.json` → `evidence` | **Pass** | Example is mock-mode; replace/extend with the live run's metadata (key never captured) |
| Never fake a provider response | Mock runs labeled `provider: mock`, UI badge "Mock (offline)" | `test_api.py::test_analyze_completes_via_mock_with_sanitized_outbound` asserts `provider == "mock"` | **Pass** | — |

## B5. Response inspection and restoration

| Requirement | Implementation | Test / evidence | Result | Remaining limitation |
|---|---|---|---|---|
| Inspect output for known secrets, patterns, placeholder tampering | `response_inspection/inspector.py` | `test_response_inspection.py` (5 tests) | **Pass** | Novel secret formats not in the pattern set pass through |
| Block/mask by default; never auto-restore | Default mask/block; restore separate endpoint | `test_api.py::test_malicious_provider_response_is_masked_before_ui` | **Pass** | — |
| Explicit, authorized, audited restore | `vault/restore.py` + `VAULT_RESTORE_TOKEN` | `test_restore.py` (6 tests), `test_api.py::test_restore_flow_end_to_end` | **Pass** | Token-in-env is an MVP authorization stand-in, not full IAM |
| Adversarial test: provider repeats a known secret | Integration test with a leaky provider (above) + lab `malicious_model_output` | Same + `test_lab.py::test_every_scenario_passes` | **Pass** | — |

## B6. Competition demo and UI evidence

| Required demo beat | Where shown | Result |
|---|---|---|
| 1. Synthetic incident with fake secret | Analyze screen sample buttons; `scripts/generate_demo_data.py` | **Pass** |
| 2. Detection + redaction preview | Analyze → "Redaction preview" | **Pass** |
| 3. Sanitized outbound request, raw secret absent | Analyze → "Exact outbound payload (proves placeholders only)" | **Pass** |
| 4. Real hosted analysis (clearly labelled) + mock mode | Overview "Provider mode" badge; Analyze mode badge + external disclosure text | **Mock label pass; live run pending credential** |
| 5. Prompt-injection / secret-extraction blocked | Security Lab `prompt_injection`, `forbidden_field` scenarios | **Pass** |
| 6. Ciphertext-tampering fails authentication | Security Lab `tampered_ciphertext` scenario | **Pass** |
| 7. Test report with measured results + limitations | Audit & Evaluation screen ← `eval/results/summary.json` (+ `report.md`) | **Pass** |
| Synthetic-only screenshots, loopback default, text-not-color-only status | `.dockerignore`/fixtures, `127.0.0.1` defaults, Badge components with text | **Pass** |

## B7. Evaluation metrics from real runs

| Metric | Source in `eval/results/summary.json` | Latest value* |
|---|---|---|
| Known-secret outbound leakage | `metrics.known_secret_outbound_leakage_rate` | 0.0 (0/11) |
| Forbidden blocked / attempted | `metrics.blocked_forbidden_requests` | 1.0 (2/2) |
| Unauthorized tool attempts blocked | lab `unauthorized_tool` in `lab_runs` | pass |
| Tampered ciphertext rejection | lab `tampered_ciphertext` in `lab_runs` | pass |
| False-positive redaction rate | `metrics.false_positive_rate` | 0.0 |
| Task utility after sanitization | `metrics.task_utility` | 1.0 |
| Local + end-to-end latency (P50/P95) | `metrics.latency_*_p50/p95_ms` | measured per run |
| Provider call count; blocked ⇒ zero extra | `metrics.provider_calls_completed`, `metrics.provider_calls_beyond_approved` | 0 beyond approved |
| Corpus size, run date, provider/model config, limitations | `config.*`, `generated_at`, `limitations` | present |

\* Numbers must be re-read from the current `eval/results/summary.json`
after each run; the report on the Audit screen renders that file live.

## D. Acceptance criteria

| Criterion | Status |
|---|---|
| Existing functionality preserved | **Yes** — incremental changes only; prior suite grew 112 → **116**, all passing |
| Trust boundary + plaintext/ciphertext lifecycle documented accurately | **Yes** — threat model §2b, architecture "Data states" |
| Keys/credentials never in outbound requests or client code | **Yes** — INV-01/INV-02 + bundle scan |
| Exact serialized request inspected immediately before sending | **Yes** — `analyze.py` + transport test |
| Blocked request proven to cause zero provider calls | **Yes** — `test_blocked_request_never_reaches_http_transport` |
| AES-GCM tamper and wrong-key tests pass | **Yes** — `test_vault.py` |
| Provider output secret-leakage tests pass | **Yes** — `test_malicious_provider_response_is_masked_before_ui` |
| Mock offline; live mode clearly distinguished | **Yes** — badges/disclosure; `provider: "mock"` in responses |
| ≥1 real hosted-provider run recorded | **Pending** — needs user credential (never claim otherwise) |
| UI shows redaction, mode, decisions, evidence | **Yes** |
| Metrics generated from repeatable runs | **Yes** — `scripts/run_security_eval.py` |
| README/demo disclose limitations; no encrypted-inference overclaim | **Yes** — README claim scope, threat model §4 |
| Tests/lint/typecheck/build/Docker smoke pass | **Yes** — see final verification output; Compose + single-container smoke tested |
| Devpost video showing boundary + attack tests | **User task** — `docs/demo-script.md` |
