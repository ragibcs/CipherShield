# Submission Checklist — CipherShield AI

Competition deadline: **1 November 2026, 5:00 PM UTC+3 (8:00 PM Bangladesh time)**.

## Product

- [x] Clean-clone setup works. *(verified: fresh clone -> install -> 116 tests pass -> evaluation reproduces)*
- [x] Mock-mode demo works without an API key. *(verified locally and via Docker Compose)*
- [x] OpenAI-compatible provider configuration is documented. *(README + .env.example)*
- [x] Secret preview and outbound sanitized payload are visible. *(Analyze screen + API tests)*
- [x] Master/vault keys remain backend-side. *(bundle scan + endpoint sweep tests)*
- [x] Blocked requests demonstrably make no provider call. *(provider call-counter tests)*
- [x] Tampered ciphertext is rejected. *(vault tests + Security Lab scenario)*
- [x] Response inspection and explicit restore flow are tested.
- [x] Security dashboard uses actual evaluation output. *(eval/results/summary.json, labeled measured)*

## Security and quality

- [x] No real secrets or credentials in Git history. *(all key-like strings are marked synthetic fixtures)*
- [x] `.env.example` contains placeholders only.
- [x] Unit, integration, and adversarial tests pass. *(116, offline with sockets blocked)*
- [x] Lint and type checks pass. *(ruff, mypy, eslint, tsc)*
- [x] External calls disabled by default. *(INV-14 tests + Docker default)*
- [x] Threat model and limitations are documented.
- [x] No unsupported "formally verified" or universal "zero leakage" claims.

## Competition compliance (merged plan — `CipherShield_AI_Merged_Claude_Code_Implementation_Plan.md`)

- [x] Per-hop trust boundary + plaintext/ciphertext lifecycle documented. *(`security/threat-model.md` §2b, `docs/architecture.md` "Data states")*
- [x] Key roles/rotation/invalid-key behavior documented; no false hierarchy. *(`security/key-management.md`)*
- [x] Exact serialized outbound request inspected before network I/O. *(`test_blocked_request_never_reaches_http_transport` — zero MockTransport calls when blocked)*
- [x] Provider failure modes tested (missing credentials, timeout, malformed shape, non-JSON body, HTTP errors). *(`test_providers.py`)*
- [x] Malicious provider response that repeats a secret is masked end-to-end. *(`test_malicious_provider_response_is_masked_before_ui`)*
- [x] Eval publishes sanitized-request evidence, latency P50/P95, and provider-call counts. *(`eval/results/summary.json` → `evidence`, `metrics`)*
- [x] Compliance matrix produced. *(`docs/compliance-matrix.md`)*
- [x] No encrypted-inference / homomorphic / formal-verification overclaims. *(README claim scope, threat model §4)*
- [ ] **Run one real hosted-provider analysis with your own API key** and record provider/model + sanitized request (key never captured). *Instructions: README → "Enabling a real OpenAI-compatible provider"*
- [ ] Devpost **video** shows the trust boundary, sanitized outbound request, blocked attack, and tamper test. *(`docs/demo-script.md`)*

## Submission

- [x] README includes problem, solution, architecture, setup, tests, limitations, screenshots.
- [ ] Demo video is short, clear, and uses synthetic data.
- [ ] Repository is accessible to judges.
- [ ] Competition-required fields and links are complete.
- [ ] Submission completed before **1 November 2026, 8:00 PM Bangladesh time**.
