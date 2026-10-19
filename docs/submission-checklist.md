# Submission Checklist — CipherShield AI

Competition deadline: **1 November 2026, 5:00 PM UTC+3 (8:00 PM Bangladesh time)**.

## Product

- [x] Clean-clone setup works. *(verified: fresh clone -> install -> 112 tests pass -> evaluation reproduces)*
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
- [x] Unit, integration, and adversarial tests pass. *(112, offline with sockets blocked)*
- [x] Lint and type checks pass. *(ruff, mypy, eslint, tsc)*
- [x] External calls disabled by default. *(INV-14 tests + Docker default)*
- [x] Threat model and limitations are documented.
- [x] No unsupported "formally verified" or universal "zero leakage" claims.

## Submission

- [x] README includes problem, solution, architecture, setup, tests, limitations, screenshots.
- [ ] Demo video is short, clear, and uses synthetic data.
- [ ] Repository is accessible to judges.
- [ ] Competition-required fields and links are complete.
- [ ] Submission completed before **1 November 2026, 8:00 PM Bangladesh time**.
