# Submission Checklist — CipherShield AI

Competition deadline: **1 November 2026, 5:00 PM UTC+3 (8:00 PM Bangladesh time)**.

## Product

- [ ] Clean-clone setup works.
- [ ] Mock-mode demo works without an API key.
- [ ] OpenAI-compatible provider configuration is documented.
- [ ] Secret preview and outbound sanitized payload are visible.
- [ ] Master/vault keys remain backend-side.
- [ ] Blocked requests demonstrably make no provider call.
- [ ] Tampered ciphertext is rejected.
- [ ] Response inspection and explicit restore flow are tested.
- [ ] Security dashboard uses actual evaluation output.

## Security and quality

- [ ] No real secrets or credentials in Git history.
- [ ] `.env.example` contains placeholders only.
- [ ] Unit, integration, and adversarial tests pass.
- [ ] Lint and type checks pass.
- [ ] External calls disabled by default.
- [ ] Threat model and limitations are documented.
- [ ] No unsupported "formally verified" or universal "zero leakage" claims.

## Submission

- [ ] README includes problem, solution, architecture, setup, tests, limitations, screenshots.
- [ ] Demo video is short, clear, and uses synthetic data.
- [ ] Repository is accessible to judges.
- [ ] Competition-required fields and links are complete.
- [ ] Submission completed before **1 November 2026, 8:00 PM Bangladesh time**.
