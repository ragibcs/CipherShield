# Evaluation Protocol — CipherShield AI

This protocol defines how every number in the dashboard and report is
produced. Metrics are computed from recorded test results — never typed in
by hand.

## 1. Corpus

`scripts/generate_demo_data.py` emits a **synthetic corpus** containing:

- Benign documents (should mostly pass untouched).
- Documents seeded with known fake secrets across categories:
  `api_token`, `bearer_token`, `password_kv`, `email`, `ipv4`.
- Attack documents: prompt injection, secret-extraction requests,
  forbidden-field payloads, placeholder spoofing, oversized input.

All secrets in the corpus are fake and generated locally. No real
credentials are ever used, even in tests.

## 2. Test layers

1. **Unit** — detectors, overlap resolution, tokenization, AES-GCM
   round-trip/tamper/wrong-key, policy rules, output scanner, audit
   redaction, provider error normalization.
2. **Integration** — preview → tokenize → policy → provider → response
   scan; blocked requests make zero provider calls; no key in any
   response; no secrets in captured logs or audit rows; restore requires
   authorization and emits an audit event.
3. **Adversarial** — AB-01 … AB-14 from `security/abuse-cases.md`.

## 3. Metrics and formulas

| Metric | Formula |
|---|---|
| Known-secret outbound leakage rate | known test secrets found in outbound payloads / known test secrets supplied |
| Blocked forbidden requests | forbidden requests blocked / forbidden requests attempted |
| Attack success rate | successful policy violations / attack attempts |
| False-positive rate | benign values incorrectly redacted / benign values evaluated |
| Task utility | approved tasks with a usable model answer / approved tasks (mock mode: mock response returned without blocking) |
| Latency | P50/P95 of local processing and end-to-end durations |
| Provider-call count | measured counter proving blocked requests never reached the provider |

## 4. Rules

- Every metric in `eval/results/summary.json` must be produced by
  `scripts/run_security_eval.py` (which runs the real suite and the attack
  scenarios) — the dashboard renders this file, it does not invent values.
- Report the corpus size, run timestamp, provider mode
  (`mock` / `external`), and model identifier alongside the numbers.
- A "zero observed leakage" result is always scoped: *"0/N leakage across
  the synthetic corpus with the configured detectors"* — never a universal
  claim.
- Synthetic demo numbers shown in the UI must be visibly labeled
  `synthetic`; measured numbers are labeled with their run ID.
- Latency percentiles are measured on the machine that ran the suite and
  are reported with the environment description.

## 5. Limitations to publish with any result

- Regex-based detection is incomplete by design.
- The suite does not test a real external provider in CI; mock-mode
  results are labeled as such.
- No formal verification is claimed; passing tests demonstrate behavior
  on the defined corpus only.
