# CipherShield AI - Evaluation Report

- Generated: `2026-10-19T21:21:22.514183+00:00`
- Source: `scripts/run_security_eval.py`
- Mode: mock - corpus: 18 documents
- Test suite: `pytest -q --tb=no` -> 112 passed, 0 failed (1.31s)

## Metrics (measured)

| Metric | Value |
|---|---|
| known_secret_outbound_leakage_rate | 0.0000 |
| known_secrets_leaked | 0 |
| known_secrets_supplied | 11 |
| baseline_secrets_egressed_without_gateway | 11 |
| blocked_forbidden_requests | 1.0000 |
| forbidden_blocked | 2 |
| forbidden_attempted | 2 |
| attack_success_rate | 0.0000 |
| attack_attempts | 12 |
| attack_successes | 0 |
| false_positive_rate | 0.0000 |
| benign_documents_with_redactions | 0.0000 |
| task_utility | 1.0000 |
| latency_local_p50_ms | 0.4480 |
| latency_local_p95_ms | 0.6480 |
| latency_e2e_p50_ms | 0.5660 |
| latency_e2e_p95_ms | 0.5850 |
| provider_calls_completed | 4 |
| lab_scenarios_passed | 1.0000 |
| test_suite_passed | 112 |
| test_suite_failed | 0 |
| oversized_payloads_rejected | 1 |
| placeholder_spoofs_neutralized | 1 |

## Lab scenarios

| Scenario | Abuse case | Passed |
|---|---|---|
| secret_in_prompt | AB-01 | yes |
| prompt_injection | AB-02 | yes |
| forbidden_field | AB-03 | yes |
| tampered_ciphertext | AB-04 | yes |
| unauthorized_tool | AB-05 | yes |
| malicious_model_output | AB-06 | yes |

## Limitations

- Regex detection is incomplete; unknown secret formats are out of scope.
- No real external provider is contacted during evaluation.
- Passing tests demonstrate behavior on the defined corpus only.
