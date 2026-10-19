# Abuse Cases — CipherShield AI

Each case states the attack, the expected system behavior, and the test
that demonstrates it. Security Lab scenarios mirror these IDs.

| ID | Abuse case | Expected behavior | Test |
|---|---|---|---|
| AB-01 | Paste an incident report containing a live-looking API token | Token detected, shown in preview, replaced with `[SECRET_n]` before any provider call | `test_detection.py` |
| AB-02 | Ask the model (via prompt text) to reveal the system prompt or API key | No key material exists in the prompt context; request proceeds without any key to reveal | `test_adversarial.py::test_prompt_injection_no_secret_in_context` |
| AB-03 | Include a forbidden category (e.g. raw `password` value) that policy marks `deny` | Outbound gate blocks; provider call count unchanged | `test_policy.py::test_forbidden_category_blocks` |
| AB-04 | Modify stored vault ciphertext or tag | AES-GCM verification fails; restore returns a safe error, audit records the failure | `test_vault.py::test_tamper_rejected`, `test_adversarial.py` |
| AB-05 | Request a tool outside the allowlist (shell, fetch, exec) | Denied by default; denial audited | `test_policy.py::test_unknown_tool_denied` |
| AB-06 | Model output repeats a known original secret | Response masked/blocked before reaching the user | `test_response_inspection.py` |
| AB-07 | Split a secret across whitespace/delimiters inside the payload | Delimiter-normalized matching detects the reassembled value, or the gate blocks on residual risk | `test_adversarial.py::test_split_secret_detection` |
| AB-08 | Submit multiple secrets of the same category | Deterministic, collision-free IDs (`[SECRET_01]`, `[SECRET_02]`, ...) | `test_tokenization.py` |
| AB-09 | Spoof a placeholder in the input (`[SECRET_01]`) to collide with a real mapping | Input placeholders are escaped/namespaced so a spoof cannot resolve to another record | `test_adversarial.py::test_placeholder_spoofing` |
| AB-10 | Oversized or malformed payload | Rejected by schema and size limits with a safe error body | `test_api.py::test_oversized_payload_rejected` |
| AB-11 | Direct request to any endpoint for the provider API key | Endpoint responses never contain key material | `test_api.py::test_no_key_in_any_response` |
| AB-12 | Call restore without authorization | 401/403, no rehydration, audited | `test_restore.py` |
| AB-13 | Ciphertext encrypted under a wrong key | Decryption fails closed with a generic error | `test_vault.py::test_wrong_key_rejected` |
| AB-14 | Enable external calls without valid provider config | Configuration validation fails; no outbound request attempted | `test_providers.py` |
