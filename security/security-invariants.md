# Security Invariants — CipherShield AI

Each invariant maps to at least one automated test. Test IDs are stable so
the Security Lab and evaluation report can reference them.

| ID | Invariant | Test |
|---|---|---|
| INV-01 | Master/vault keys never appear in the serialized LLM request | `test_invariants.py::test_keys_absent_from_outbound_payload` |
| INV-02 | Provider API key never appears in API responses, audit events, logs, or frontend source | `test_invariants.py::test_provider_key_never_leaked` |
| INV-03 | A detected secret is replaced before external submission unless a policy explicitly allows the category | `test_detection.py::test_detected_secrets_tokenized_before_send` |
| INV-04 | If the outbound gate finds a forbidden value, no provider request occurs | `test_policy.py::test_blocked_request_never_calls_provider` |
| INV-05 | Every AES-GCM encryption uses a fresh cryptographically random nonce per operation | `test_vault.py::test_nonce_uniqueness_and_freshness` |
| INV-06 | Modified ciphertext or authentication tag is rejected | `test_vault.py::test_tampered_ciphertext_rejected` |
| INV-07 | Vault plaintext mappings are never persisted unencrypted | `test_vault.py::test_no_plaintext_on_disk` |
| INV-08 | Unknown tools and tool arguments are denied by default | `test_policy.py::test_unknown_tool_denied` |
| INV-09 | Response inspection blocks or masks known-secret disclosure | `test_response_inspection.py::test_known_secret_in_response_masked` |
| INV-10 | Error handling does not leak request content or cryptographic material | `test_errors.py::test_error_responses_are_sanitized` |
| INV-11 | No network call occurs in offline/mock-provider tests | `test_invariants.py::test_no_network_in_mock_mode` |
| INV-12 | Placeholder restoration is explicit, authorized, and audited | `test_restore.py::test_restore_requires_authorization_and_is_audited` |
| INV-13 | The app fails closed if encryption or policy evaluation fails | `test_policy.py::test_fail_closed_on_policy_error` |
| INV-14 | External provider calls are disabled by default until explicitly enabled | `test_providers.py::test_external_calls_disabled_by_default` |

**Rule:** an invariant without a failing-first test does not ship. If a test
is removed, the invariant row must be removed from this file in the same
commit — no silent drift.
