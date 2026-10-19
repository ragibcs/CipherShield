# Security Invariants — CipherShield AI

Each invariant maps to at least one automated test. Test IDs are stable so
the Security Lab and evaluation report can reference them.

| ID | Invariant | Test |
|---|---|---|
| INV-01 | Master/vault keys never appear in the serialized LLM request | `test_api.py::test_analyze_completes_via_mock_with_sanitized_outbound`, `test_api.py::test_blocked_request_never_reaches_http_transport` |
| INV-02 | Provider API key never appears in API responses, audit events, logs, or frontend source | `test_api.py::test_no_key_in_any_endpoint_response`, `test_config.py::test_status_never_contains_key_or_paths`, `test_logging.py::test_registered_values_are_scrubbed` |
| INV-03 | A detected secret is replaced before external submission unless a policy explicitly allows the category | `test_tokenization.py::test_no_original_values_remain_in_sanitized_text`, `test_adversarial.py::test_split_secret_never_reaches_outbound` |
| INV-04 | If the outbound gate finds a forbidden value, no provider request occurs (zero transport calls) | `test_api.py::test_blocked_request_never_reaches_http_transport`, `test_api.py::test_analyze_blocked_when_forbidden_value_remains`, `test_policy.py::test_forbidden_category_blocks` |
| INV-05 | Every AES-GCM encryption uses a fresh cryptographically random nonce per operation | `test_vault.py::test_nonce_is_fresh_per_encryption` |
| INV-06 | Modified ciphertext, tag, or wrong key is rejected | `test_vault.py::test_tampered_ciphertext_rejected`, `test_vault.py::test_tampered_payload_byte_rejected`, `test_vault.py::test_wrong_key_rejected` |
| INV-07 | Vault plaintext mappings are never persisted unencrypted | `test_vault.py::test_store_never_persists_plaintext` |
| INV-08 | Unknown tools and tool arguments are denied by default | `test_policy.py::test_unknown_tool_denied`, `test_policy.py::test_unknown_argument_denied`, `test_policy.py::test_empty_allowlist_denies_everything` |
| INV-09 | Response inspection blocks or masks known-secret disclosure | `test_response_inspection.py::test_known_secret_in_response_masked`, `test_api.py::test_malicious_provider_response_is_masked_before_ui` |
| INV-10 | Error handling does not leak request content or cryptographic material | `test_api.py::test_validation_errors_do_not_echo_input`, `test_providers.py::test_http_adapter_normalizes_errors_without_leaking`, `test_adversarial.py::test_malformed_json_returns_static_error` |
| INV-11 | No network call occurs in offline/mock-provider tests | `tests/conftest.py::_block_network` (autouse: every test), `test_providers.py::test_mock_provider_is_deterministic_and_offline` |
| INV-12 | Placeholder restoration is explicit, authorized, and audited | `test_restore.py::test_restore_disabled_by_default`, `test_restore.py::test_restore_with_valid_token_returns_selected_values`, `test_api.py::test_restore_flow_end_to_end` |
| INV-13 | The app fails closed if encryption or policy evaluation fails | `test_policy.py::test_policy_error_fails_closed`, `test_vault.py::test_store_tampered_row_fails_closed` |
| INV-14 | External provider calls are disabled by default until explicitly enabled | `test_config.py::test_external_calls_disabled_by_default`, `test_providers.py::test_default_build_selects_mock`, `test_providers.py::test_external_opt_in_without_valid_config_fails_closed` |

**Rule:** an invariant without a failing-first test does not ship. If a test
is removed, the invariant row must be removed from this file in the same
commit — no silent drift.

Mapping verified against the live test suite (`grep` of `tests/`); any
test renamed here must be renamed in the suite in the same commit.
