# Decision 0003: Provider adapter behind one interface

## Status

Accepted

## Context

Tests and demos must run without network access, while production needs an
OpenAI-compatible chat-completions client with strict timeouts.

## Decision

`LLMProvider` protocol with `complete(request) -> ProviderResponse`:

- `MockProvider` — deterministic, offline, no sockets; used when
  `ALLOW_EXTERNAL_LLM` is false or no key is configured.
- `OpenAICompatibleProvider` — `httpx` client, configurable
  `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY`, hard timeouts, bounded
  input and `max_tokens`, normalized error types, no silent fallback to
  another provider.

Provider selection is explicit in configuration, never auto-detected at
runtime.

## Consequences

- `test_no_network_in_mock_mode` can assert zero socket usage.
- Swapping providers is a configuration change, not a code change.
- Failures surface as typed errors handled by the fail-closed gate.
