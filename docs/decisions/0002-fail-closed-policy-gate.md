# Decision 0002: Fail-closed outbound policy gate

## Status

Accepted

## Context

A policy bug, missing configuration, or evaluation exception must never
result in an unsanitized outbound request.

## Decision

Every outbound request passes through a single gate that:

1. serializes the **final** request body exactly as it will be sent,
2. re-scans it for forbidden categories and any known original secret,
3. allows the send only on an explicit, error-free approval,
4. returns `blocked` (with a reason code) on any error or ambiguity,
   incrementing the audit trail and the provider-call counter unchanged.

External sending additionally requires `ALLOW_EXTERNAL_LLM=true` **and**
validated provider configuration.

## Consequences

- Blocked requests provably make zero provider calls (asserted by tests
  and the provider-call counter).
- Misconfiguration degrades to "no analysis" instead of "leaky analysis".
- Cost: occasional false blocks, surfaced with actionable reason codes.
