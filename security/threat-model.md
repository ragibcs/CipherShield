# Threat Model — CipherShield AI

Scope: the competition MVP. This document is intentionally honest about
what the system does **not** protect against.

## 1. Assets

| Asset | Sensitivity | Location |
|---|---|---|
| Vault encryption key (VEK) | Critical | Backend key provider: env var or local key file (0600) |
| Provider API key (`LLM_API_KEY`) | Critical | Backend environment only |
| Raw secret → placeholder mapping | High | Encrypted vault records (AES-256-GCM) |
| Sanitized prompts | Medium | Sent to external provider after policy approval |
| Model responses | Medium | Scanned for secret disclosure before display |
| Audit events | Low (must stay secret-free) | SQLite / JSONL audit store |

## 2. Trust boundaries

```
[ Browser ]  --untrusted-->  [ FastAPI backend ]  --sanitized only-->  [ External LLM provider ]
                                   |        ^
                                   v        |
                            [ Encrypted vault ]   [ Audit store: secret-free metadata ]
```

- **Browser** — untrusted. Never receives provider credentials, vault keys,
  or raw mappings.
- **Backend** — trusted for the MVP. Must not leak secrets through logs,
  exceptions, tracebacks, or debug endpoints.
- **Vault** — ciphertext only; key is not stored beside ciphertext.
- **External provider** — outside the boundary. May retain or inspect
  submitted prompts under its own terms.
- **Audit store** — minimal metadata only.

## 3. Adversaries and goals

| Adversary | Goal | Primary control |
|---|---|---|
| Curious/compromised LLM provider | Harvest usable secrets from prompts | Detection + tokenization before send; outbound gate on exact serialized payload |
| Malicious model output | Reflect a known secret back to the user | Response inspection against known originals and configured patterns |
| Prompt injection in incident text | Extract system secrets or trigger tools | Instruction/data separation, tool allowlist deny-by-default, no secret material in prompt |
| Local attacker without key access | Read vault mappings from disk | AES-256-GCM, key file kept outside the ciphertext store |
| Tampering with stored ciphertext | Undetected mapping modification | GCM authentication tag; modified ciphertext fails verification |
| Confused deputy / stray code path | Send unapproved request externally | `ALLOW_EXTERNAL_LLM=false` default; fail-closed policy gate; provider call counter |

## 4. Out of scope (stated honestly)

- A fully compromised host, kernel, or privileged backend process.
- Formal "zero knowledge" of the provider — the provider sees whatever
  passes the gate.
- Detection of every possible secret or prompt injection (regex detection
  is incomplete by design and documented as such).
- Multi-tenant isolation, cloud KMS, DDoS, and physical attacks.
- Rewrite-proof audit logs: the hash chain is tamper-*evident* for
  appended/edited entries, but an administrator who can rewrite the whole
  chain and an external anchor is out of scope.

## 5. Residual risks

1. Unknown secret formats leak unless a detector pattern matches.
2. Semantic leakage (model inferring a secret from context) is not
   detected structurally.
3. The local demo key file protects against casual disk reads, not an
   attacker with the user's OS account.
4. Denial of service against the local service is not mitigated beyond
   input size limits and rate limiting.
