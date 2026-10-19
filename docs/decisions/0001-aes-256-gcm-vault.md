# Decision 0001: AES-256-GCM from `cryptography` for the vault

## Status

Accepted

## Context

Vault records hold the raw-secret → placeholder mapping. Recoverable
encryption with integrity is required, and the implementation must not
invent cryptography.

## Decision

Use `cryptography.hazmat.primitives.ciphers.aead.AESGCM` with a 256-bit
key and a fresh 96-bit random nonce per encryption. Record layout is
versioned:

```
ciphershield.v1 | 12-byte nonce | ciphertext+tag (AES-256-GCM)
```

Base64url encoding is applied for storage. The key is loaded through a
`KeyProvider` interface (env var or 0600 key file in the MVP, KMS later)
and never stored with the ciphertext.

## Consequences

- Tampered ciphertext or tag fails verification → fail-closed error.
- Nonce uniqueness is guaranteed by `os.urandom(12)` per operation.
- A production KMS can be added by implementing `KeyProvider` only.
