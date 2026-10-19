# Key Management — CipherShield AI

Implements merged-plan requirement **B2**. Three roles are distinct and
never share a value:

| Role | Name in code | Where it lives | Ever sent to the LLM? |
|---|---|---|---|
| Vault encryption key (VEK) | `CIPHERSHIELD_KEY` env var, or `KeyFileProvider` file | Backend only (env var, or local file created `0600`) | **No** — invariant `INV-01` |
| LLM provider API credential | `LLM_API_KEY` | Backend environment only; registered with the log scrubber | **No** — it authenticates the connection; the key itself is never placed in message content (`INV-02`) |
| Application master key | *not used in the MVP* | — | — |

**No key hierarchy claim:** the MVP encrypts vault records directly with
the VEK. There is no wrapping key and no derived key hierarchy — we do
not describe the single VEK as a complex hierarchy. If a master key that
wraps a data-encryption key is ever introduced, the wrapping relationship
must be implemented and tested before any hierarchy language appears in
this repo.

## Generation and storage

- Keys are 32 bytes from a cryptographically secure source
  (`os.urandom` / `secrets`). Never hardcoded, never committed; `.env`
  and `secrets/` are gitignored (`.env.example` holds placeholders only).
- `KeyFileProvider` creates the local key file with mode `0600`, refuses
  group/other-readable files (it re-chmods and warns), and keeps the file
  outside the ciphertext store (`services/api/app/services/vault/key_provider.py`).
- The key file is excluded from Docker build contexts by every
  `.dockerignore` in this repo; production injects `CIPHERSHIELD_KEY` as
  an environment secret.

## Rotation and invalid-key behavior (documented; automated rotation is out of MVP scope)

| Event | Behavior |
|---|---|
| Rotate the env key / key file | Existing records were sealed with the old key: AES-GCM authentication fails and the store **fails closed** with a secret-free `VaultError`. Rotation therefore requires re-sealing records under the new key (export/decrypt under old → re-encrypt under new), which is deliberately not automated in the MVP. |
| Wrong key supplied | Decryption rejected (`test_vault.py::test_wrong_key_rejected`); no plaintext or key material in the error. |
| Malformed / short key | Rejected at load time (`test_vault.py::test_invalid_key_size_rejected`, `EnvKeyProvider` length check). |
| Tampered ciphertext or tag | GCM verification fails, operation rejected (`test_vault.py::test_tampered_ciphertext_rejected`, lab scenario `tampered_ciphertext`). |
| Key file deleted | `KeyFileProvider` generates a fresh key with `0600` and a warning; old records then fail closed as with a rotation. |

## Honesty

These controls assume a trusted backend. A compromised host, kernel, or
privileged backend process can read the VEK from memory — see
`security/threat-model.md` §4. Keys never appear in prompts, API
responses, audit events, logs, screenshots, or the frontend bundle.
