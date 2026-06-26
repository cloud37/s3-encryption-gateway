# ADR 0014 — State-Key Derivation Hardening: Envelope-Encrypted State DEK

- **Status:** Accepted
- **Date:** 2026-06-26
- **Driver:** V1.0-SEC-30 (Security Audit 2026-06-23 Finding B)
- **Supersedes:** The HKDF-Extract derivation in `deriveStateAEADKey` (V0.6-SEC-3 / ADR 0009)
- **References:**
  - ADR 0009 — Encrypted Multipart Uploads (`0009-encrypted-multipart-uploads.md`)
  - ADR 0013 — Self-Contained Envelope KEK (`0013-self-contained-envelope-kek.md`)
  - Security Audit 2026-06-23 (Vuln-2, Vuln-3)
  - RFC 5869 §2.2: HKDF-Extract is designed for uniformly-random input keys

## Context

The 2026-06-23 security audit identified three findings in the MPU state
encryption path. This ADR covers the remediation for Finding B (state KDF) and
Finding C (fail-open plaintext fallback), and the rationale for the chosen
approach.

### Finding B — Valkey state-encryption KDF uses HKDF-Extract on a password with no work factor (HIGH)

`internal/mpu/state.go` derived the 32-byte AES-256 key protecting MPU state at
rest via a single `hkdf.Extract` pass:

```go
func deriveStateAEADKey(password string) []byte {
    salt := []byte("s3eg-mpu-state-v1")
    extracted := hkdf.Extract(sha256.New, []byte(password), salt)
    key := make([]byte, 32)
    copy(key, extracted)
    return key
}
```

Three problems:
1. **Wrong primitive.** HKDF-Extract is designed for uniformly-random input
   keys (RFC 5869 §2.2). The input is a human passphrase.
2. **No work factor.** A single SHA-256 compression offers no resistance to
   offline dictionary attack.
3. **Hardcoded cross-deployment salt.** Identical salt in every installation
   enables precomputation across the entire fleet.

The threat model in ADR 0009 explicitly considers read-only Valkey
exfiltration, so offline attack is in scope.

### Finding C — Silent plaintext fallback on Valkey state AEAD failure (MEDIUM)

`Get` and `List` silently fell back to treating the raw ciphertext as plaintext
JSON when `DecryptState` returned an AEAD authentication failure, contradicting
the README's "fail-closed guarantees" table.

## Decision

### Envelope-encrypted state DEK (Finding B)

Replace the HKDF-Extract password-derived key with a **random 32-byte state DEK
wrapped by the existing `KeyManager`** — the same envelope pattern used for
object DEKs (ADR 0013). This:

1. Eliminates password-based key derivation from the state-encryption path.
2. Reuses the `KeyManager` infrastructure the operator already configured.
3. Incurs KDF/KMS cost only at startup (`WrapKey`/`UnwrapKey`), not per
   Valkey call.
4. Supports all KeyManager providers (self-contained AES/RSA, Cosmian KMIP,
   in-memory, HSM) and the `PasswordKeyManager` fallback.

The wrapped state DEK is persisted in Valkey under `mpu:state-key-wrapped`
using `SET NX` (atomic first-writer-wins across replicas). On restart, the
KeyManager unwraps it. Per-call `EncryptState`/`DecryptState` use the cached
state DEK directly (AES-GCM, microseconds).

### V1 legacy key for backward-compatible decrypt

Existing deployments have state encrypted with
`HKDF-Extract(SHA256, password, "s3eg-mpu-state-v1")`. After upgrade:

- New state is encrypted with the envelope state DEK.
- `DecryptState` tries the envelope state DEK first, then falls back to the
  V1 HKDF key (if configured via `legacyPassword`) for decrypting pre-upgrade
  state.
- Since MPU state has a 7-day TTL, all pre-upgrade state expires within 7 days.
  After that, the V1 key is dead code and can be removed in a future version
  (tracked as V1.0-SEC-32).

### Fail-closed with opt-in legacy plaintext (Finding C)

When `encryptState` is enabled and `DecryptState` fails, `Get`/`List` now
return an error — they do NOT fall back to plaintext unmarshal. A new config
flag `allow_legacy_plaintext_state` (default `false`) gates the one-time legacy
plaintext migration path, with a startup log warning and a metric.

## Rationale

### Why not PBKDF2?

The original draft (Rev 1) proposed PBKDF2-SHA256 600k for the state-encryption
key. Operator feedback:

1. **Architectural inconsistency.** The project uses an envelope-encryption
   pattern for object DEKs (ADR 0013). Adding a separate KDF for the state key
   introduces a second key-derivation mechanism for the same purpose.
2. **Unnecessary startup cost.** Even a one-time ~600ms PBKDF2 cost at startup
   is wasteful when the KeyManager already provides wrap/unwrap with the
   configured KDF cost (which is also PBKDF2 600k, but only at object-creation
   time, not at startup).

### Why not argon2id?

Argon2id is not FIPS-approved, and the project maintains a FIPS build profile
(ADR 0005). Using argon2id would break FIPS compliance for the state-encryption
path.

### Risk: wrapped state DEK lost if Valkey is wiped

The wrapped DEK is stored in Valkey (`mpu:state-key-wrapped`). If Valkey is
wiped, all in-flight MPU state is also lost (it lives in Valkey), so the
wrapped DEK is recovered alongside the state it protects — both are gone
together. For persistent backups, the wrapped DEK can be backed up as part of
Valkey snapshots.

## Consequences

### Positive

- **Stronger security:** random state DEK with no offline-dictionary-attack
  surface.
- **Architectural consistency:** same envelope pattern for state DEK and object
  DEKs.
- **No KDF on the hot path:** per-call encryption is AES-GCM, microseconds.
- **FIPS compliant:** AES-256-GCM + KeyManager wrapping (no argon2id).

### Negative

- **Requires a KeyManager.** Deployments with `encrypt_state: true` and no
  `key_manager` configured will fail to start. In password-only mode, the
  `PasswordKeyManager` wraps the state DEK automatically (one-time PBKDF2 cost
  at startup).
- **V1 legacy key adds complexity.** The `stateKeyV1` field and the
  try-envelope-then-V1 logic in `DecryptState` are temporary (7-day TTL
  window). Tracked as V1.0-SEC-32 for cleanup.
- **Breaking change:** `NewValkeyStateStore` signature changes to accept a
  `KeyManager` parameter. Only internal callers are affected.
