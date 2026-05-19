# ADR 0013: Self-Contained Envelope Encryption KEK Provider

**Status:** Accepted (v1.0)

**Context:**

The S3 Encryption Gateway's `KeyManager` interface can be backed by external
KMS providers (Cosmian KMIP, AWS KMS, HashiCorp Vault Transit). For air-gapped
deployments, resource-constrained environments, and operators who want to use
existing PKI infrastructure, an external KMS call is undesirable or infeasible.

The existing `memory` adapter uses RFC 3394 AES key-wrap with an in-memory
master key. While useful for testing, it lacks authenticated encryption
(AEAD) and has no asymmetric wrapping variant. Operators needing AES-GCM or
RSA-OAEP wrapping without a network KMS have no option today.

**Decision:**

Introduce a single `"self_contained"` registry adapter that supports two
wrapping modes:

1. **AES-256-GCM** (`AESKEKManager`) — symmetric wrapping with authenticated
   encryption. Uses a 12-byte random nonce per wrap call. Multiple versioned
   KEKs are stored in a `map[int][]byte`; unwrap tries the envelope's declared
   version first, then falls back to all known versions for dual-read rotation.
   Implements `RotatableKeyManager` for the admin rotation API.

2. **RSA-OAEP/SHA-256** (`RSAKEKManager`) — asymmetric wrapping. The public
   key is used for `WrapKey`, the private key for `UnwrapKey`. Minimum key
   size is 2048 bits. No `AddVersion` or rotation automation; multiple
   versions require separate manager instances.

Both managers:
- Accept key material via `"env:VAR"`, `"base64:..."`, or `"file:PATH"`
  references, never requiring key bytes in config files.
- Zeroize all key material on `Close()`.
- Are registered under the single name `"self_contained"`; the factory
  dispatches on a `"type"` field (`"aes"` or `"rsa"`).
- Satisfy `KeyManager` at compile time; `AESKEKManager` additionally
  satisfies `RotatableKeyManager`.

**Alternatives Considered:**

- **RFC 3394 key-wrap (as in `memory` adapter):** Already available. GCM is
  more widely implemented, provides AEAD, and follows the standard Go
  `cipher.AEAD` interface.

- **libsodium sealed-box:** Requires CGo dependency; not suitable for a pure-Go
  codebase.

- **age encryption:** Separate dependency; designed for file encryption rather
  than DEK wrapping.

- **Single adapter per mode:** Would require two registry names and duplicate
  factory boilerplate. A single name with a `"type"` discriminator is simpler.

**Consequences:**

Positive:
- No network calls for DEK wrapping/unwrapping.
- AES-GCM provides authenticated encryption; tampered ciphertext is detected.
- RSA-OAEP allows PKI integration without a network KMS.
- Thread-safe; all operations use `sync.RWMutex`.
- Full `ConformanceSuite` contract tests pass for `AESKEKManager`.

Negative:
- Operator is solely responsible for KEK backup. KEK loss = permanent DEK
  irrecoverability. Documented in ADR, README, and KMS_COMPATIBILITY.md.
- RSA private key zeroization is best-effort (Go's `big.Int` may retain
  internal copies). For higher-assurance deployments, the HSM adapter should
  be used.
- GCM nonce collision risk if `rand.Read` fails silently; `WrapKey` returns an
  error on `rand.Read` failure. Maximum safe object count per KEK is ~2^32.
- RSA does not support automated rotation; manual key pair replacement
  required.

**Security Properties:**

- AES-256-GCM: unique nonce per wrap; AEAD authentication tag prevents
  ciphertext tampering.
- RSA-OAEP: SHA-256 hash; minimum 2048-bit key; padding prevents
  deterministic encryption.
- No KEK material in logs, error messages, or `KeyEnvelope` fields.
- Zeroization on `Close()` for both AES and RSA key material.
- Thread safety via `sync.RWMutex`; `ctx.Err()` checked before lock
  acquisition.

**References:**

- NIST SP 800-38D (AES-GCM)
- NIST FIPS PUB 186-5 (RSA key size requirements)
- PKCS #1 v2.2, RFC 8017 (RSAES-OAEP)
- ADR 0007 — Admin API and Key Rotation
- `docs/plans/V1.0-KMS-4-plan.md`
