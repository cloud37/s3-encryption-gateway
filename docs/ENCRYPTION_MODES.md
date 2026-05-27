# Encryption Modes Guide

This document explains the three key-derivation and key-management paths available in the S3 Encryption Gateway, their security properties, and their performance impact.

## Benchmark Results

Results from `make benchmark-local` (5-second runs, 4 concurrent workers, three local
Testcontainer backends). Throughput ranges span the fastest three providers
(MinIO, RustFS, SeaweedFS); the slowest backend is excluded as it bottlenecks
at its own network ceiling rather than reflecting encryption cost.

### Chunked PutObject (1 MiB payload, single-object upload)

| Mode | Throughput (Mbps) | vs. PBKDF2 600k |
|------|--------------------:|:---:|
| PBKDF2-SHA256 600k iterations | 45–49 | 1× |
| PBKDF2-SHA256 100k iterations | 250–264 | 5.5× |
| argon2id (t=2, m=19456 KiB, p=1) | 199–209 | 4.4× |
| **AES-256-GCM KEK** (envelope) | 2387–3710 | 53–76× |
| RSA-OAEP/SHA-256 KEK (envelope) | 1705–2266 | 38–46× |
| Cosmian KMIP KMS (envelope) | 1949–3010 | 41–61× |

### Encrypted Multipart Upload (4 × 50 MiB parts)

| Mode | Throughput (Mbps) | vs. PBKDF2 600k |
|------|-------------------:|:---:|
| PBKDF2-SHA256 600k | 92–96 | 1× |
| PBKDF2-SHA256 100k | 192–224 | 2.1× |
| argon2id (t=2, m=19456 KiB, p=1) | 176–208 | 2.0× |
| AES-256-GCM KEK | 236–304 | 2.8× |
| RSA-OAEP/SHA-256 KEK | 240–292 | 2.7× |
| Cosmian KMIP KMS | 236–288 | 2.7× |

### RangedGet (200 KiB object, 5 sub-ranges)

| Mode | Throughput (Mbps) | vs. PBKDF2 600k |
|------|-------------------:|:---:|
| PBKDF2-SHA256 600k | 2.3–2.5 | 1× |
| PBKDF2-SHA256 100k | 13.4–13.8 | 5.5× |
| argon2id (t=2, m=19456 KiB, p=1) | 10.3–10.5 | 4.2× |
| AES-256-GCM KEK | 111–172 | 48–74× |
| RSA-OAEP/SHA-256 KEK | 97–111 | 41–47× |
| Cosmian KMIP KMS | 95–141 | 40–60× |

### Key observations

- **PBKDF2 600k RangedGet is unusable at scale**: 2.5 Mbps per client — KDF
  compute (78 ms p50) dominates. A single client cannot saturate a 10 Mbps
  link on ranged reads.
- **Envelope encryption is 50×+ faster than PBKDF2 600k** on single-object
  uploads. On RangedGet the gap widens to 70×.
- **KMS network overhead is negligible**: Cosmian KMIP over localhost adds
  ~15% vs local AES KEK in Chunked and is effectively identical in MPU. The
  KMIP round-trip costs ~100 μs — 800× less than PBKDF2 600k.
- **argon2id is 4.4× faster than PBKDF2 600k** for Chunked despite being
  memory-hard. PBKDF2's 600 000 SHA-256 iterations burn more CPU than
  argon2id's two-pass 19 MiB hash. argon2id obtains its security from memory
  hardness (resisting GPU/ASIC), not raw iteration count.

## Quick Comparison

| Mode | Request latency (p50) | Chunked throughput | Key source | FIPS 140-3 | Best for |
|------|----------------------|---------------------|------------|------------|----------|
| **PBKDF2 password-derived** | ~80 ms | 45–49 Mbps | Gateway password | ✅ Yes | Regulated environments that require FIPS approval and can tolerate latency |
| **argon2id password-derived** | ~19 ms | 199–209 Mbps | Gateway password | ❌ No | Air-gapped or password-only deployments that want maximum brute-force resistance |
| **Self-contained envelope** | < 2 ms | 2387–3710 Mbps | Locally-held AES-256 / RSA KEK, or external KMS | ✅ Yes (AES-GCM / RSA-OAEP) | Production deployments that need low latency without an external KMS |

## 1. PBKDF2 Password-Derived Keys

This is the default when no `key_manager` is configured. The gateway runs PBKDF2-SHA256 with **600 000 iterations** (up from the legacy 100 000, minimum value now) on every encrypt and decrypt call to turn the gateway password into a per-object AES-256 key.

### Why it is slow

PBKDF2 is intentionally compute-heavy to slow down password-guessing attacks. At 600 000 iterations a single derivation takes **~80 ms (p50)** on modern hardware. For a single `GetObject` or `DecryptRange` request that cost is paid **once per object**, capping throughput around **45–49 Mbps** (Chunked) or **2.5 Mbps** (RangedGet, where the KDF dominates the 200 KiB read). For multipart uploads the derivation runs **once per 50 MiB part**, limiting throughput to **92–96 Mbps**.

### When to use it

- Your compliance regime requires FIPS 140-3 validated primitives.
- You accept the latency trade-off in exchange for not managing a separate Key Encryption Key.

### Configuration

```yaml
encryption:
  password: "${ENCRYPTION_PASSWORD}"
  kdf:
    algorithm: pbkdf2-sha256
    pbkdf2:
      iterations: 600000
```

## 2. argon2id Password-Derived Keys

argon2id is a memory-hard password-hashing function (PHC 2015 winner). At OWASP-recommended parameters (t=2, m=19456 KiB, p=1) it is **~4× faster** per request than PBKDF2 600k (~19 ms vs ~80 ms), because PBKDF2 burns more CPU on raw iteration count. argon2id achieves its security margin by forcing attackers to spend 19 MiB of RAM per guess — a resource that GPUs and ASICs cannot scale as cheaply as CPU cycles.

### Why it is faster than PBKDF2 at equivalent security

argon2id obtains equivalent brute-force resistance to 600 000 PBKDF2 iterations with only 2 passes over 19 MiB of memory. On a modern CPU this costs ~19 ms per derivation vs. ~80 ms for PBKDF2. The memory-hardness prevents attackers from parallelising guesses on GPU/ASIC hardware, so you do not need to burn as many CPU cycles to achieve the same security level. The performance benefit is most visible on **Chunked PutObject (199–209 Mbps vs 45–49 Mbps)** and **RangedGet (10.5 Mbps vs 2.5 Mbps)**.

### FIPS status

There is **no FIPS 140-3 validated implementation of argon2id**. If you build the gateway with `-tags fips`, `algorithm: argon2id` is rejected at startup.

### When to use it

- You want the strongest password-hashing defence available today.
- FIPS compliance is not required.
- You are switching from PBKDF2 and want better throughput without deploying a key manager.

### Configuration

```yaml
encryption:
  password: "${ENCRYPTION_PASSWORD}"
  kdf:
    algorithm: argon2id
    argon2id:
      time: 2
      memory: 19456
      threads: 1
```

## 3. Self-Contained Envelope Encryption

Introduced in v0.9 (issue `V1.0-KMS-4`), this mode removes the password-derivation step from the **per-request hot path** entirely.

### How it works

1. The operator generates a single 256-bit Key Encryption Key (KEK) and configures it in the gateway.
2. At encrypt time the gateway generates a fresh random Data Encryption Key (DEK), encrypts the object with the DEK, then **wraps the DEK with the KEK** using fast AES-256-GCM (or RSA-OAEP).
3. At decrypt time the gateway **unwraps the DEK** with the KEK — again fast AES-GCM — and decrypts the object.

The KEK is loaded once at startup and kept in memory. No KDF runs per request.

### Performance impact

- Key wrap / unwrap: < 2 ms (AES-GCM is hardware-accelerated on modern x86_64 and ARM64).
- Removes the ~80 ms PBKDF2 penalty entirely.
- **Chunked throughput**: 2387–3710 Mbps (AES KEK), 1705–2266 Mbps (RSA KEK), 1949–3010 Mbps (Cosmian KMIP KMS). All three variants are functionally identical on the hot path — DEK wrap/unwrap is a single AES operation regardless of whether the KEK is local or fetched from a KMS.
- **MPU throughput**: 236–304 Mbps across all three KEK variants. The KMS path (288 Mbps) is indistinguishable from local AES KEK (304 Mbps) — the ~100 μs KMIP round-trip is invisible at MPU part sizes.
- **RangedGet throughput**: 95–172 Mbps across all KEK variants. KMS adds no measurable overhead vs local KEK; the spread is dominated by backend S3 provider latency, not crypto.

### FIPS status

The self-contained provider uses standard AES-256-GCM and RSA-OAEP-SHA256, both of which are FIPS-approved algorithms. When the gateway is built with `-tags fips`, Go routes AES-GCM through the FIPS-validated module.

> **Caveat:** FIPS compliance also depends on how the KEK is generated, stored, and accessed. A KEK generated by `openssl rand -base64 32` and injected via environment variable satisfies the primitive requirement, but operators in regulated environments should still follow their key-management policy (HSM storage, key ceremony, access logging, etc.).

### When to use it

- Low-latency S3 workloads (range GETs, streaming, high RPS).
- Air-gapped or resource-constrained environments without an external KMS.
- Any production deployment where 50 ms of crypto overhead per request is unacceptable.

### Configuration (AES KEK)

```yaml
encryption:
  password: "${ENCRYPTION_PASSWORD}"   # still needed for legacy reads
  key_manager:
    enabled: true
    provider: self_contained
    self_contained:
      type: aes
      aes:
        active_version: 1
        keys:
          - version: 1
            key_source: "env:S3EG_AES_KEK"   # base64-encoded 32-byte key
```

### Configuration (RSA KEK)

```yaml
encryption:
  password: "${ENCRYPTION_PASSWORD}"
  key_manager:
    enabled: true
    provider: self_contained
    self_contained:
      type: rsa
      rsa:
        private_key_source: "file:/run/secrets/kek_rsa.pem"
        key_version: 1
```

See [`KMS_COMPATIBILITY.md`](KMS_COMPATIBILITY.md) for full key-source formats and rotation details.

## Migration Between Modes

### Password-derived → Self-contained envelope

1. Generate a 32-byte KEK: `openssl rand -base64 32`.
2. Configure `kms.provider: self_contained` with the new KEK.
3. Restart the gateway.
4. **New objects** use envelope encryption (fast).
5. **Old objects** remain readable via the backward-compatible password-derived path.
6. Re-upload old objects lazily if you want to eliminate the PBKDF2 latency entirely.

### PBKDF2 → argon2id

1. Set `encryption.kdf.algorithm: argon2id`.
2. Restart the gateway.
3. **New objects** use argon2id.
4. **Old objects** are still readable — the KDF parameters are stored in metadata (`x-amz-meta-encryption-kdf-params`) and the gateway selects the correct function automatically.

> **Note:** Switching from PBKDF2 600k to argon2id gives a ~4× throughput improvement while maintaining equivalent brute-force resistance. It is a throughput upgrade, not a downgrade.

## Key Takeaways

- **PBKDF2 600k is the slowest option** at ~80 ms per derivation (45–49 Mbps Chunked, 2.5 Mbps RangedGet). It is FIPS-compatible but unsuitable for latency-sensitive or high-throughput workloads.
- **argon2id is ~4× faster than PBKDF2 600k** at equivalent brute-force resistance (~19 ms, 199–209 Mbps Chunked). Not FIPS-approved but a substantial throughput improvement for password-only deployments.
- **Envelope encryption (AES KEK / RSA KEK / Cosmian KMIP) removes KDF from the hot path entirely.** Throughput is 50–76× higher than PBKDF2 600k for Chunked and 70× higher for RangedGet. The KMIP network overhead to an external KMS is imperceptible (~100 μs).
- **PBKDF2 100k is a low-security floor** included only for benchmark comparison. It is not recommended for production — 100 000 iterations provides minimal brute-force resistance.
- You can switch modes without losing access to existing data. The gateway keeps enough metadata to decode objects written under any of the three schemes.
