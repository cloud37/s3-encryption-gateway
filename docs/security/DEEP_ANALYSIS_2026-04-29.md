# Deep Security Analysis — S3 Encryption Gateway (_post-v0.6.2, pre-v1.0_)

**Analysis Date:** 2026-04-29  
**Scope:** Full repository audit of the current `HEAD` (25 security commits since `s3-encryption-gateway-0.6.2`)  
**Methodology:** Static code analysis, commit archaeology, cross-reference with `docs/issues/v1.0-issues.md` and `docs/issues/v1.0-deep-analysis-findings.md`.

---

## 1. Executive Summary

Since the `v0.6.2` release, the project has undergone an **extraordinary security hardening sprint** — 25 dedicated security commits implementing 28 tracked issues (V1.0-SEC-1 through V1.0-SEC-28). The vast majority of findings from the v0.6 security audit and the subsequent deep-analysis have been **correctly and thoroughly addressed**. Code quality is high, tests are comprehensive (including race-detector passes), and the engineering discipline around security issues (implementation guides, test criteria, CVSS estimates) is well above industry average.

**However, two P1 security issues from the v1.0 tracker remain unimplemented, and the legacy (non-chunked) encryption paths retain a known but unaddressed memory-exhaustion DoS vector.** These do not negate the impressive progress, but they prevent a clean "production-ready" security statement without qualification.

---

## 2. What Was Fixed (Comprehensive Review)

### Cryptographic Hardening (SEC-1, SEC-3, SEC-5, SEC-12, SEC-15, SEC-19, SEC-25)

| Issue | Status | Verification |
|-------|--------|--------------|
| **SEC-1** — Password `[]byte` zeroization, DEK zeroization, constant-time audit | ✅ Complete | `engine.password` is `[]byte` with `Close()` zeroization; `mpuDecryptReader.returnEncBuf()` zeroizes `r.dek`; `subtle.ConstantTimeCompare` and `hmac.Equal` used throughout; debug output redacted |
| **SEC-3** — Debug `fmt.Printf` of crypto params removed | ✅ Complete | All `debug.Enabled()` blocks in `engine.go` use `slog.Debug` with lengths only; startup warning emitted |
| **SEC-5** — Integer overflow in `calculateEncryptedByteRange` | ✅ Complete | Pre-cast overflow guards, `int64` promotion, post-calculation sanity checks; tests for edge cases |
| **SEC-12** — Key padding creates catastrophically weak keys | ✅ Complete | All `copy(adjustedKey[len(key):], ...)` blocks replaced with hard errors in KMS branches and defensive assertions in PBKDF2 branches |
| **SEC-15** — KMS key length not validated in chunked/range decrypt | ✅ Complete | `decryptChunked` (line 1190) and `DecryptRange` (line 1353) both validate `len(key) != keySize` after `UnwrapKey` |
| **SEC-19** — Password loaded into immutable `string` | ✅ Complete | `cmd/server/main.go` reads password into `[]byte` via `os.ReadFile`, copies defensively, zeroizes source; no intermediate `string` |
| **SEC-25** — MPU hardcodes AES256-GCM | ✅ Complete | `initMPUEncryptionState` calls `engine.PreferredAlgorithm()`; `NewMPUPartEncryptReader` and `NewMPUDecryptReader` dispatch through `createMPUAEADCipher` supporting both AES-GCM and ChaCha20-Poly1305 |

### Network & Transport Security (SEC-6, SEC-8, SEC-9, SEC-16, SEC-17, SEC-21, SEC-22, SEC-23, SEC-24)

| Issue | Status | Verification |
|-------|--------|--------------|
| **SEC-6** — XFF header spoofing | ✅ Complete | `TrustedProxies` CIDR list parsed; `getClientIP` and `getClientKey` use `util.IPExtractor`; default empty (fail-safe) |
| **SEC-8** — Audit sink HTTP transport unhardened | ✅ Complete | `NewHTTPSinkWithConfig` sets `TLSHandshakeTimeout`, `MaxConnsPerHost`, `IdleConnTimeout`; dropped-events counter implemented |
| **SEC-9** — `InsecureSkipVerify` silent in production | ✅ Complete | `ERROR`-level startup warning emitted in both `crypto_factory.go` and `mpu/state.go` |
| **SEC-16** — Tracing middleware blindly trusts XFF | ✅ Complete | `TracingMiddleware` accepts `*util.IPExtractor`; `getRemoteAddr` delegates to `extractor.GetClientIP(r)` or falls back to `r.RemoteAddr` |
| **SEC-17** — OTel spans leak presigned URL signatures | ✅ Complete | `semconv.HTTPURL` uses `scheme://host/path` only (no query string); `http.query` separately redacted when `redactSensitive=true` |
| **SEC-18** — Debug `fmt.Printf` in S3 client leaks metadata | ✅ Complete | `client.go` `fmt.Printf` blocks replaced with `slog.Debug`; only lengths logged; no preview variables remaining |
| **SEC-21** — Admin listener lacks `MaxHeaderBytes` | ✅ Complete | `internal/admin/server.go` sets `MaxHeaderBytes: 64*1024` (configurable) |
| **SEC-22** — Admin token re-read on every request | ✅ Complete | Token cached in `Server.tokenCache` with `sync.RWMutex`; `tokenRefreshLoop` re-reads every 30s with permission re-validation |
| **SEC-23** — TLS allows weak default cipher suites | ✅ Complete | Both `buildAdminTLSConfig()` and `buildCosmianTLSConfig()` explicitly set `CipherSuites` (AES-256-GCM, ChaCha20-Poly1305) and `CurvePreferences` (X25519, P-256) |
| **SEC-24** — `RecoveryMiddleware` innermost | ✅ Complete | Applied **last** (outermost) in `cmd/server/main.go` so it wraps all other middleware; panic-injection tests passing |
| **SEC-28** — Admin token file TOCTOU via symlinks | ✅ Complete | `os.Lstat` used for permission check; symlinks explicitly rejected with error |

### Authentication & Authorization (SEC-11)

| Issue | Status | Verification |
|-------|--------|--------------|
| **SEC-11** — SigV4 header auth missing clock-skew / replay window | ✅ Complete | `ValidateSignatureV4` parses `X-Amz-Date` for ALL requests (header and presigned); rejects if `|time.Since(t)| > defaultClockSkew` (15 min); presigned expiry unchanged |

**Correction (GH-345, 2026-10-01):** The verification above describes the
April implementation, not the current request-time contract. Applying the
symmetric window to presigned URLs shortened their signed lifetime; the default
was subsequently reduced to five minutes. GH-345 keeps symmetric skew checks
for header authentication, limits only future skew for SigV4 presigned URLs,
and requires a signed 1–604800-second expiry. See the
[current contract](../S3_API_IMPLEMENTATION.md#sigv4-request-time-and-presigned-expiration).

### Resource Exhaustion & DoS Mitigation (SEC-10, SEC-13, SEC-14, SEC-20)

| Issue | Status | Verification |
|-------|--------|--------------|
| **SEC-10** — Rate limiter timing side-channel | ✅ Complete | `minAllowTime = 50µs` spin-wait deferred guarantee; benchmark verifies P99 impact < 0.1 ms |
| **SEC-13** — Unbounded goroutine spawning in audit `BatchSink` | ✅ Complete | Bounded semaphore (`flushSem chan struct{}`); `maxConcurrentFlushes` configurable (default 4); saturation drops events and increments `droppedAuditEventsTotal` |
| **SEC-14** — Chunked encrypt reads entire plaintext into memory | ✅ Complete | `encryptChunked` passes raw `io.Reader` directly to `newChunkedEncryptReader`; no `io.ReadAll` |
| **SEC-20** — Cached policy engines never closed | ✅ Complete | TTL cache (1h TTL, 5m sweep); `Close()` called on eviction and shutdown; tested under `-race` |

### Observability & Operational Security (SEC-26)

| Issue | Status | Verification |
|-------|--------|--------------|
| **SEC-26** — Audit `FileSink` world-readable permissions | ✅ Complete | Default `0600`; `NewFileSinkWithMode` allows override; `//nolint:gosec` annotations with justification |

---

## 3. Remaining Open Issues (Pre-v1.0 Blockers)

### 🔴 [V1.0-SEC-2] HKDF-based Chunk-IV Derivation — **NOT IMPLEMENTED**

**Severity:** P1 (Cryptographic inconsistency)  
**Location:** `internal/crypto/chunked.go` lines 114-127  
**Current State:**
```go
func (r *chunkedEncryptReader) deriveChunkIV(chunkIndex int) []byte {
    // XOR the last 4 bytes with chunk index to derive unique IV per chunk
    ...
}
```
The chunked encrypt/decrypt paths still derive per-chunk IVs by **XOR-ing the chunk index into the last 4 bytes of `baseIV`**. While functionally correct (each object has a random 96-bit `baseIV`; birthday-bound collisions between objects are not possible), this is cryptographically inconsistent with `mpu_iv.go`, which correctly uses **HKDF**.

**Risk:** Low in practice (no known attacks against this specific XOR construction with random base IVs), but it represents a **design inconsistency** and a departure from standard practice. The v1.0 tracker specifies a non-breaking migration path using a metadata flag (`MetaIVDerivation = "hkdf-sha256"`) with a dual-read window.

**Fix Required:**
1. Implement `deriveChunkIVHKDF` using `hkdf.Expand(sha256.New, baseIV, info)`.
2. Set `MetaIVDerivation = "hkdf-sha256"` on encrypt.
3. In decrypt, read the flag and dispatch to HKDF or XOR (legacy fallback).
4. Mark XOR path as `// Deprecated: remove no earlier than v3.0`.

---

### 🔴 [V1.0-SEC-4] AAD Fallback Restricted to Explicitly Marked Legacy Objects — **NOT IMPLEMENTED**

**Severity:** P1 (Integrity bypass)  
**Location:** `internal/crypto/engine.go` line 712  
**Current State:**
```go
// Attempt decrypt with current key and AAD
plaintext, openErr := gcm.Open(nil, iv, ciphertext, aad)
if openErr != nil {
    // Backward compatibility: try without AAD
    if pt, err2 := gcm.Open(nil, iv, ciphertext, nil); err2 == nil {
        plaintext = pt
        openErr = nil
    }
}
```
The AAD fallback is **unconditionally executed** for any object that fails AAD decryption. This means an attacker with backend write access can strip/tamper with metadata, and the gateway will silently fall back to no-AAD decryption — **bypassing the AAD integrity check**.

**Risk:** Medium. Requires attacker access to backend storage or metadata. But if gained, it allows undetected ciphertext tampering.

**Fix Required:**
1. Introduce metadata constant `MetaLegacyNoAAD = "x-amz-meta-enc-legacy-no-aad"`.
2. Encrypt path: new objects do NOT receive this flag.
3. Decrypt path: only execute the `gcm.Open(nil, iv, ciphertext, nil)` fallback when `metadata[MetaLegacyNoAAD] == "true"`.
4. Document breaking change for very old objects without the flag.

---

### 🟡 [V1.0-SEC-27] Metadata Fallback Path Double-Buffering — **PARTIALLY ADDRESSED**

**Severity:** P2 (Memory DoS)  
**Location:** `internal/crypto/engine.go` lines 1033-1036, 1048-1053  
**Current State:** The `encryptChunkedWithMetadataFallback` method still accumulates the full chunked ciphertext into a `bytes.Buffer` before constructing the final AEAD payload:
```go
var chunkedBuf bytes.Buffer
if _, err := io.Copy(&chunkedBuf, chunkedReader); err != nil { ... }
chunkedData := chunkedBuf.Bytes()
// ... then copies into another buffer `dataToEncrypt`
```
While the comment claims "No plaintext buffer is held — only the encrypted output is accumulated," the ciphertext is still fully buffered, and the outer `Seal` call creates a second full-size buffer. Peak memory remains roughly `2× object size` for this code path.

**Mitigation:** The fallback path is only triggered when metadata exceeds provider header limits (uncommon for typical objects). The primary chunked path (SEC-14) is fully streaming.

---

## 4. New Findings from This Analysis

### 🟡 NEW-01: Legacy (Non-Chunked) Paths Still Fully Buffer Plaintext/Ciphertext

**Severity:** Medium (DoS via memory exhaustion)  
**Locations:**
- `internal/crypto/engine.go:348` — `Encrypt` legacy path: `plaintext, err := io.ReadAll(reader)`
- `internal/crypto/engine.go:503` — Compress-then-encrypt: `dataToEncrypt, err := io.ReadAll(toEncryptReader)`
- `internal/crypto/engine.go:668` — `Decrypt` legacy path: `ciphertext, err := io.ReadAll(reader)`
- `internal/crypto/engine.go:1599` — `decryptWithMetadataFallback`: `ciphertext, err := io.ReadAll(reader)`
- `internal/crypto/decrypt_reader.go:19` — `decryptReader`: `ciphertext, err := io.ReadAll(source)`

**Analysis:** The chunked encryption path was correctly fixed (SEC-14) to stream without full materialization. However, when chunked mode is **disabled** (default for backward compatibility, or explicitly configured), the legacy paths still call `io.ReadAll(reader)` on the entire object. For a 5 GB upload, the gateway allocates 5 GB of heap. An attacker can trigger remote memory exhaustion simply by uploading or downloading large objects.

**Recommendation:** If chunked mode is intended to be the production default for v1.0, document that non-chunked mode is **deprecated for large objects** and emit a startup warning when `chunkedMode = false`. Alternatively, implement streaming encryption for the legacy path ( harder due to the need for `gcm.Seal` on a `[]byte`, but using `io.Pipe` or a streaming AEAD wrapper is possible).

**Current defense:** The chunked mode is configurable, and operators should enable it for production. However, the default configuration is not fail-safe.

---

### 🟢 NEW-02: Admin Auth Prefix Check Not Constant-Time

**Severity:** Very Low (Information disclosure)  
**Location:** `internal/admin/auth.go:43`
```go
if authHeader[:len(prefix)] != prefix {
```
This string prefix comparison is not constant-time. While the actual token comparison (`subtle.ConstantTimeCompare`) is correct, a determined attacker might theoretically measure timing differences between a missing prefix and an invalid token. In practice, the network jitter dominates any measurable signal.

**Recommendation:** Replace with `strings.HasPrefix` (which is not constant-time either) or a byte-by-byte comparison. Given the negligible practical risk, this is a hygiene issue, not a blocker.

---

### 🟡 V1.0-SEC-29: `upload_part_copy.go` Full-Buffering on Large Part Copies

**Severity:** Low-Medium (DoS / memory pressure)  
**Location:** `internal/api/upload_part_copy.go` lines 532, 587, 730, 771, 790, 818  
**Analysis:** Multiple `io.ReadAll` calls exist in the upload-part-copy handler, some guarded by `io.LimitReader` with `maxLegacyCap+1` (line 730) but others unbounded (line 532: `decryptedBytes, err := io.ReadAll(decryptedReader)`). If an attacker can craft a cross-bucket copy of a very large object, this could exhaust memory.

**Recommendation:** Audit all `io.ReadAll` in the API layer and ensure they are bounded by reasonable limits or streamed.

---

### 🟢 NEW-04: `ValidateSignatureV4` Error Messages Distinguish Failure Modes

**Severity:** Very Low (Enumeration aid)  
**Location:** `internal/api/auth.go`  
**Analysis:** Different error strings are returned for "missing timestamp", "invalid timestamp format", "outside clock skew window", and "signature mismatch". An attacker could use these to iteratively debug a forged signature. However, the errors are returned as HTTP 400/403 responses, which is standard behavior.

**Recommendation:** For a hardened v1.0, consider collapsing all validation failures into a single opaque error: `"authentication failed"`. This is defense-in-depth, not a critical fix.

---

## 5. Security Standards Statement

### Overall Rating: **B+ (Approaching A- with two P1 fixes)**

The S3 Encryption Gateway has undergone a **remarkable security transformation** since v0.6.2. The development team has demonstrated:

- **Systematic threat modeling:** Issues are tracked with CVSS estimates, implementation guides, and verification criteria.
- **Fail-closed posture:** Insecure defaults emit `ERROR`-level warnings; misconfigurations refuse to start rather than silently degrade (e.g., encrypted MPU without Valkey).
- **Cryptographic diligence:** Constant-time comparisons, `crypto/rand` exclusivity, memory zeroization, and defensive size assertions are now standard practice.
- **Observability hygiene:** Debug logging no longer leaks key material; trace spans redact sensitive query parameters.
- **Resource bounds:** Rate limiters, audit semaphores, connection pools, and header-size limits are all bounded.

### What Prevents an "A" Rating

1. **Unconditional AAD fallback (SEC-4):** A correct attacker with backend access can bypass integrity checks on any object. This is a genuine integrity failure, not just a theoretical concern.
2. **Legacy-path `io.ReadAll` (NEW-01):** The non-chunked encryption/decryption paths still fully materialize objects in memory. In a security product, the default code path should not have a trivial remote memory-exhaustion vector.
3. **Inconsistent IV derivation (SEC-2):** While low-risk, the XOR-based chunk IV derivation is an outlier in an otherwise standards-compliant cryptographic codebase.

### What Would Achieve an "A" Rating

- Implement V1.0-SEC-2 and V1.0-SEC-4.
- Either make chunked mode the **default and only** mode for v1.0, or add a startup warning when chunked mode is disabled.
- Add `govulncheck`, `gosec`, and container scanning to CI (V1.0-OPS-2).
- Publish `SECURITY.md` with responsible disclosure guidelines.

---

## 6. Detailed Cross-Reference: Tracker vs. Reality

| Tracker ID | Title | Claimed Status | Verified Status | Discrepancy? |
|------------|-------|----------------|-----------------|--------------|
| SEC-1 | Zeroization / crypto hygiene | ✅ Done | ✅ Done | None |
| SEC-2 | HKDF chunk-IV derivation | ⬜ Open | ⬜ Open | None (known) |
| SEC-3 | Remove debug logging of crypto params | ✅ Done | ✅ Done | None |
| SEC-4 | Restrict AAD fallback | ⬜ Open | ⬜ Open | None (known) |
| SEC-5 | Integer overflow in range calc | ✅ Done | ✅ Done | None |
| SEC-6 | XFF spoofing | ✅ Done | ✅ Done | None |
| SEC-7 | `math/rand` → `crypto/rand` | ✅ Done | ✅ Done | None |
| SEC-8 | Harden HTTP transport for audit | ✅ Done | ✅ Done | None |
| SEC-9 | `InsecureSkipVerify` warning | ✅ Done | ✅ Done | None |
| SEC-10 | Rate limiter timing side-channel | ✅ Done | ✅ Done | None |
| SEC-11 | SigV4 clock-skew / replay | ✅ Done | ✅ Done | None |
| SEC-12 | Key padding weakens keys | ✅ Done | ✅ Done | None |
| SEC-13 | Unbounded goroutines in BatchSink | ✅ Done | ✅ Done | None |
| SEC-14 | Chunked encrypt `io.ReadAll` | ✅ Done | ✅ Done | None |
| SEC-15 | KMS key length in chunked/range | ✅ Done | ✅ Done | None |
| SEC-16 | Tracing XFF trust | ✅ Done | ✅ Done | None |
| SEC-17 | OTel span URL leak | ✅ Done | ✅ Done | None |
| SEC-18 | S3 client debug printf | ✅ Done | ✅ Done | None |
| SEC-19 | Password in `string` | ✅ Done | ✅ Done | None |
| SEC-20 | Engine cache never closed | ✅ Done | ✅ Done | None |
| SEC-21 | Admin `MaxHeaderBytes` | ✅ Done | ✅ Done | None |
| SEC-22 | Admin token re-read | ✅ Done | ✅ Done | None |
| SEC-23 | TLS weak cipher suites | ✅ Done | ✅ Done | None |
| SEC-24 | RecoveryMiddleware ordering | ✅ Done | ✅ Done | None |
| SEC-25 | MPU hardcodes AES-GCM | ✅ Done | ✅ Done | None |
| SEC-26 | FileSink `0644` permissions | ✅ Done | ✅ Done | None |
| SEC-27 | Metadata fallback double-buffer | ⬜ Open | 🟡 Partial | Partially mitigated |
| SEC-28 | Admin token symlink TOCTOU | ✅ Done | ✅ Done | None |

**Note:** The bottom tracking checklist in `v1.0-issues.md` erroneously marks SEC-16, SEC-17, SEC-18 as unchecked, but the individual issue sections and source code confirm they are fully implemented. This is a **documentation inconsistency**, not a code issue.

---

## 7. Recommendations for v1.0 Release

### Must-Fix (Block Release)
1. **[V1.0-SEC-4]** Restrict AAD fallback to `MetaLegacyNoAAD == "true"`. This is an integrity vulnerability with a straightforward, low-risk fix.

### Should-Fix (Release or v1.0.1)
2. **[V1.0-SEC-2]** Implement HKDF chunk-IV derivation with backward-compatible dual-read window.
3. **[NEW-01]** Emit a prominent startup warning when `chunkedMode = false` alerting operators to the memory-exhaustion risk for large objects.

### Should-Have (Process / CI)
4. **[V1.0-OPS-2]** Add `govulncheck` and `gosec` to CI; create `SECURITY.md`.
5. Fix the tracking checklist in `v1.0-issues.md` to accurately reflect SEC-16/17/18/28 as complete.

---

*End of Analysis*
