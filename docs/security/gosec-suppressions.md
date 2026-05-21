# gosec Suppression Audit

This file documents every `#nosec` or `//nolint:gosec` suppression in the
codebase. Suppressions are grouped by gosec rule. Each entry includes the
file, line, rule, and a one-line justification.

**Policy:** Only HIGH-severity gosec findings that are proven false positives
are suppressed. Genuine HIGH findings must be fixed, not suppressed. This
file is regenerated after every significant gosec version bump to verify
that suppressions remain valid.

---

## G101 — Hardcoded Credentials (CWE-798)

All G101 findings are in test provider registration code. The "credentials"
are environment variable names, placeholder secrets for test containers, or
empty SDK-default endpoints. None are production secrets.

| File | Line | Justification |
|------|------|---------------|
| `test/provider/hetzner.go` | 19–29 | Test provider registration; values are env var names and default endpoints; annotated `// #nosec G101` |
| `test/provider/garage.go` | 73 | Test-only RPC secret for Garage container; annotated `// #nosec G101` |
| `test/provider/aws.go` | 20–33 | Test provider registration; annotated `// #nosec G101` |

---

## G115 — Integer Overflow Conversions (CWE-190)

All G115 findings are deliberate, safe integer conversions used in
cryptographic operations. None can overflow in practice because the source
values are bounded by small constants, chunk sizes, or object metadata limits.

### AES Key Wrap (RFC 3394) — `internal/crypto/keymanager_memory.go`

| Lines | Justification |
|-------|---------------|
| 270–276 | AES-KW wrap: `t = n*j + i + 1`, j ≤ 5, n ≤ 2^32, product fits uint64; the `byte(t >> N)` extracts one octet of the 8-byte counter |
| 312 | `uint64(n*j + i + 1)` — multiplication of small ints, no overflow; annotated `// #nosec G115` |
| 315–321 | AES-KW unwrap: same t computation; same justification |

### Metadata Length Encoding — `internal/crypto/engine.go`

| Lines | Justification |
|-------|---------------|
| 1202 | `uint32(len(metadataJSON))` — metadata is JSON of encryption params, max ~1 KiB |
| 1205–1207 | 4-byte big-endian header encoding the metadata length |
| 1656 | Same encoding in fallback path |
| 1660–1662 | Same 4-byte header bytes in fallback path |
| 1871 | `uint32(len(plaintext)-4)` — length is guarded by `len(plaintext) < 4` check above; annotated `// #nosec G115` |
| 2028 | `uint32(len(data))` in writeLengthPrefixed — AAD metadata field, tiny |

### Chunk Index Derivation — `internal/crypto/chunked.go`

| Lines | Justification |
|-------|---------------|
| 126 | `uint32(chunkIndex)` — HKDF info field; chunkIndex ≤ total chunks, well within uint32 |
| 414 | `uint32(chunkIndex)` — XOR-based IV derivation; same bound |

### Range Decrypt — `internal/crypto/range_decrypt.go`

| Lines | Justification |
|-------|---------------|
| 109 | `uint32(chunkIndex)` — XOR IV derivation; chunkIndex bounded by range size |

### PBKDF2 Iterations — `internal/crypto/password_keymanager.go`

| Lines | Justification |
|-------|---------------|
| 99 | `uint32(m.pbkdf2Iterations)` — PBKDF2 iterations are configurable but practical max is ~10^7, well within uint32 |

### MPU Encrypter — `internal/crypto/mpu_encrypter.go`

| Lines | Justification |
|-------|---------------|
| 121 | `uint32(partNumber)` — S3 part numbers are 1–10000 |
| 356 | `uint32(part.PartNumber)` and `uint32(r.chunkIdx)` — part ≤ 10000, chunkIdx ≤ total chunks per part |
| 416 | `uint32(startChunkIdx)` — chunk index bounds |
| 425, 471 | `uint32(partNumber)` — part ≤ 10000 |

### Chunk Count Computation — `internal/api/handlers.go`, `internal/api/upload_part_copy.go`

| File | Lines | Justification |
|------|-------|---------------|
| `handlers.go` | 2948 | `int32(encMPUPlainLen / chunkSize)` — max ~82k chunks for 5 GiB parts |
| `upload_part_copy.go` | 851 | Same computation; same bound |

### Crypto Jitter — `internal/s3/retry.go`

| Lines | Justification |
|-------|---------------|
| 46 | `int64(binary.BigEndian.Uint64(...) % uint64(n))` — n is maxAttempts ≤ 10, product fits int64 |

---

## G402 — TLS InsecureSkipVerify (CWE-295)

`InsecureSkipVerify` is always an operator opt-in, guarded by explicit
configuration with a startup warning (V1.0-SEC-9). Each site uses
`//nolint:gosec` and `// #nosec G402` annotations.

| File | Line | Justification |
|------|------|---------------|
| `internal/mpu/state.go` | 218 | Valkey TLS: operator opt-in; startup warning at ERROR level; annotated `// #nosec G402` |
| `internal/audit/sink.go` | 276 | Audit HTTP sink TLS: operator opt-in; annotated `// #nosec G402` |
| `internal/api/crypto_factory.go` | 129 | KMS TLS: operator opt-in; startup warning with custom CA; annotated `// #nosec G402` |

---

## G404 — Weak Random Number Generator (CWE-338)

| File | Line | Justification |
|------|------|---------------|
| `test/harness/faulty_s3.go` | 75 | Test-only: `math/rand` with deterministic seed for reproducible fault injection; `//nolint:gosec` already present |

---

## G501 / G505 — Blocklisted Import (CWE-327)

These imports are required by the S3 protocol or FIPS build infrastructure.
They are not used for security purposes.

| File | Rule | Justification |
|------|------|---------------|
| `internal/crypto/etag_default.go` | G501 | `crypto/md5` — ETag is an S3 protocol identifier (not a security hash); FIPS builds use `etag_fips.go` with SHA-256 |
| `internal/s3/client.go` | G501 | `crypto/md5` — Content-MD5 is an S3 protocol header; required for request integrity |
| `internal/api/auth.go` | G505 | `crypto/sha1` — AWS Signature V4 requires HMAC-SHA1 for the signing key derivation step |

---

## G304 — Potential File Inclusion via Variable (CWE-22)

All G304 findings are intentional file reads from operator-configured paths.
Paths come from config files, environment variables, or command-line flags set
by the operator during deployment. None are user-supplied.

| File | Line | Justification |
|------|------|---------------|
| `internal/config/config.go` | 842 | `os.ReadFile(path)` — path from `CONFIG_FILE` env var or `--config` flag |
| `internal/config/config.go` | 1318 | `os.ReadFile(path)` — path from `AUTH_CREDENTIALS_FILE` env var (also annotated `#nosec G703`) |
| `internal/config/config.go` | 2097 | `os.ReadFile(path)` — metadata key file path from config |
| `internal/config/policy.go` | 62 | `os.ReadFile(match)` — glob match from `POLICIES` env var |
| `internal/crypto/keymanager_registry.go` | 131 | `os.ReadFile(path)` — key material from `file://` URI |
| `internal/crypto/keymanager_selfcontained_factory.go` | 146, 183 | `os.ReadFile(path)` — key material from `file://` URI |
| `internal/admin/server.go` | 236, 271 | `os.ReadFile(path)` — admin bearer token file from config |
| `internal/migrate/state.go` | 61 | `os.ReadFile(path)` — migration state file path from CLI flag |

---

## G703 — Path Traversal via Taint Analysis (CWE-22)

These findings involve paths from environment variables or flags that gosec's
taint tracker flags. Both are operator-configured and not user-controllable.

| File | Line | Justification |
|------|------|---------------|
| `internal/config/config.go` | 1318 | `os.ReadFile(path)` — path from `AUTH_CREDENTIALS_FILE` env var; annotated `// #nosec G703` |
| `cmd/server/main.go` | 351 | `os.Stat(configPath)` — config file path from flag/env; annotated `// #nosec G703` |

---

## G704 — SSRF via Taint (CWE-918)

All G704 findings are in the S3 passthrough proxy code. The gateway
intentionally proxies HTTP requests to the configured backend S3 endpoint.
This is the core function of the gateway, not a vulnerability.

| File | Line | Justification |
|------|------|---------------|
| `internal/api/handlers.go` | 474 | `http.NewRequestWithContext` — proxying request to configured backend S3 endpoint |
| `internal/api/handlers.go` | 563 | `httpClient.Do(backendReq)` — executing the forwarded request |
| `internal/api/utils.go` | 211 | `client.Do(proxyReq)` — proxying request to backend in `forwardToBackend` |

---

## G705 — XSS via Taint (CWE-79)

All G705 findings are writing XML responses to HTTP clients in S3 API
handlers. This is the expected behaviour of an S3-compatible gateway, not
a cross-site scripting vector (S3 clients parse XML, not render it as HTML).

| File | Line | Justification |
|------|------|---------------|
| `internal/api/handlers.go` | 1375 | `w.Write(outputData)` — writing S3 GET response body |
| `internal/api/handlers.go` | 2018 | `w.Write([]byte(xmlResponse))` — writing S3 ListObjects/ListParts XML response |
| `internal/api/object_lock.go` | 269 | `w.Write(b)` — writing S3 Object Lock configuration XML |