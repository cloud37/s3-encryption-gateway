# gosec Suppression Audit

This is the complete source-annotation inventory for this repository, including
production code, tagged code, test providers, and `_test.go` files. Each entry
records the rule and its concrete guard or trust precondition. An annotation
does not establish safety for unrelated code or for every deployment setting.

## Policy and scan coverage

- Fix real numeric, authentication, and transport defects instead of suppressing
  them. Prefer explicit bounds and ordinary byte encoding to suppression.
- Retained annotations must use `#nosec Gxxx -- reason` with specific rule IDs.
  Broad `nolint:gosec`, unexplained directives, and global rule exclusions are
  not permitted. Direct gosec does not interpret standalone `nolint:gosec`.
- Explicit insecure-TLS opt-ins are **accepted diagnostic risk exceptions**, not
  proven false positives. Secure defaults verify certificates. See below for
  the exact remaining limitations.
- The CI/Makefile gate pins gosec **v2.29.0**, enforces rule IDs and explanations,
  and blocks unsuppressed HIGH findings. G104 is no longer globally excluded;
  its lower-severity findings remain visible in all-severity audits.
- The default scan excludes `_test.go` and inactive build tags. The inventory
  guard examines all Go source comments, regardless of tags, independently of
  scanner severity. FIPS/conformance and explicit test scans supplement CI.
- Do not run HSM builds/scans until functional HSM support exists, per
  `docs/TESTING.md`.

## Reproduce and verify completeness

```bash
# CI-equivalent security gate (no global rule exclusions).
make gosec

# Independent inventory check; does not rewrite the document.
python3 scripts/gosec-suppressions.py
go test ./internal/ci -run '^TestGosecSuppressionInventory$' -count=1
python3 scripts/test-gosec-suppressions.py

# Refresh only after reviewing the changed source guards and trust assumptions.
python3 scripts/gosec-suppressions.py --write

# Explicit all-severity audit, ignoring annotations; findings require triage.
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 \
  -nosec -fmt=json -out=/tmp/opencode/gosec-unsuppressed.json ./...

# Additional source/build configurations (not a claim of zero raw findings).
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 \
  -nosec -tags=fips,conformance ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 \
  -nosec -tests -tags=conformance,load,soak,chaos ./...
```

The Python refresh and the independent Tier 1 Go AST test require exact rows,
source line numbers, rules, scopes, and reasons. Missing, extra, duplicated,
stale, or broad annotations fail the check. This prevents the former inventory
drift; it does not replace human review of whether a reason remains true.
Both directive parsers reject whitespace-only explanations, multiple directives
in one comment, and duplicate rule IDs. Their negative regression tests cover
these cases independently of the scanner's own formatting checks.

## Reviewed controls and remaining preconditions

### Numeric and cryptographic encoding

Metadata/AAD writers validate the uint32 wire length before encoding. Fallback
readers compare widened body lengths, including values crossing 4 GiB, before
forming slice indices. PBKDF2 ceilings must be positive before unsigned error
encoding. MPU manifests validate ordered part numbers, nonnegative lengths,
consistent chunk counts/ciphertext lengths/totals, and overflow bounds; public
range and cipher helpers reject invalid coordinates. Declared part lengths and
chunk counters are enforced before further encryption. Valid legacy formats
remain readable; small legacy MPU chunk sizes are permitted up to 1 MiB.
Manifest serialization validates the same layout as readers. Completion checks
plaintext accumulation before addition and rejects invalid state before companion
encryption/storage or backend completion; failed validation reopens the lifecycle.
An allocation-free regression uses individually valid large parts to exercise
cumulative ciphertext overflow rather than an earlier consistency error.

AES key wrap uses ordinary big-endian integer XOR rather than byte-truncation
annotations. Its remaining counter conversion is bounded by the source slice
length and loop limits, not an assumed small key. Retry jitter's modulo result
is less than its positive int64 nanosecond bound; it is not key material.

### TLS exceptions

- **Cosmian:** `insecure_skip_verify` requires a configured CA and now skips
  hostname matching only. `VerifyConnection` still validates chain, expiry,
  server-auth purpose, and intermediates; it runs on resumed handshakes too.
- **OpenBao with CA:** same hostname-only exception with pinned-chain
  verification. Any valid server certificate under that CA can be accepted
  regardless of hostname, so the CA and network remain trusted.
- **OpenBao without CA, backend S3, Valkey, and audit sink:** explicit
  skip-verification disables certificate authentication and permits MITM.
  Warnings identify this diagnostic setting; never enable it as a secure
  production configuration. All skip-verification defaults are false.
- The audit HTTP sink rejects invalid custom TLS initialization before network
  I/O; it no longer falls back to a different system-root policy.
- Test-only self-signed probes/clients are scoped to ephemeral fixtures, not
  production secret-bearing endpoints.

### HTTP and filesystem boundaries

Passthrough host/scheme are operator-selected. Client path/query cannot replace
the destination, and redirects are returned rather than followed: the gateway
does not forward credentials or replay bodies to a redirect target. S3/CORS
request filtering happens before gateway signing.

Configuration, token and JWT paths are operator-selected, never S3-request
paths. Audit file writes reject unsafe configured/existing modes, symlinks and
nonregular destinations; no-follow/exclusive creation and opened-inode
revalidation occur before writes. Default `0600` and explicit `0640` remain
supported. Parent directories must be operator-controlled; file hardening does
not authorize writes into directories controlled by other users.

### Compatibility primitives and fixtures

MD5 here supplies S3 Content-MD5/ETag compatibility, not encryption or access
control. Legacy SigV2 uses **HMAC-SHA1**; SigV4 uses **HMAC-SHA256**. Unsuppressed
lower-severity import/checksum findings remain visible in full scans; entries
are not invented for imports with no source annotation.

Fixture secrets are public/disposable, not production credentials. Garage test
ports require an isolated test runner/network. The ephemeral MinIO private-key
fixture is mode `0644` inside its disposable nonroot container only; this is
not a recommendation for production key permissions. Deterministic test RNGs
drive fault timing/probability, never cryptographic keys or authorization.

## Complete annotation inventory

<!-- BEGIN GENERATED GOSEC SUPPRESSIONS -->
| Source location | Rules | Scope | Verified justification / precondition |
|---|---|---|---|
| `cmd/server/main.go:409` | G703 | Production | CONFIG_PATH is operator-selected; existence check only, not request input |
| `internal/api/aws_chunked_reader.go:142` | G115 | Production | remaining is checked non-negative |
| `internal/api/crypto_factory.go:252` | G402 | Production | explicit hostname-only opt-in; VerifyConnection checks the configured CA chain and emits a warning |
| `internal/api/crypto_factory.go:414` | G402 | Production | explicit hostname-only opt-in; VerifyConnection checks the pinned CA chain on every handshake including resumption |
| `internal/api/crypto_factory.go:435` | G402 | Production | operator-only diagnostic opt-in with ERROR warning; no certificate authentication, never a secure production mode |
| `internal/api/crypto_factory.go:466` | G304 | Production | token or SecretID file reference is chosen by the operator, never by an S3 request |
| `internal/api/handlers.go:4269` | G115 | Production | negative sizes are rejected above |
| `internal/api/upload_part_copy.go:1065` | G115 | Production | chunkCount is bounded by MaxInt32 above |
| `internal/api/utils.go:5` | G501 | Production | S3 Content-MD5 interoperability header |
| `internal/api/utils.go:301` | G704 | Production | host/scheme come only from operator backend config; requests supply path/query and redirects are disabled |
| `internal/api/utils.go:360` | G401 | Production | required by S3 lifecycle APIs |
| `internal/api/utils_bucket_management_test.go:64` | G401 | Test fixture | test expected S3 header |
| `internal/audit/sink.go:283` | G402 | Production | operator-only diagnostic opt-in emits WARN; secure default verifies chain and hostname |
| `internal/audit/sink.go:479` | G304 | Production | operator-controlled directory/path; no-follow exclusive creation and inode/type/mode revalidation precede writes |
| `internal/config/config.go:2048` | G703 | Production | AUTH_CREDENTIALS_FILE is operator-selected; HTTP requests cannot choose its path |
| `internal/crypto/engine.go:145` | G115 | Production | field count was checked above |
| `internal/crypto/engine.go:1843` | G115 | Production | ChunkedPlaintextSize rejects negative sizes |
| `internal/crypto/engine.go:1909` | G115 | Production | ChunkedPlaintextSize rejects negative sizes |
| `internal/crypto/keymanager_memory.go:304` | G115 | Production | n=len(ciphertext)/8-1; j=0..5 and i=0..n-1 imply 1<=counter<=6*n<MaxInt |
| `internal/crypto/keymanager_openbao.go:852` | G304 | Production | JWT path is operator-configured or the projected ServiceAccount path; requests cannot choose it |
| `internal/crypto/password_keymanager.go:88` | G115 | Production | constructor and derivation validate 100000..2000000 iterations before encoding |
| `internal/crypto/range_decrypt.go:105` | G115 | Production | product was bounded by MaxInt64 above |
| `internal/crypto/range_decrypt.go:216` | G115 | Production | index was bounded by MaxInt64/chunkSize above |
| `internal/crypto/range_optimization.go:98` | G115 | Production | dataSize is non-negative |
| `internal/crypto/range_optimization.go:129` | G115 | Production | validateChunkSize requires a positive chunk size |
| `internal/crypto/range_optimization.go:138` | G115 | Production | values are bounded by MaxInt64 above |
| `internal/crypto/range_optimization.go:188` | G115 | Production | negative offsets were rejected above |
| `internal/crypto/range_optimization.go:189` | G115 | Production | negative offsets were rejected above |
| `internal/crypto/range_optimization.go:252` | G115 | Production | ChunkCount was bounded by MaxInt64 above |
| `internal/crypto/range_optimization.go:377` | G115 | Production | size was bounded by MaxInt64 above |
| `internal/mpu/state.go:659` | G402 | Production | operator-only diagnostic opt-in with ERROR warning above; default requires authenticated TLS |
| `internal/s3/backend_transport.go:27` | G402 | Production | explicit operator-controlled diagnostic configuration; startup emits a warning |
| `internal/s3/client_bench_test.go:54` | G404 | Test fixture | deterministic benchmark fault timing only; never keys, tokens, or authorization |
| `internal/s3/retry.go:46` | G115 | Production | n>0; modulo result is less than n<=MaxInt64; jitter only, not key material |
| `test/conformance/passthrough_headers_test.go:245` | G401 | Test fixture | S3 Content-MD5 compatibility header |
| `test/conformance/s3_compat_test.go:73` | G401 | Test fixture | required S3 compatibility header |
| `test/harness/faulty_s3.go:75` | G404 | Test fixture | deterministic test fault timing/probability only; never cryptographic material |
| `test/harness/gateway.go:364` | G402 | Test fixture | the test-only TLS certificate is self-signed |
| `test/harness/gateway.go:482` | G402 | Test fixture | test-only self-signed certificate |
| `test/provider/aws.go:20` | G101 | Test fixture | provider registration contains environment variable names, not embedded credentials |
| `test/provider/garage.go:86` | G101 | Test fixture | public disposable RPC secret for an isolated test container, never production credentials |
| `test/provider/hetzner.go:19` | G101 | Test fixture | provider registration contains environment variable names and public endpoints, not embedded credentials |
| `test/provider/minio.go:180` | G402 | Test fixture | test-only health probe for the generated self-signed fixture |
| `test/provider/minio.go:181` | G306 | Test fixture | disposable container-only certificate/private key must be readable by its nonroot user; isolated fixture, never production key permissions |
<!-- END GENERATED GOSEC SUPPRESSIONS -->
