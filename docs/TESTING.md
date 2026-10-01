# Testing Guide

This document is the single authoritative source for testing the
S3 Encryption Gateway. It supersedes the four older README files
(`test/README.md`, `test/INTEGRATION_TESTS.md`,
`test/BACKBLAZE_B2_TESTING.md`, `test/README_LOAD_TESTS.md`).

---

## Test tier taxonomy

Tests are divided into three tiers. A test lives in **exactly one** tier.

```
┌──────────────────────────────────────────────────────────────────┐
│ Tier 3 — Soak / Load / Chaos                                      │
│ Build tags: soak | load | chaos                                   │
│ Not a PR gate; manual + nightly only. Budget: 10–60 min each.    │
├──────────────────────────────────────────────────────────────────┤
│ Tier 2 — Conformance (multi-provider)                             │
│ Build tag: conformance                                            │
│ PR gate and main push both run all local providers.               │
│ Budget: < 15 min.                                                 │
├──────────────────────────────────────────────────────────────────┤
│ Tier 1 — Unit                                                     │
│ No build tag.                                                     │
│ Every `go test ./...`, every PR, every push. Baseline: main.      │
└──────────────────────────────────────────────────────────────────┘
```

Key rules:

1. **A test lives in exactly one tier.** If it needs Docker it is tier 2.
2. **`go test ./...` is tier 1 only.** Tier 2/3 tests use build tags so
   they never run under the default build.
3. **Docker unavailability is a `t.Skip`, not an error.** Tier 2 skips
   cleanly when Docker is absent; the skip message names the missing
   fixture.
4. **Flaky tier 1 is a P0 bug.** Tier 1 is the fastest feedback loop;
   any flake in tier 1 is prioritised over feature work.

---

## Running each tier locally

### Tier 1 — unit tests

```bash
# Standard run with race detector.
go test -race ./...

# Inspect individual test durations if the Tier 1 gate slows down.
go test -race -count=1 -json ./internal/api > /tmp/api-tier1.json

# FIPS build.
GOFIPS140=v1.0.0 go test -race -tags=fips ./...

# HSM validation is intentionally disabled. The current `hsm` provider is a
# non-functional PKCS#11 skeleton/stub, so tagged builds do not validate a
# supported deployment path. Do not run HSM tests, builds, or vet commands until
# functional HSM support and its provider fixture are implemented. Re-enable
# this command as part of that work:
# go test -race -tags=hsm ./...
```

**Tier 1 runtime is evaluated against previous `main` behavior, not a fixed
60-second limit.** Compare uncached runs of the same command on the same
machine (or comparable CI workers); use package timings to identify regressions.
For example, run `go test -race -count=1 -timeout 20m ./...` on both the branch
and `main`, then compare the slowest packages. Cached runs and runs with
different flags, hardware, or concurrent workloads are not comparable. Treat
a substantial slowdown relative to the recent `main` baseline as something to
investigate, even if the suite still passes; the figures below are observations,
not a new hard budget.

On 2026-09-28, an uncached race run on the same machine measured
`internal/api` at ~603 s and `internal/crypto` at ~268 s on `main` (`a275e2c`),
compared with ~130 s and ~102 s respectively on `v1.0-S3-6` after the Tier 1
fixture optimizations. Rerun the comparison when `main` or the test suite
changes rather than treating these numbers as permanent thresholds.

### Tier 2 — conformance tests

Requires Docker. Testcontainers-Go pulls and starts containers automatically;
no `docker-compose up` is needed.

```bash
# All local providers (MinIO + Garage + RustFS + SeaweedFS).
make test-conformance-local

# All registered providers (local always; external when creds are set).
make test-conformance

# External providers only (needs vendor credentials in env).
make test-conformance-external
```

Individual local providers can be skipped via environment variables:

```bash
# Skip a provider for a single run.
GATEWAY_TEST_SKIP_RUSTFS=1    make test-conformance-local
GATEWAY_TEST_SKIP_SEAWEEDFS=1 make test-conformance-local

# Skip multiple providers.
GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_SEAWEEDFS=1 make test-conformance-local
```

### Tier 2 — CI equivalents

```bash
# What the PR gate runs.
make test
make test-conformance-local
make test-isolation-check

# What the main-push gate runs (same local provider suite).
make test-comprehensive
```

### Tier 3 — load / soak / chaos

```bash
# Load tests (requires Docker).
go test -tags=load -timeout 1h ./test/load/...

# In-process 400 MiB encrypted MPU round-trip (no Docker; intentionally
# excluded from Tier 1 because its 80 x 5 MiB parts are a load workload).
go test -tags=load -timeout 1h ./internal/api -run '^TestMPU_LargeObjectGoldenPath$' -count=1

# Soak tests.
go test -tags=soak -timeout 1h ./test/soak/...

# Chaos tests.
go test -tags=chaos -timeout 30m ./test/chaos/...

# Per-provider soak targets.
make test-load-minio
make test-load-garage
make test-load-rustfs
make test-load-seaweedfs
```

### Local encryption benchmark matrix (`benchmark-local`)

`make benchmark-local` runs every local provider (MinIO, Garage, RustFS,
SeaweedFS) against the following encryption configurations in sequence:

| # | Config name                              | Key material          | Object / op           |
|---|------------------------------------------|-----------------------|-----------------------|
| 1 | `Password_PBKDF2_Chunked`                | Password + PBKDF2     | 1 MiB PutObject       |
| 2 | `Password_PBKDF2_100k_Chunked`           | Password + PBKDF2 (min) | 1 MiB PutObject     |
| 3 | `Password_Argon2id_Chunked`              | Password + Argon2id   | 1 MiB PutObject       |
| 4 | `AES256GCM_KEK_Chunked`                  | AES-256-GCM KEK       | 1 MiB PutObject       |
| 5 | `RSA_OAEP_KEK_Chunked`                   | RSA-OAEP/SHA-256 KEK  | 1 MiB PutObject       |
| 6 | `AES256GCM_KEK_EncryptedMPU_50MiB`       | AES-256-GCM KEK       | 4 × 50 MiB MPU        |
| 7 | `Password_PBKDF2_EncryptedMPU_50MiB`     | Password + PBKDF2     | 4 × 50 MiB MPU        |
| 8 | `Password_PBKDF2_100k_EncryptedMPU_50MiB`| Password + PBKDF2 (min) | 4 × 50 MiB MPU      |
| 9 | `Password_Argon2id_EncryptedMPU_50MiB`   | Password + Argon2id   | 4 × 50 MiB MPU        |
|10 | `RSA_OAEP_KEK_EncryptedMPU_50MiB`        | RSA-OAEP/SHA-256 KEK  | 4 × 50 MiB MPU        |
|11 | `AES256GCM_KEK_RangedGet_MultiChunk`     | AES-256-GCM KEK       | 200 KiB 5 sub-ranges  |
|12 | `Password_PBKDF2_RangedGet_MultiChunk`   | Password + PBKDF2     | 200 KiB 5 sub-ranges  |
|13 | `Password_PBKDF2_100k_RangedGet_MultiChunk`| Password + PBKDF2 (min) | 200 KiB 5 sub-ranges|
|14 | `Password_Argon2id_RangedGet_MultiChunk` | Password + Argon2id   | 200 KiB 5 sub-ranges  |
|15 | `RSA_OAEP_KEK_RangedGet_MultiChunk`      | RSA-OAEP/SHA-256 KEK  | 200 KiB 5 sub-ranges  |
|16 | `CosmianKMIP_Chunked`                    | Cosmian KMIP KMS      | 1 MiB PutObject       |
|17 | `CosmianKMIP_EncryptedMPU_50MiB`         | Cosmian KMIP KMS      | 4 × 50 MiB MPU        |
|18 | `CosmianKMIP_RangedGet_MultiChunk`       | Cosmian KMIP KMS      | 200 KiB 5 sub-ranges  |

Configs 16-18 require a Cosmian KMS container (`ghcr.io/cosmian/kms:5.22.0`)
and are automatically skipped when `GATEWAY_TEST_SKIP_COSMIAN=1` is set.

Results are always printed via `t.Logf` (visible with `-v`). Optionally write
NDJSON for programmatic comparison:

```bash
# Default: 8 workers, 30s per config.
make benchmark-local

# Custom: 16 workers, 2 min per config, save results.
BENCH_LOCAL_WORKERS=16 BENCH_LOCAL_DURATION=2m \
  BENCH_LOCAL_JSON_OUT=/tmp/bench-results.ndjson \
  make benchmark-local

# Run only one provider.
GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 \
  GATEWAY_TEST_SKIP_SEAWEEDFS=1 make benchmark-local

# Skip KMS-backed configs.
GATEWAY_TEST_SKIP_COSMIAN=1 make benchmark-local
```

**Environment variables:**

| Variable                  | Default     | Description                            |
|---------------------------|-------------|----------------------------------------|
| `BENCH_LOCAL_WORKERS`     | `8`         | Goroutines per config                  |
| `BENCH_LOCAL_DURATION`    | `30s`       | Duration per config                    |
| `BENCH_LOCAL_OBJECT_SIZE` | `1048576`   | PutObject payload size (bytes)         |
| `BENCH_LOCAL_MPU_SIZE`    | `52428800`  | Per-part MPU size (bytes, default 50 MiB)|
| `BENCH_LOCAL_JSON_OUT`    | *(empty)*   | NDJSON output file path (optional)     |
| `GATEWAY_TEST_SKIP_COSMIAN` | *(unset)*| Set to `1` to omit KMS-backed configs  |

This suite is **not run in CI** (requires Docker and takes several minutes per
configuration). It is intended for manual performance verification and
regression detection between versions.

### Large-list enumeration benchmark (`benchmark-list`)

`make benchmark-list` is a Tier 3 manual benchmark for issue #216. It compares
direct backend `ListObjectsV2` enumeration with enumeration through the
in-process gateway. The benchmark runs against every registered provider:
local Testcontainers providers when Docker is available, and external
providers when their credentials are set. It is deliberately not registered
in the conformance suite and is not called by any CI target.

Each provider runs these scenarios:

| Scenario | Dataset | Translation | Purpose |
|----------|---------|-------------|---------|
| `warm-cache` | Uploaded through gateway | Enabled | Steady-state Valkey cache path |
| `cold-cache` | Uploaded directly to backend | Enabled | Cache misses without HEAD fallback |
| `fallback-head` | Uploaded directly to backend | Enabled + fallback HEAD | Legacy-object HEAD amplification |
| `translation-disabled` | Uploaded directly to backend | Disabled | Proxy/listing baseline |

The benchmark reports direct and gateway wall-clock time, object counts,
gateway `ListObjects` and `HeadObject` operations, Valkey cache hits/misses,
and fallback HEAD calls. A count mismatch fails the run so a slow listing is
not confused with an incomplete listing. Results are printed via `t.Logf` and
can optionally be written as NDJSON:

```bash
# Local providers, 1,000 objects per scenario.
make benchmark-list

# 10,000 objects, 1 KiB each, 100 repetitions of 100-object pages.
BENCH_LIST_OBJECTS=10000 BENCH_LIST_PAGE_SIZE=100 BENCH_LIST_ROUNDS=2 \
  BENCH_LIST_JSON_OUT=/tmp/list-benchmark.ndjson \
  make benchmark-list

# MinIO only.
GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 \
  GATEWAY_TEST_SKIP_SEAWEEDFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
  make benchmark-list

# External providers whose credentials are configured, for example B2/Wasabi.
GATEWAY_TEST_SKIP_MINIO=1 GATEWAY_TEST_SKIP_GARAGE=1 \
  GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_SEAWEEDFS=1 \
  make benchmark-list
```

**Environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `BENCH_LIST_OBJECTS` | `1000` | Objects created for each scenario |
| `BENCH_LIST_OBJECT_SIZE` | `1024` | Plaintext bytes per object |
| `BENCH_LIST_PAGE_SIZE` | `1000` | `ListObjectsV2` page size, capped at 1000 |
| `BENCH_LIST_ROUNDS` | `1` | Complete listing repetitions |
| `BENCH_LIST_JSON_OUT` | *(empty)* | Optional NDJSON output path |

External runs use the existing provider credentials documented below, such as
`B2_ACCESS_KEY_ID` / `B2_SECRET_ACCESS_KEY` / `B2_BUCKET_NAME` and
`WASABI_ACCESS_KEY_ID` / `WASABI_SECRET_ACCESS_KEY` / `WASABI_BUCKET_NAME`.
Use a disposable prefix or bucket for benchmark data. Wasabi is configured
with `CleanupPolicySkipDelete` because of its minimum storage duration.

### Real `rclone ncdu` benchmark (`benchmark-rclone-ncdu`)

`make benchmark-rclone-ncdu` runs the actual interactive `rclone ncdu` command
inside the pinned `rclone/rclone:1.68` container. It starts with a dataset
uploaded through the gateway, then measures the same scan against the direct
backend and the gateway. The container is given a TTY and the benchmark exits
`ncdu` after the configurable settle period, so this exercises rclone's real
scan path rather than an SDK-equivalent listing loop.

This benchmark is separately gated with `benchmark_rclone_ncdu`, is not part of
`TestConformance`, and is not run in CI. It uses local Testcontainers
providers and configured external providers in the same way as
`benchmark-list`.

```bash
# Default: 1,000 objects in ten nested prefixes, 1 KiB each.
make benchmark-rclone-ncdu

# Larger dataset and JSON results.
BENCH_RCLONE_NCDU_OBJECTS=10000 \
BENCH_RCLONE_NCDU_OBJECT_SIZE=1024 \
BENCH_RCLONE_NCDU_SETTLE=10s \
BENCH_RCLONE_NCDU_JSON_OUT=/tmp/rclone-ncdu.ndjson \
make benchmark-rclone-ncdu

# MinIO only.
GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 \
  GATEWAY_TEST_SKIP_SEAWEEDFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
  make benchmark-rclone-ncdu
```

The result includes direct and gateway scan durations, exit codes, configured
object count, and the gateway's list-size cache and fallback-HEAD metrics. The
benchmark intentionally uses objects uploaded through the gateway, so a
non-zero fallback-HEAD count indicates a cache/configuration problem rather
than an expected legacy-object condition.

**Environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `BENCH_RCLONE_NCDU_OBJECTS` | `1000` | Objects uploaded for the scan |
| `BENCH_RCLONE_NCDU_OBJECT_SIZE` | `1024` | Plaintext bytes per object |
| `BENCH_RCLONE_NCDU_SETTLE` | `5m` | Safety deadline for the ncdu scan |
| `BENCH_RCLONE_NCDU_JSON_OUT` | *(empty)* | Optional NDJSON output path |

---

## Capability bitmap reference

The `provider.Capabilities` bitmask controls which conformance tests run
against each backend. Tests call `t.Skipf` when the tested capability is
absent from the provider's bitmap.

| Constant                   | Meaning                                                           |
|----------------------------|-------------------------------------------------------------------|
| `CapObjectLock`            | S3 Object Lock / WORM retention                                   |
| `CapObjectTagging`         | PutObjectTagging / GetObjectTagging                               |
| `CapMultipartUpload`       | S3 multipart upload API                                           |
| `CapMultipartCopy`         | UploadPartCopy                                                    |
| `CapVersioning`            | Bucket versioning                                                 |
| `CapServerSideEncryption`  | Backend-native SSE (not gateway encryption)                       |
| `CapPresignedURL`          | Pre-signed GET / PUT URLs                                         |
| `CapConditionalWrites`     | If-None-Match / If-Match on PUT                                   |
| `CapBatchDelete`           | DeleteObjects (XML multi-delete)                                  |
| `CapKMSIntegration`        | Cosmian KMS integration works with this backend                   |
| `CapInlinePutTagging`      | x-amz-tagging header accepted on PutObject (vs. ?tagging only)   |
| `CapEncryptedMPU`          | Run encrypted multipart upload conformance tests (needs Valkey)   |
| `CapLoadTest`              | Backend is suitable for in-process load/soak tests                |

---

## Local provider reference

The following Testcontainers-backed providers are registered by default.  Each
can be disabled with the corresponding environment variable.

| Provider   | Image                           | Skip env var                    | Notes                                              |
|------------|---------------------------------|---------------------------------|----------------------------------------------------|
| `minio`    | `chainguard/minio@sha256:de89cccd6cb19f505bf85c8a36f099414dc7a372c0e16abd2170ebaada9cc99f` | `GATEWAY_TEST_SKIP_MINIO=1` | Primary reference; PR-gated local provider |
| `garage`   | `dxflrs/garage:v2.4.1`          | `GATEWAY_TEST_SKIP_GARAGE=1`    | Rust-based; requires bootstrap via admin REST API  |
| `rustfs`   | `rustfs/rustfs:v1.0.0-rc.5`     | `GATEWAY_TEST_SKIP_RUSTFS=1`    | Alpha-quality; PR-gated, capability bitmap conservative |
| `seaweedfs`| `chrislusf/seaweedfs:4.46`      | `GATEWAY_TEST_SKIP_SEAWEEDFS=1` | Blob-store-backed; PR-gated local provider       |

All four local providers (MinIO, Garage, RustFS, and SeaweedFS) run in the
pull-request conformance gate. RustFS compatibility failures are reported and
tracked as provider issues, but the provider remains part of the gate.

**RustFS note**: RustFS is explicitly labelled "Do NOT use in production" by
its authors as of 2026. The provider is included to test gateway behaviour
against an actively-developed implementation and to provide early signal on
compatibility.

Confirmed capability gaps (full conformance run 2026-04-22):
- **Object Lock** (`CapObjectLock` absent): RustFS accepts the `ObjectLockConfiguration`
  at bucket-creation time but does not persist or return the
  `x-amz-object-lock-mode` / `x-amz-object-lock-legal-hold` response headers.
  Re-enable `CapObjectLock` once the upstream implementation is complete.

All other capabilities pass, including KMS envelope encryption, encrypted MPU,
UploadPartCopy, tagging, presigned URLs, load tests, and chaos tests.

**Garage note**: Garage v2.3.0 does not implement the `?tagging` subresource
for `PutObjectTagging` / `GetObjectTagging` (returns 501 `NotImplemented`).
Inline tagging via `x-amz-tagging` on `PutObject` (`CapInlinePutTagging`) works
correctly.

Confirmed capability gaps (full conformance run 2026-05-14):
- **Object tagging** (`CapObjectTagging` absent): `?tagging` subresource not
  implemented in Garage v2.3.x. Re-enable `CapObjectTagging` when a supported
  version ships.

**SeaweedFS note**: SeaweedFS uses a blob-store-backed S3 gateway architecture.

Confirmed capability gaps (full conformance run 2026-04-22):
- **Object Lock** (`CapObjectLock` absent): SeaweedFS accepts the
  `ObjectLockConfiguration` at bucket-creation time but does not persist or
  return the `x-amz-object-lock-mode` / `x-amz-object-lock-legal-hold`
  response headers — identical behaviour to RustFS.  `ObjectLock_BypassRefused`
  passes; `ObjectLock_Retention` and `ObjectLock_LegalHold` fail.
- **Conditional writes** (`CapConditionalWrites` absent): `If-None-Match` /
  `If-Match` on PUT not verified against SeaweedFS.

`CapKMSIntegration` **passes** — KMS envelope encryption works correctly.
All other capabilities pass, including encrypted MPU, UploadPartCopy,
versioning, tagging, presigned URLs, load tests, and chaos tests.
Note: `Load_Multipart` throughput (~15 req/s) is significantly lower than
MinIO/RustFS (~30 req/s) due to SeaweedFS's multi-component architecture.

---

## How to add a new test

1. Decide which tier the test belongs to.
2. **Tier 1**: add it to the appropriate `internal/*/..._test.go` file.
   No build tag; runs under `go test ./...`.
3. **Tier 2**: add a `testXxx(t *testing.T, inst provider.Instance)` function
   in the appropriate `test/conformance/*.go` file, then register it in
   `test/conformance/suite_test.go`'s `cases` slice with the required capability
   bit (or `0` if no capability is needed).
4. **Tier 3**: add to `test/load/`, `test/soak/`, or `test/chaos/` with the
   corresponding build tag.

The metadata model and response-precedence contract are documented in
[`METADATA_MODEL.md`](METADATA_MODEL.md). Legacy object-format fixtures belong
in `internal/api/testdata/objectformats/`. The object-format golden fixtures
contain authentic encrypted backend bodies and are exercised through the
production handlers, as detailed below.

Metadata conformance coverage includes PUT, COPY, COPY REPLACE, encrypted MPU,
UploadPartCopy, all six standard fields, two user metadata keys, full/HEAD/fixed
(`bytes=1-9`), open-ended, and suffix reads, bypass persistence, reserved-key
rejection, presigned response overrides, cache-hit body replay and backend-ETag
mismatch refresh, and encrypted-MPU plaintext-size listing and companion
deletion through DeleteObjects. Encrypted MPU and UploadPartCopy matrices each run self-contained
chunked and non-chunked variants. Each asserts HEAD status, plaintext
Content-Length, ETag, all six standard headers, two user metadata fields, plus
full/fixed/open/suffix GET status, body, Content-Range, Content-Length, ETag,
and the same eight metadata fields. Cases are registered in
`test/conformance/suite_test.go` with capability masks and remain
provider-agnostic. The encrypted MPU and UploadPartCopy variants both configure
an AES KEK manager. The non-versioned `DeleteObject_EncryptedMPUv2` case is
registered separately with `CapEncryptedMPU`; versioned manifest deletion
requires both `CapVersioning` and `CapEncryptedMPU`.

The cache case populates the bounded response cache, verifies a subsequent
response from the cached body, changes the object directly at the backend, and
then verifies that the ETag mismatch evicts the entry and returns fresh bytes.

The committed `internal/api/testdata/objectformats/*.json` files contain
deterministic test-only encrypted object bodies (and encrypted MPU companion
manifests where applicable), backend metadata, and expected response fields.
The fixture generator invokes the production crypto engine for current formats
and deterministic test primitives for explicitly legacy read-only formats.
`TestObjectHeaders_GoldenPerFormat` seeds the mock S3 backend with those bytes
and exercises production HEAD, full GET, and ranged GET handlers. It checks
plaintext, status, ETag, all six standard headers, reserved metadata filtering,
and range headers. `serveMPURangedGet` has separate handler coverage for
success, failures, and response projection. Golden fixtures assert exact
fallback full-GET, HEAD, and ranged-GET `Content-Length` values.

Regenerate fixtures with this exact command from the repository root:

```bash
UPDATE_OBJECTFORMAT_GOLDENS=1 go test ./internal/api -run '^TestGenerateObjectFormatFixtures$' -count=1
```

The helper supplies a deterministic test-only entropy reader for the engine's
supported random inputs; generated outputs are reviewed and committed. Run the
golden test without the environment variable to validate the committed corpus:
`go test ./internal/api -run '^TestObjectHeaders_GoldenPerFormat$' -count=1`.

Tier 1 also runs production-source AST ownership checks for object errors and
metrics, response headers and aliases, MPU markers/suffixes, and the crypto
metadata literal registry. The real-router route parity test checks routing,
instrumentation, and authorization permissions against an independent test
oracle. Manual benchmarks `BenchmarkProjectObjectHeaders` and
`BenchmarkHeadObject_Chunked` report allocations and bytes processed.
Run them reproducibly without Docker using `make benchmark-object-metadata`; it
executes both benchmarks with `-benchmem -count=5` and reports observations only
when explicitly run.
The API suite also includes `TestGetObject_CacheFillConcurrentReaders` to verify
concurrent cache-hit body serving.
Handler metadata/MPU unit fixtures use the supported minimum PBKDF2 work factor
to keep `-race` feedback bounded; production defaults and KDF limits remain
covered by the crypto and config tests. `TestMPU_MultipartRoundTrip` checks
cross-part integrity in Tier 1; the 400 MiB `TestMPU_LargeObjectGoldenPath`
uses the `load` tag instead.
Crypto object-format fixtures likewise use the minimum work factor unless the
test explicitly verifies KDF defaults, cross-iteration reads, or cost limits.

**The conformance contract**: test bodies must never branch on provider names.
Use capability bits. The `TestConformance_NoProviderNameLiterals` AST check in
`test/conformance/matrix_guard_test.go` enforces this mechanically.

The legacy `integration`-tagged Azurite fixture is outside the PR conformance
gate. It is retained for separate integration validation until migrated to the
conformance tier.

### Reverse-proxy header regressions (GH-338)

No reverse proxy **in front of the gateway** is required to reproduce this
bug: tests inject the headers a frontend proxy adds after client signing.
The failure depends on a backend frontend changing a signed header after
gateway signing, not on running Caddy itself.

- **Tier 1:** `internal/api/passthrough_headers_test.go` uses the production
  router and a local `httptest` backend. The backend verifies SigV4, appends
  to `X-Forwarded-For`, then verifies again. Cases cover location, creation,
  ListBuckets, multipart listing, tagging, and preflight; direct requests are
  positive controls. Separate checks assert exact signed-header exclusion,
  S3/CORS header preservation, body length, authentication/query stripping,
  case-insensitive Connection tokens, response filtering, and independent
  inbound/outbound header storage. No Docker or expensive KDF fixture is used.
- **Tier 2:** `test/conformance/passthrough_headers_test.go` registers
  `Passthrough_ProxyHeaders_*` cases in the ordinary provider matrix. An
  in-process backend frontend verifies signatures before and after appending
  `X-Forwarded-For`, then re-signs the final hop for the real provider's host.
  A deliberately signed proxy-header control must fail with
  `SignatureDoesNotMatch`; gateway requests must survive the mutation and
  preserve real provider behavior. Location, scoped ListBuckets, and CORS
  forwarding run without a capability requirement. Creation, multipart
  listing, tagging, and configured CORS use their existing capability bits.
  Backend-denied account-wide ListBuckets is explicitly skipped. CORS
  forwarding compares native backend status/headers even when configured CORS
  is unsupported. Local backends remain Testcontainers-managed with the usual
  Docker-unavailable skips; no extra proxy container, fixed port, or CI target
  is needed.

Focused commands from the repository root:

```bash
# Tier 1: repeat inexpensive regressions under the race detector.
go test -race ./internal/api -count=10 \
  -run 'Test(PassthroughHeaders|ForwardToBackend_HeaderBoundary|BackendRequestHeaders|CopyProxyResponse_ConnectionTokens)'

# Tier 2: all local providers, using the existing fixture/capability registry.
GATEWAY_TEST_SKIP_EXTERNAL=1 go test -race -tags=conformance \
  ./test/conformance -count=1 -timeout=10m \
  -run '^TestConformance/[^/]+/Passthrough_ProxyHeaders'
```

These focused commands supplement, not replace, the full Tier 1 and local
conformance gates. See the
[passthrough header contract](S3_API_IMPLEMENTATION.md#passthrough-request-header-contract)
for the exact preserved and excluded header sets.

### Suppression and transport hardening regressions

Tier 1 includes allocation-free uint32 metadata-length and wide fallback-slice
bounds, negative KDF ceilings, malformed MPU layout/coordinates, declared MPU
length enforcement, pinned KMS CA handshakes, and audit TLS/file safety tests.
The independent Go AST `TestGosecSuppressionInventory` checks **all** Go source
comments (including tagged/test files) against the generated suppression table;
it rejects broad, unexplained, missing, or stale annotations. The standard
HIGH-severity gate pins gosec v2.29.0 and requires specific rules and reasons.

Tier 2 registers `Passthrough_RedirectNotFollowed` and
`Passthrough_TLSVerification` with capability `0`. The existing provider harness
uses injected HTTP/TLS frontends to prove unchanged redirect status/headers/body,
no target requests or body replay, actual private-CA rejection, and successful
configured-CA/explicit-diagnostic controls. No new proxy container or provider
name branch is needed. Run focused coverage with:

```bash
GATEWAY_TEST_SKIP_EXTERNAL=1 go test -race -tags=conformance \
  ./test/conformance -count=1 -timeout=10m \
  -run '^TestConformance/[^/]+/Passthrough_(RedirectNotFollowed|TLSVerification)'
python3 scripts/gosec-suppressions.py
go test ./internal/ci -run '^TestGosecSuppressionInventory$' -count=1
python3 scripts/test-gosec-suppressions.py
```

Review and regeneration procedures and all accepted-risk preconditions are in
[`security/gosec-suppressions.md`](security/gosec-suppressions.md).
Completion regressions additionally inject invalid committed-state snapshots
and assert no companion write or backend completion, plus lifecycle reopening.
Manifest overflow coverage uses individually consistent parts whose cumulative
ciphertext length exceeds int64. Python and Go parser regressions reject empty
reasons, duplicate rules, and multiple directives in a single comment.

### Atomic bucket-policy reload regressions (GH-339)

- **Tier 1:** `internal/config/policy_reload_test.go` pauses a reload at the
  file/environment source boundary using channels. With environment-only and
  combined sources, readers must retain the complete previous policy set;
  no timing loop or Docker fixture is needed to expose the original bug.
  Cases cover malformed/unreadable files, invalid globs, validation failures,
  a late invalid environment entry, all-or-nothing individual loaders,
  precedence, replacement/removal, nonaccumulation, and concurrent policy
  lookups. `cmd/server/policy_reload_test.go` checks publication on the shared
  manager, retained selected policy objects, preparation before live mutation,
  and a real credentials-file replacement driving the production reload
  callback. The watcher test signals callback completion rather than guessing
  a sleep duration. Policy failures retain credentials and current config.
- **Tier 2:** `test/conformance/policy_reload_test.go` registers
  `PolicyReload_FailedLoadPreservesBypass` and
  `PolicyReload_ConcurrentBypassWrites` with capability `0` in the ordinary
  provider matrix. The first deterministically reproduces a failed reload
  followed by a successful PUT, then checks raw backend bytes/markers and
  gateway reads after restoring the intended policy. The second checks a
  positive control and 32 bounded concurrent PUTs during reload, then backend
  bytes/length, GET status/body/length, and ListObjectsV2 sizes. It is
  supplemental concurrency coverage, not the sole reproduction gate or a
  timed load workload. Both use the same snapshot-loading/publication path as
  the server, with Testcontainers-managed providers and standard
  Docker-unavailable skips. No provider-name branching, global environment
  mutation in provider cases, extra container, or new CI target is needed.

```bash
# Repeat deterministic Tier 1 regressions under the race detector.
go test -race ./internal/config ./cmd/server -count=20 \
  -run 'Test(PolicyReload|PolicyLoad_Failure|ConfigApplier_Policy|ConfigApplier_CredentialFailure|ConfigReloader_CredentialsFilePolicyFailure)'

# Tier 2: both cases on all four local providers.
GATEWAY_TEST_SKIP_EXTERNAL=1 go test -race -tags=conformance \
  ./test/conformance -count=1 -timeout=10m \
  -run '^TestConformance/[^/]+/PolicyReload_'
```

These focused commands supplement the full Tier 1, local conformance, and
isolation gates; they do not replace them. Reload publication and operator
recovery are documented in [Policy Configuration](POLICY_CONFIGURATION.md).

### Presigned URL Lifetime Regressions (GH-345)

- **Tier 1:** `internal/api/presigned_time_test.go` signs requests using the
  independent AWS SDK SigV4 signer and backdates the signing timestamp, so a
  15-minute URL used after six minutes reproduces the bug immediately, without
  sleeps or Docker. Validator/middleware cases cover 15-/30-/60-minute and
  seven-day lifetimes, custom/default skew, expiry without a grace extension,
  future timestamps, strict expiry inputs and overflow, tampering, fixed XML,
  one auth-failure audit event, and no downstream invocation on rejection.
  An explicit request-time snapshot tests nanosecond expiry/skew boundaries
  and UTC-midnight crossings without a mutable global clock. Existing success
  and expiry tests require genuine valid signatures rather than allowing a
  signature mismatch to pass as expiry coverage.
- **Tier 2:** `test/conformance/presigned_time_test.go` registers
  `PresignedTime_Lifetime`, `PresignedTime_Failures`,
  `PresignedTime_InvalidExpiry`, and `PresignedTime_HeaderSkew` with capability
  `0`. These test **inbound gateway authentication**, not backend-generated
  presigning, so `CapPresignedURL` is not required. Every provider stores a
  real self-contained AES-KEK chunked object. Delayed SDK-signed GETs must
  return exact decrypted bytes and plaintext Content-Length. Invalid requests
  must return the expected S3 code/message/resource without issuing any
  gateway-to-backend HTTP request; a subsequent normal read remains healthy.
  The standard Testcontainers matrix and Docker-unavailable skips are retained,
  with no provider-name branches, extra containers, or new CI targets.

```bash
# Tier 1: repeat inexpensive production-validator/middleware regressions.
go test -race ./internal/api -count=20 -run '^TestPresignedTime_'

# Tier 2: all four local providers and existing presigned auth cases.
GATEWAY_TEST_SKIP_EXTERNAL=1 go test -race -tags=conformance \
  ./test/conformance -count=1 -timeout=10m \
  -run '^TestConformance/[^/]+/(PresignedTime_|Auth_PresignedURL_)'
```

These tests assert the corrected contract: the delayed-download and error
cases were confirmed red before the fix in Tier 1 and on all four local
providers. Focused checks supplement, not replace, full Tier 1/FIPS, local
conformance, and isolation gates. The [request-time contract](S3_API_IMPLEMENTATION.md#sigv4-request-time-and-presigned-expiration)
and [operator guidance](DEPLOYMENT.md#presigned-url-lifetime-and-clock-skew-gh-345)
describe expiry requirements and removing the widened-skew workaround.

### Object-read backend error regressions (GH-344)

- **Tier 1:** `internal/api/object_read_backend_test.go` uses real routes and
  authentic chunked-v2 ciphertext with targeted terminal/HEAD acquisition
  failures. Cases cover full and ranged GET, HEAD, CopyObject, UploadPartCopy,
  cached terminal validation and cached/ranged planning HEAD failures. Wrapped
  SDK `NoSuchKey`, `AccessDenied`, `SlowDown`, `ServiceUnavailable`, deadline and
  unknown failures assert exact status/code, source resource, no plaintext or
  diagnostic leakage, exactly-once accounting, no decrypt/tamper audit or
  metric, selected versions, and full-reader closure without body consumption.
  AES KEK positive and tampered-terminal controls preserve genuine crypto
  behavior. Error-owner tests prove that SDK errors from key managers are not
  classified as storage errors and that missing MPU manifests keep their
  distinct diagnostic. `TestTranslateError_BackendAvailability` checks 503
  mappings directly. Unit tests have no build tag or Docker requirement.
- **Tier 2:** `test/conformance/object_read_backend_test.go` registers
  `ObjectRead_BackendErrors` and `ObjectRead_BackendDeleteRace` with capability
  `0`, and `ObjectRead_BackendPartCopy` with `CapMultipartCopy`. Real providers
  handle writes, metadata, ciphertext reads and deletion; the existing harness's
  backend-transport option injects only terminal HTTP errors through the real
  SDK client. Self-contained AES KEK controls verify successful reads before
  and after faults. The delete-race case performs PUT → GET → DELETE, replays
  the frozen successful full backend response, and fails the terminal request
  with 404: this reproduces inconsistency deterministically without timing
  loops or reliance on a particular provider's consistency model. The ordinary
  Testcontainers provider matrix, capability skips and Docker-unavailable
  behavior remain unchanged. There are no provider-name branches or new CI
  targets.

```bash
# Tier 1, repeated under the race detector.
go test -race ./internal/api -count=5 \
  -run '^(TestObjectRead_|TestObjectBackendError_|TestTranslateError_BackendAvailability)'

# Tier 2, all four local providers.
GATEWAY_TEST_SKIP_EXTERNAL=1 go test -race -tags=conformance \
  ./test/conformance -count=1 -timeout=10m \
  -run '^TestConformance/[^/]+/ObjectRead_Backend'
```

The regression tests assert the intended corrected contract: before the fix,
the failure cases must be red, not skipped or changed to expect 500. These
focused checks supplement the full Tier 1/FIPS, local conformance and isolation
gates. See [S3 error translation](S3_API_IMPLEMENTATION.md#backend-error-translation)
and [failure observability](OBSERVABILITY.md#object-read-failure-classification-gh-344).

---

## How to add a new public S3 provider (plug-in recipe)

1. Create `test/provider/<vendor>.go`.
2. Register an `externalProvider` in `init()` with the vendor's endpoint,
   region, env-var names, capability bitmap, and cleanup policy:
   ```go
   func init() {
       if os.Getenv("GATEWAY_TEST_SKIP_EXTERNAL") != "" { return }
       ak := os.Getenv("ACME_ACCESS_KEY_ID")
       sk := os.Getenv("ACME_SECRET_ACCESS_KEY")
       bk := os.Getenv("ACME_BUCKET_NAME")
       if ak == "" || sk == "" || bk == "" { return }
       Register(&externalProvider{
           name:      "acme",
           endpoint:  "https://s3.acmecorp.com",
           region:    "us-east-1",
           keyEnv:    "ACME_ACCESS_KEY_ID",
           secretEnv: "ACME_SECRET_ACCESS_KEY",
           bucketEnv: "ACME_BUCKET_NAME",
           caps:      CapMultipartUpload | CapObjectTagging | CapBatchDelete,
           cleanup:   CleanupPolicyDelete,
       })
   }
   ```
3. Run `make test-conformance-external` with the vendor's credentials set.
4. If any conformance test fails because the vendor does not support a feature,
   **narrow the capability bitmap**, do not add a branch inside the test body.
5. If any test fails for a behavioural quirk (different error code shape), open
   a ticket — the gateway may need a compatibility fix.
6. Submit PR. CI picks up the new provider automatically when credentials are
   supplied as repo secrets.

**What the plug-in contract forbids:**

- Edits to `test/conformance/*.go` (provider-agnostic).
- Edits to the Makefile (targets iterate `provider.All()` automatically).
- `if providerName == "..."` branches outside the provider file.

---

## CI matrix

| Trigger       | Tier 1 | Local conformance                  | External conformance | Tier 3 |
|---------------|--------|------------------------------------|----------------------|--------|
| PR            | ✅     | ✅ (`make test-conformance-local`) | –                    | –      |
| `main` push   | ✅     | ✅ (`make test-conformance-local`) | –                    | –      |
| Nightly       | ✅     | ✅ (`make test-conformance-local`) | ✅ (with creds)      | –      |
| Release tag   | ✅     | ✅ (`make test-conformance-local`) | ✅                   | ✅     |

---

## Docker-only deployment model

All tier-2 tests use **Testcontainers-Go** to spin up backend containers on
demand. No `docker-compose up` is needed; containers are started per test and
cleaned up by Ryuk (a sidecar that tracks the test process and kills orphan
containers).

The `scripts/test-isolation.sh` script enforces this mechanically by failing
the build if any `test/*.go` file references `docker-compose`, binary
`exec.Command` invocations for backends, or hard-coded well-known ports.

To run the isolation check manually:

```bash
bash scripts/test-isolation.sh
# or
make test-isolation-check
```

---

## Troubleshooting

### Docker not running

```
SKIP: minio provider: failed to start container (Docker unavailable?): ...
```

Start Docker Desktop or the Docker daemon. All tier-2 tests skip cleanly
when Docker is unavailable.

### Port conflicts

Testcontainers-Go maps container ports to random host ports — there are no
hard-coded ports. If you see "address already in use", an old container may
be running. Ryuk cleans these up automatically, but you can also run:

```bash
docker ps -f label=org.testcontainers=true
docker rm -f <container-id>
```

### MinIO container slow to start

Testcontainers waits for the MinIO health check. If startup takes > 60 s
on a slow machine, set `TESTCONTAINERS_RYUK_TIMEOUT=120` in your environment.

### Credentials not set for external providers

External provider tests skip cleanly if the required env vars are absent:

```
SKIP: aws credentials not set (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_BUCKET_NAME)
```

Set the env vars to activate the provider in the test run.
