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
│ Every `go test ./...`, every PR, every push. Budget: < 60 s.     │
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

# FIPS build.
GOFIPS140=v1.0.0 go test -race -tags=fips ./...

# HSM stub build.
go test -race -tags=hsm ./...
```

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
SeaweedFS) against the following six encryption configurations in sequence:

| # | Config name                         | Key material          | Object / op         |
|---|-------------------------------------|-----------------------|---------------------|
| 1 | `Password_PBKDF2_Chunked`           | Password + PBKDF2     | 1 MiB PutObject     |
| 2 | `Password_Argon2id_Chunked`         | Password + Argon2id   | 1 MiB PutObject     |
| 3 | `AES256GCM_KEK_Chunked`             | AES-256-GCM KEK       | 1 MiB PutObject     |
| 4 | `RSA_OAEP_KEK_Chunked`              | RSA-OAEP/SHA-256 KEK  | 1 MiB PutObject     |
| 5 | `AES256GCM_KEK_EncryptedMPU_50MiB`  | AES-256-GCM KEK       | 4 × 50 MiB MPU      |
| 6 | `AES256GCM_KEK_RangedGet_MultiChunk`| AES-256-GCM KEK       | 200 KiB 5 sub-ranges|

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
```

**Environment variables:**

| Variable                  | Default     | Description                            |
|---------------------------|-------------|----------------------------------------|
| `BENCH_LOCAL_WORKERS`     | `8`         | Goroutines per config                  |
| `BENCH_LOCAL_DURATION`    | `30s`       | Duration per config                    |
| `BENCH_LOCAL_OBJECT_SIZE` | `1048576`   | PutObject payload size (bytes)         |
| `BENCH_LOCAL_MPU_SIZE`    | `52428800`  | Per-part MPU size (bytes, default 50 MiB)|
| `BENCH_LOCAL_JSON_OUT`    | *(empty)*   | NDJSON output file path (optional)     |

This suite is **not run in CI** (requires Docker and takes several minutes per
configuration). It is intended for manual performance verification and
regression detection between versions.

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
| `minio`    | `minio/minio:RELEASE.2024-...`  | `GATEWAY_TEST_SKIP_MINIO=1`     | Primary reference; PR gate uses this provider only |
| `garage`   | `dxflrs/garage:v2.3.0`          | `GATEWAY_TEST_SKIP_GARAGE=1`    | Rust-based; requires bootstrap via admin REST API  |
| `rustfs`   | `rustfs/rustfs:latest`          | `GATEWAY_TEST_SKIP_RUSTFS=1`    | Alpha-quality; capability bitmap is conservative   |
| `seaweedfs`| `chrislusf/seaweedfs:latest`    | `GATEWAY_TEST_SKIP_SEAWEEDFS=1` | Blob-store-backed S3 gateway; single-node CI mode  |

**RustFS note**: RustFS is explicitly labelled "Do NOT use in production" by
its authors as of 2026.  The provider is included to test gateway behaviour
against an actively-developed implementation and to provide early signal on
compatibility.  Failing RustFS tests are not a PR gate blocker; they are
tracked separately.

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
   `test/conformance/suite.go`'s `cases` slice with the required capability
   bit (or `0` if no capability is needed).
4. **Tier 3**: add to `test/load/`, `test/soak/`, or `test/chaos/` with the
   corresponding build tag.

**The conformance contract**: test bodies must never branch on provider names.
Use capability bits. The `TestConformance_NoProviderNameLiterals` AST check in
`test/conformance/matrix_selftest.go` enforces this mechanically.

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
