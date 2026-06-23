# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

### Security

### Fixed

### Changed

### Removed

### Dependencies

## [0.10.1] — 2026-06-23

### Added

- **V1.0-CONFIG-1 — Per-bucket encryption bypass + flat ENV policy config**:
  `PassthroughEngine` (no-op encryption) for buckets marked with
  `disable_encryption: true` in policy; HTTP 409
  `EncryptionConfigurationMismatch` is returned when a client tries to PUT
  an already-encrypted object into a bypass bucket. All `PolicyConfig` fields
  are now configurable via indexed environment variables (`GW_POLICY_N_*`)
  without any policy YAML files — hot-reload resets and reloads from both
  file and environment sources on every SIGHUP. Startup emits a warning for
  each policy with `disable_encryption: true`. See
  `docs/plans/V1.0-CONFIG-1-plan.md`.

### Fixed

- **Harbor ListObjects blob-size regression**: legacy single-PUT
  chunked-encrypted objects written before `MetaOriginalSize` was persisted
  exposed ciphertext sizes in small `ListObjects(max-keys=1)` stat-style
  listings (used by Docker Distribution as a `HeadObject` fallback).
  `handleListObjects` now translates object sizes to plaintext by looking
  up object metadata, matching the size-derivation logic already used by
  `HeadObject`. Keeps normal large listings fast while fixing Harbor
  compatibility for legacy encrypted blobs.

- **README Docker examples used stale credential env var names**
  (PR #195): the `docker run` snippets still referenced the pre-v0.8 names
  `GW_ACCESS_KEY_N` / `GW_SECRET_KEY_N` instead of the current
  `GW_CRED_N_ACCESS_KEY` / `GW_CRED_N_SECRET_KEY`. Only documentation
  changed — the variables the gateway reads have been `GW_CRED_*` since
  V1.0-AUTH-1.

### Dependencies

- Updated AWS SDK Go v2 monorepo to v1.104.0.
- Updated `github.com/cenkalti/backoff/v5` to v6.
- Updated `github.com/moby/moby/api` to v1.55.0.
- Updated `golang.org/x/perf` digest to 9e4b9dd.
- Updated Helm release valkey to ~0.10.0.
- Updated dependency helm to v4.2.2.
- Updated `actions/checkout` action to v7.
- Updated `github.com/redis/go-redis` to v9.21.0.
- Updated `testcontainers-go` monorepo to v0.43.0.

## [0.10.0] — 2026-06-09

### ⚠️ Breaking ⚠️

- **Built-in compression removed (V1.0-MAINT-2)**: The `compression` config
  stanza, `CompressionEngine`, compression metadata constants, and
  decompression-bomb guard are removed. All `NewEngine*` constructors and
  `NewEngineWithOpts` no longer accept a `compressionEngine` parameter.
  Users who need compressed+encrypted objects should compose with
  [s4](https://github.com/abyo-software/s4) before the gateway:

  ```
  client → s4 → s3-encryption-gateway → storage
  ```

  **Migration**: objects stored with `x-amz-meta-compression-enabled: true`
  must be re-uploaded (decrypt via old gateway version, re-upload
  uncompressed) before upgrading. See `docs/MIGRATION.md`.

- **`s3eg-migrate` offline migration tool removed (V1.0-CLI-2)**: The
  gateway-bypassing `s3eg-migrate` binary (batch re-encryption,
  `BackfillLegacyNoAAD`, KDF migration) is replaced by the read-only
  `s3eg-cli` audit tool. Re-encrypt legacy objects through the gateway
  using any standard S3 client:

  ```
  aws s3 cp s3://bucket/key - --endpoint-url $GATEWAY | \
    aws s3 cp - s3://bucket/key --endpoint-url $GATEWAY
  ```

  The gateway decrypts on GET via fallback paths and re-encrypts on PUT with
  current parameters. `s3eg-migrate` is retained as a deprecation shim.
  See `docs/MIGRATION.md` and `docs/S3_CLI_TOOLS.md`.

### Added

- **V1.0-KMS-1 — KMS Production Readiness**: Retry-with-backoff decorator
  (`RetryingKeyManager`), circuit-breaker decorator
  (`CircuitBreakerKeyManager`) with three-state fail-fast, DEK unwrap cache
  (`CachingKeyManager`) using true LRU with hit-time reordering, and periodic
  health-check goroutine. Four new Prometheus metrics:
  `gateway_kms_dek_cache_hits_total`, `gateway_kms_dek_cache_misses_total`,
  `gateway_kms_circuit_breaker_state`, `gateway_kms_retry_attempts_total`.
  KMS outage degraded-mode runbook section in `docs/RUNBOOK.md`.
  See `docs/plans/V1.0-KMS-1-plan.md`.

- **V1.0-S3-1 — ACL and Lifecycle Header Passthrough**: `PutObject` and
  `CreateMultipartUpload` now forward ACL inline headers
  (`x-amz-acl`, `x-amz-grant-*`) to the backend. Lifecycle headers
  (`x-amz-storage-class`, `x-amz-website-redirect-location`,
  `x-amz-server-side-encryption-*`, `x-amz-object-lock-*`) are passed through
  on PUT operations. Updated inline header passthrough feature matrix in
  `docs/S3_API_IMPLEMENTATION.md`. See `docs/plans/V1.0-S3-1-plan.md`.

- **V1.0-COMPAT-1 — SDK/Tool Compatibility Matrix**: Automated smoke tests for
  AWS SDK Go v2, boto3, awscli, s5cmd, rclone, and minio-py against all local
  providers. Published `docs/SDK_COMPATIBILITY.md` with pass/fail and caveats.
  CI `compat-matrix` job added to conformance workflow.
  See `docs/plans/V1.0-COMPAT-1-plan.md`.

- **V1.0-PERF-1 — Scale & Throughput Guidance**: Named load profiles
  (`make test-load-smoke`, `test-load-spike`, `test-load-high-throughput`)
  and `bench-load-capture` for all four profiles. Shipped tuned HPA overlay
  (`examples/values-hpa-tuned.yaml`) and KEDA `ScaledObject` example
  (`examples/values-keda-example.yaml`). Published `docs/SCALING.md` with
  empirical sizing tables, HPA configuration guidance, graceful-shutdown
  formulae, and three gateway SLOs (availability 99.9%, p99 latency 500ms,
  throughput 80% of linear). Load profile corpus committed under
  `docs/perf/v1.0-perf-1/`. Updated `docs/PERFORMANCE.md` with cross-reference
  and `docs/perf/v0.6-qa-1/slo-summary.md` with v1.0 SLO section.
  See `docs/plans/V1.0-PERF-1-plan.md`.

- **V1.0-OPS-1 — Supply-chain & Publishing**: Multi-arch images (linux/amd64,
  linux/arm64) published to Docker Hub via docker buildx; FIPS image
  (linux/amd64) published to Docker Hub with `-fips` tag suffix; SPDX-JSON
  SBOM generated by syft and attached to GitHub release assets; cosign keyless
  OIDC attestation on Docker Hub image digest (SLSA provenance); Artifact Hub
  annotations added to Chart.yaml; Artifact Hub annotation CI gate added to
  helm-test.yml; `make docker-buildx` and `make sbom` targets added for local
  developer parity. See `docs/plans/V1.0-OPS-1-plan.md`.

- **V1.0-ECOSYS-1 — Additional Backends via Shims**: New `backend.type`
  discriminator (`s3`, `gcs`, `azure`) with config validation and env-var
  wiring. GCS shim (`gcsClient`) with automatic metadata key lowercasing,
  32-part multipart-upload limit, and `CopyObject` LastModified fallback.
  Azure shim (`azureClient`) with metadata size/key validation (8 KiB limit),
  `BlobNotFound` → `NoSuchKey` mapping, and ObjectLock `NotImplemented` stubs.
  Test providers for GCS (external, gated by env vars) and Azure/Azurite
  (Testcontainers). Published `docs/BACKENDS.md` with per-backend caveat
  tables. Compile-time `var _ Client = ...` assertions verify all shims
  satisfy the S3 client interface. See `docs/plans/V1.0-ECOSYS-1-plan.md`.

- **V1.0-CLI-2 — Gateway-Aware Audit Tooling (`s3eg-cli`)**: New read-only
  audit binary with three sub-commands (`inspect`, `verify-key`,
  `list-algorithm`). Replaces the removed `s3eg-migrate` offline migration
  tool. Re-encryption now uses the GET-through-gateway → PUT-through-gateway
  pattern. Adds `encryption.allow_unmarked_no_aad_fallback` config flag
  (default false) for controlled no-AAD recovery. `s3eg-migrate` retained as
  a deprecation shim. See `docs/plans/V1.0-CLI-2-plan.md`.

- **Harbor integration guide**: Published `docs/integrations/harbor.md` with
  required storage configuration (`disableredirect: true` in Helm chart,
  `redirect.disable: true` in standalone `harbor.yml`), explanation of why the
  redirect path is incompatible with the gateway, and a map of Docker
  Distribution S3 driver calls to gateway behaviour.

### Removed

- **V1.0-CLI-1 — Developer CLI (rejected)**: The proposed `presign`, `put`,
  `get`, `head` CLI commands are fully covered by existing S3-compatible tools
  (`awscli`, `s5cmd`, `mc`). No gateway-specific wrapper binary is needed.
  Superseded by `docs/S3_CLI_TOOLS.md` and V1.0-CLI-2.

### Fixed

- **KMS-1 LRU ordering and close safety**: `CachingKeyManager` LRU upgraded
  from slice-based FIFO to `container/list`-based true LRU with hit-time
  reordering. Added `sync.Once` guard on `close(stopCleanup)` for double-close
  safety. Added `closed bool` flag to `CircuitBreakerKeyManager` to prevent
  Open→Half-Open recovery after `Close()`.

- **Auth: remove `AWSSecretAccessKey` extraction from URL query parameters**:
  SigV2 secret-key extraction from `?AWSAccessKeyId=...` query parameters
  (Method 1) is no longer supported. Only presigned-URL signatures (Method 2)
  and Authorization headers (Method 3) are recognised.

- **MPU part and manifest encryption metrics**: `gateway_encrypted_object_bytes`
  and `gateway_decrypted_object_bytes` are now correctly incremented for
  multipart-upload part uploads and manifest creations.

- **`ErrNotImplemented` tightened for backend shims**: GCS and Azure shims use
  a typed sentinel error (`errors.New`), allowing callers to detect unsupported
  operations via `errors.Is`.

- **Rclone compatibility**: bumped `--s3-copy-cutoff` from 0 to 1 for rclone
  1.68 minimum compatibility.

- **KDF legacy read nil-pointer**: fixed nil-pointer dereference in
  legacy-KDF-iteration fallback path when KDF params metadata is absent.

- **Harbor/Docker Distribution encrypted MPU compatibility**: plaintext-size
  translation for HeadObject, ListObjects, and ListParts so Docker Distribution's
  size checks (`statHead`, `statList`, `validateBlob`) see the correct byte count
  instead of inflated ciphertext sizes. Added `SourceClassMPUEncrypted`
  classification so `CopyObject` and `UploadPartCopy` correctly decrypt
  MPU-encrypted sources during Harbor's `moveBlob()` staging path. ListParts
  response now always includes `IsTruncated` (even when false) to prevent a
  nil-pointer dereference in Docker Distribution's S3 driver. Fixes
  "blob invalid length" errors when Harbor pushes images through the gateway.

- **Content-MD5 for Ceph/MinIO backends**: `PutObject` and `UploadPart` now
  compute and send the legacy `Content-MD5` header when the body is seekable.
  Older S3-compatible backends (Ceph, certain MinIO versions) require this
  header; AWS SDK v2 dropped automatic MD5 computation in favour of
  `x-amz-checksum-*`.

- **Passthrough client-auth stripping**: `forwardToBackend` now unconditionally
  strips `Authorization`, `X-Amz-Content-Sha256`, `X-Amz-Date`, and
  `X-Amz-Security-Token` headers, and removes presigned query parameters
  (`X-Amz-Signature`, `X-Amz-Credential`, etc.) before forwarding. The gateway
  always re-signs with its own backend credentials. Previously, the client's
  signature (bound to the original `Host` header) was forwarded verbatim,
  causing the backend to reject authenticated passthrough requests.

- **Negative-byte Prometheus panic**: `handlePassthrough` clamps
  `resp.ContentLength` from -1 (chunked encoding, no `Content-Length` header)
  to 0 before passing to the metrics counter. `RecordHTTPRequest` guards
  against `bytes <= 0`. Prevents a Prometheus `Counter.Add` panic on chunked
  backend responses.

- **PutObject ETag and oversized Range saturation**: `PutObject` now returns
  the backend ETag so the handler can surface it in the response header.
  `applyRangeRequest` saturates the range end to `dataLen-1` when the
  requested end exceeds the object size (RFC 7233 §4.2), instead of returning
  `416 Range Not Satisfiable`. Fixes s5cmd multipart downloads which request
  default 50 MiB parts that may exceed the final object size.

### CI & Dependencies

- Go version bumped to 1.26.4; CI images updated.
- Updated `github.com/aws/aws-sdk-go-v2` to v1.42.0, `aws-sdk-go-v2/service/s3`
  to v1.103.3, `aws-sdk-go-v2/config` to v1.32.25,
  `aws-sdk-go-v2/credentials` to v1.19.24.
- Updated `github.com/aws/smithy-go` to v1.27.2.
- Updated `golang.org/x/crypto` to v0.53.0.
- Updated `golang.org/x/perf` digest to 712aea8.
- Updated `github.com/cenkalti/backoff` from v4 to v5 (v5.0.3); stale v4
  direct dependency removed from `go.mod`; retry key manager migrated to v5.
- Updated `github.com/ovh/kmip-go` to v0.9.1.
- Updated `github.com/moby/moby/api` to v1.54.2 (for Azurite Testcontainers).
- Updated `github.com/redis/go-redis/v9` to v9.20.1.
- Updated `docker/setup-qemu-action` to v4, `docker/setup-buildx-action` to v4,
  `docker/login-action` to v4, `docker/build-push-action` to v7.
- Updated `sigstore/cosign-installer` to v4.
- Updated `aquasecurity/trivy-action` to v0.36.0.
- Updated Alpine Docker base image to v3.24; runtime stage now runs
  `apk upgrade` to pull patched libraries (fixes Trivy findings for
  `libcrypto3` and `libssl3`).
- Updated Helm CLI in CI workflows to v4.2.1.
- **Fixed prerelease flag in chart-releaser workflow**: removed invalid
  `releaseNotesFile` key from `.github/cr.yaml`; added explicit
  `gh release edit --prerelease` step after chart-releaser for versions
  with pre-release suffixes (`-rc*`, `-alpha*`, `-beta*`). Makes the
  GitHub release prerelease flag deterministic rather than relying on
  GitHub's SemVer heuristics.

## [0.9.0] — 2026-05-28

### ⚠️ Repository Migration ⚠️

- **GitHub repository moved**: `kenchrcum/s3-encryption-gateway` →
  `cloud37/s3-encryption-gateway`. Update any bookmarks, CI references, and
  `go get` import paths accordingly. The Go module path is now
  `github.com/cloud37/s3-encryption-gateway`.

- **Docker image moved**: `kenchrcum/s3-encryption-gateway` →
  `cloud37io/s3-encryption-gateway`. Update any `image:` references in
  Kubernetes manifests, Helm values, and `docker pull` commands.

- **Helm chart repository moved**: `https://kenchrcum.github.io/s3-encryption-gateway/`
  → `https://cloud37.github.io/s3-encryption-gateway/`. Update your `helm repo add`
  commands and FluxCD / ArgoCD `HelmRepository` resources.

### Security

- **Auth failure audit events on all rejection paths**: `auth.failure` audit
  events are now emitted on every S3 authentication rejection path (SigV4,
  SigV2, presigned URL) as well as on admin bearer-auth failures. Provides
  complete audit coverage for authentication events in SIEM and log aggregation
  pipelines.

- **V1.0-OPS-2 — Security scanning in CI pipeline**: Added `govulncheck`
  (dependency vulnerability scanning), `gosec` (static analysis), and Trivy
  (container image scanning) to the CI pipeline. A new `.github/workflows/security.yml`
  workflow runs both `govulncheck` and `gosec` on every PR to `main` and every
  push to `main`. The `helm.yml` release workflow builds the Docker image and
  runs Trivy with CRITICAL severity blocking the release. `Makefile` updated
  with `security-scan`, `gosec`, and `trivy-scan` targets for local parity.
  Initial `gosec` triage completed: 27 G115, 3 G402, 2 G703, 3 G704, 3 G101,
  1 G404 HIGH findings suppressed with `#nosec` annotations and documented in
  `docs/security/gosec-suppressions.md`. Gosec configured with `-severity=high`
  so only HIGH findings gate CI.

### Added

- **Argon2id KDF support** (V1.0-CRYPTO-1): New selectable KDF algorithm
  `"argon2id"` as an alternative to the default `"pbkdf2-sha256"`. Uses OWASP
  2024 defaults (m=19456 KiB, t=2, p=1). FIPS builds reject argon2id at
  config validation time. Backwards-compatible: existing objects encrypted with
  PBKDF2 are transparently decrypted via `x-amz-meta-kdf-params` metadata.
  Configurable via `kdf.algorithm`, `kdf.argon2id.*` YAML keys and
  `S3GW_KDF_*` environment variables. Helm chart and `config.yaml.example`
  updated with annotated argon2id stanza. Full multipart round-trip and
  conformance tests added; all existing PBKDF2 callers migrated to the new
  options API.

- **Valkey at-rest encryption for multipart-upload state** (V1.0-CRYPTO-2):
  All `UploadState` blobs persisted in Valkey are now encrypted with
  AES-256-GCM using a dedicated key derived via HKDF-SHA256. The encryption
  password is sourced from `VALKEY_ENCRYPTION_PASSWORD` (or falls back to the
  main `ENCRYPTION_PASSWORD` with a distinct salt). Backwards-compatible:
  plaintext blobs are read via a transparent fallback and expire naturally via
  TTL. Configurable via `multipart_state.valkey.encryption_password_env` and
  `encrypt_state`. Helm chart, schema, deployment template, and runbook
  (`docs/RUNBOOK.md`) fully updated.

- **Object metadata encryption** (V1.0-CRYPTO-3): All S3 object metadata values
  (e.g. user-supplied `x-amz-meta-*` headers) are now optionally encrypted
  at rest using AES-256-GCM with a dedicated metadata key. The `MetaEncrypted`
  marker is preserved outside the encrypted blob so the gateway can detect
  encrypted objects on `HEAD` and `GET` responses. Configurable via
  `crypto.metadata_encryption.key` / `METADATA_ENCRYPTION_KEY` environment
  variable. Mutual-exclusion validation prevents misconfiguration.
  Full metadata encryption round-trip, tamper-detection, and configuration
  validation tests included.

- **Turnkey dashboards and alerting** (V1.0-OBS-1): Grafana dashboard (8 rows,
  33 panels) and PrometheusRule (10 alert rules) now ship as opt-in Helm resources
  (`monitoring.grafana.dashboard.enabled`, `monitoring.prometheusRule.enabled`).
  8 new Prometheus metrics added: `gateway_kms_healthy`, `gateway_metadata_encryption_enabled`,
  `gateway_tls_cert_expiry_seconds`, `gateway_key_rotation_objects_total`,
  `gateway_kdf_algorithm_active`, `gateway_admin_api_requests_total`,
  `gateway_admin_api_request_duration_seconds`, `gateway_mpu_active_uploads`,
  `gateway_encrypted_object_bytes`. Dashboard supports stacked-by-pod
  visualisation with `$pod`/`$namespace`/`$datasource`/`$interval` template
  variables. Local verification via `hack/export-dashboard.sh`. Documentation
  updated in `docs/OBSERVABILITY.md` and `docs/RUNBOOK.md`.

- **Dedicated decrypt-bytes metrics for MPU and full-object GET paths**:
  `gateway_decrypted_object_bytes` is now incremented on both the MPU and
  single-object `GetObject` code paths, giving accurate decryption throughput
  metrics for all read paths.

- **Self-contained envelope encryption provider** (V1.0-KMS-4): New
  `"self_contained"` `KeyManager` adapter supporting AES-256-GCM (symmetric)
  and RSA-OAEP/SHA-256 (asymmetric) DEK wrapping with no external KMS
  dependencies. Includes `AESKEKManager` (with `RotatableKeyManager` for key
  rotation), `RSAKEKManager`, factory registration, env-var injection
  (`SELF_CONTAINED_AES_KEYS`), YAML config schema, ADR-0013, and full test
  suite (unit, conformance, fuzz, integration). Wired as the default Helm
  KMS provider. See `docs/KMS_COMPATIBILITY.md` for configuration examples.

  **Updated between rc1 and rc2**: The Helm `selfContained.aes.keys` value
  was restructured from a flat composite string (`"1=env:VAR,2=env:VAR2"`) to
  a list of typed entries. Each entry specifies a `version` and exactly one of
  `value` (inline base64), `secretKeyRef`, or `configMapKeyRef`. The chart
  synthesises `SELF_CONTAINED_AES_KEY_V{version}` env vars and the
  `SELF_CONTAINED_AES_KEYS` composite string automatically. Kubernetes Secrets
  synced from HashiCorp Vault or other secrets managers can now be referenced
  directly without manual string composition:
  ```yaml
  selfContained:
    aes:
      keys:
        - version: 1
          secretKeyRef:
            name: s3-gateway-master-key
            key: master_key
  ```

- **`ENCRYPTION_MODES.md` guide**: new documentation page covering all
  supported encryption modes, KDF options, and provider-specific
  compatibility notes.

- **SigV2 policy flag and presigned URL expiry cap**: a new
  `auth.allow_sigv2` policy flag (default `true`) lets operators disable
  SigV2 entirely per-bucket or globally. Presigned URL `Expires` query
  parameter is capped to a configurable maximum (default 7 days) consistent
  with the SigV4 presigned URL cap introduced in 0.8.0.

### Performance

- **`DecryptRangeOptimized` — zero-seek range decryption**: new
  `DecryptRangeOptimized` method on the crypto engine that assumes the
  caller has already fetched only the ciphertext byte-range from the backend.
  The range-decrypt reader is extended with an `isOptimizedSource` flag that
  skips all forward chunk-seeking when the source is already aligned to the
  requested range. `handleGetObject` now uses this path, removing unnecessary
  full-object reads on ranged GETs. Range-decryption failures now escalate to
  `InternalError` instead of silently falling back to a full-object read (which
  would read beyond the already-applied backend byte-range).

### Fixed

- **`FallbackKeyManager` for legacy password-wrapped MPU DEKs**: objects
  written before a self-contained KEK provider was activated store their
  `WrappedDEK` with `provider="password"`. After upgrading, `serveMPURangedGet`
  routed all `UnwrapKey` calls to the new primary `KeyManager`, which returned
  `ErrUnwrapFailed` because it cannot unwrap a PBKDF2+AES-GCM envelope.
  Introduced `FallbackKeyManager` (`internal/crypto/keymanager_fallback.go`)
  that wraps a primary `KeyManager` with a `passwordKeyManager` fallback:
  `UnwrapKey` tries the primary first; if `ErrUnwrapFailed` is returned and
  `envelope.Provider == "password"`, it falls back to the password KM.
  `WrapKey` always delegates to the primary so new objects are never written
  with legacy password wrapping. No config changes required.

- **`BuildKeyManager` — self-contained provider no longer falls through**: the
  `self_contained` provider fell through to the generic default branch in
  `BuildKeyManager`, which called `crypto.Open` with an empty config map,
  causing the runtime error `keymanager/self-contained: "type" field is
  required (must be "aes" or "rsa")`. A dedicated `"self_contained"` case now
  constructs the config map from `cfg.SelfContained` and delegates correctly.

- **`x-amz-meta-encrypted` no longer filtered from HEAD responses**: the
  `x-amz-meta-encrypted` marker was incorrectly stripped from `HEAD` object
  responses, preventing clients from detecting encrypted objects. It is now
  preserved and forwarded.

- **Go module path corrected** after repository migration: stale
  `github.com/kenchrcum/s3-encryption-gateway` import paths updated
  throughout the codebase to `github.com/cloud37/s3-encryption-gateway`.

- **`internal/api` mock `GetObject` byte-range support**: the race-detector
  test `TestContentRangeMapping/last_byte` failed because
  `mockS3Client.GetObject` ignored the `Range` request header,
  causing the range-optimised decrypt reader to read the wrong chunk
  and fail AEAD authentication. The mock now respects byte ranges,
  matching the behaviour of `mpuMockS3Client`.

- **`export-dashboard.sh` unbound variable**: a missing variable reference
  in `hack/export-dashboard.sh` caused the script to fail with `unbound
  variable` in strict-mode shells. Fixed.

- **SeaweedFS conformance test volume size**: test volume increased from
  128 MiB to 1 GiB to prevent OOM kills on full-matrix benchmark runs.

### CI & Infrastructure

- **Encryption benchmark matrix** (`make benchmark-local`): new benchmark
  infrastructure covering 18 configurations across three operation types
  (Chunked PutObject, Encrypted MPU, RangedGet) and all encryption modes
  (PBKDF2 100k/600k, argon2id, AES KEK, RSA KEK, Cosmian KMIP). Results are
  emitted as NDJSON for automated regression gating. Benchmark configs include
  a 100k PBKDF2 floor (for comparison only — not production-recommended) and
  KMIP-backed ranged-read scenarios. Full results published in
  `docs/ENCRYPTION_MODES.md`.

- **Grafana dashboard overhaul**: the bundled Grafana dashboard
  (`helm/s3-encryption-gateway/dashboards/s3-encryption-gateway.json`) was
  substantially expanded — 432 lines → 2239 lines, adding per-mode encryption
  throughput panels, KMS health status, metadata encryption indicators, and
  improved template variable support.

- **Conformance test timeout increased to 30 minutes**: the
  `test-conformance-local` CI job timeout raised from the previous default
  to 30 minutes to accommodate the full multi-provider conformance matrix
  without spurious timeouts on slow CI runners.

- **Conformance tests unified across all local providers**: MinIO- and
  Garage-specific CI jobs removed; all conformance tests now run against
  the full set of local providers (MinIO, Garage, RustFS, SeaweedFS) in a
  single job matrix, reducing CI surface area and duplication.

- **Go version bumped to 1.26.3**: CI and Docker images updated to Go 1.26.3;
  FIPS build jobs skip non-FIPS algorithm tests to avoid false failures.

- **`gosec` runs via `go run`**: the `gosec` CI step now uses `go run
  github.com/securego/gosec/...` instead of a Docker image to avoid
  Go version mismatches between the CI runner and the gosec image.

- **Helm release skips duplicate publish**: the chart-releaser step in the
  release workflow is skipped when the chart version has already been
  published, and the binary-build and README-copy steps are also skipped
  accordingly — preventing duplicate-release errors on documentation-only
  pushes.

- **Conformance tests run per-provider in a CI matrix**:
  `conformance-local` now shards MinIO, Garage, RustFS, and SeaweedFS
  across four parallel jobs (one provider per `ubuntu-latest` runner)
  instead of running all providers concurrently on a single runner.
  Prevents resource exhaustion (SIGTERM / exit 143) caused by simultaneous
  Docker container startup under the `-race` memory overhead.

- **Removed `needs: [unit]` from conformance-local**: conformance tests
  now execute in parallel with unit tests rather than waiting for them,
  reducing overall PR gate wall-clock time.

- **RustFS test environment compatibility**: the conformance test fixture
  now sets `RUSTFS_ALLOW_INSECURE_DEFAULT_CREDENTIALS=true` to accommodate
  `rustfs/rustfs:latest` rejecting default credentials on non-loopback
  interfaces.

- **Performance-baseline workflow label fix**: removed the `--label
  perf-regression` requirement from `gh issue create` and `gh issue list`
  calls in `.github/workflows/performance-baseline.yml` to fix failures
  when the repository does not have that label.

### Dependencies

- Updated `golang.org/x/crypto` to v0.52.0
- Updated `aws-sdk-go-v2/config` to v1.32.18, `aws-sdk-go-v2/credentials` to v1.19.17, `aws-sdk-go-v2/service/ssooidc` to v1.36.0
- Updated `ghcr.io/cosmian/kms` to 5.22.0
- Updated `go.opentelemetry.io/otel` monorepo to v1.44.0
- Updated `github.com/aws/aws-sdk-go-v2/service/s3` to v1.102.0
- Updated `github.com/aws/smithy-go` to v1.26.0
- Updated `github.com/redis/go-redis/v9` to v9.20.0

## [0.8.0] — 2026-05-18

### ⚠️ Breaking ⚠️

- **Unified credential store replacing `use_client_credentials`** (V1.0-AUTH-1):
  the legacy `use_client_credentials` boolean passthrough has been removed. A
  new `auth.credentials` configuration block supports multiple named
  `GatewayCredential` entries. A `CredentialStore` interface and
  `StaticCredentialStore` handle per-credential S3 client construction;
  `AuthMiddleware` dispatches SigV4 and SigV2 validation against the
  configured credential set. The Helm chart removes `useClientCredentials` in
  favour of `auth.credentials`.

  **Migration**: replace `backend.use_client_credentials: true` with
  `auth.credentials` entries matching your S3-compatible backend credentials.
  See `config.yaml.example` and ADR-0012 for the new format.

### Security

This release addresses all 23 findings from the 2026-05-04 deep security
analysis. As documented in that report (§7), **none of the findings
represent immediately exploitable remote vulnerabilities in a correctly
deployed instance**. They are defence-in-depth gaps, design-level
correctness improvements, and hardening measures. The gateway was safe to
run before this release; these changes raise the security floor further.

#### Defence-in-Depth & Design Correctness

- **`context.Context` propagation through `EncryptionEngine`** (V1.0-SEC-C02):
  `Encrypt`, `Decrypt`, `DecryptRange`, and the fallback v2 decoder now
  accept a `context.Context` as their first argument. KMS wrap/unwrap
  operations (KMIP over TLS) are now cancellable when the originating HTTP
  request is cancelled or times out, preventing goroutine leaks under KMS
  outage. OpenTelemetry spans created inside the engine are now children of
  the HTTP request span, restoring distributed trace continuity.

- **Remove `defaultWriter` audit fallback** (V1.0-SEC-C01): the
  `defaultWriter` type — which emitted raw audit events via `fmt.Printf`
  without applying field redaction — has been removed. `StdoutSink` (which
  correctly applies `redactMetadata`) is now the fallback when no explicit
  sink is configured. Sensitive metadata fields (object keys, algorithm
  identifiers, KMS key IDs) can no longer appear unredacted in container
  log streams via this path.

- **Length-prefixed AAD canonicalization** (V1.0-SEC-H01): `buildAAD` now
  uses a length-prefixed TLV encoding (`writeLengthPrefixed`) instead of
  a bare pipe-delimited concatenation. The previous format allowed a crafted
  metadata value containing a pipe character to produce an AAD collision
  between two distinct objects. The new format is injection-proof. Legacy
  objects continue to decrypt via the retained `buildAADLegacy` path;
  `s3eg-migrate --migration-class sec-h01` re-seals objects under the new
  AAD scheme.

- **Remove `keyResolver` two-oracle path** (V1.0-SEC-H02): the
  `keyResolver` feature (struct field, both constructors, `SetKeyResolver`,
  `WithKeyResolver` option) has been removed entirely. It created a
  second GCM oracle that could be queried without AAD verification when
  an attacker had S3 backend write access. The single-key
  `MetaLegacyNoAAD` fallback for explicitly tagged legacy objects is
  retained as a documented backward-compatibility path.

- **Configurable PBKDF2 iteration count, default raised to 600 000**
  (V1.0-SEC-H03): the default PBKDF2 iteration count is raised from
  100 000 to 600 000 (NIST SP 800-132 §5.3, 2023 guidance). The count
  is now operator-configurable via `crypto.kdf.pbkdf2.iterations` and is
  recorded in per-object metadata so mixed-iteration deployments decrypt
  correctly. An Argon2id compile-time gate is included for future
  migration. KDF parameters are propagated by the migration tool
  (`s3eg-migrate --migration-class sec-h03`). New config key:
  `crypto.kdf.pbkdf2.iterations` (default `600000`).

- **Decompression bomb protection** (V1.0-SEC-M05): `io.LimitReader` is
  now applied immediately after `Decompress` returns on both the primary
  and fallback decrypt paths. The limit is
  `MetaCompressionOriginalSize + 65536` bytes (64 KiB format-overhead
  tolerance). Objects without a recorded original size are still decompressed
  without a limit (as before), but objects that carry the size metadata are
  now bounded.

#### Hardening & Operational Correctness

- **Single `time.Now()` capture + credential-date cross-check**
  (V1.0-SEC-H04): `ValidateSignatureV4` now captures a single
  `now := time.Now().UTC()` at entry and reuses it for all time-based
  checks. The credential-date component of the scope string is
  cross-validated against `now` (±1 day) to prevent attackers from
  constructing a credential scope that maps to a different signing key.
  Presigned URLs with `X-Amz-Expires` values exceeding 7 days (604 800
  seconds) are now rejected with `400 AuthorizationQueryParametersError`
  (V1.0-SEC-M04).

- **Admin token zeroized on shutdown** (V1.0-SEC-H05): `AdminServer.Shutdown()`
  now calls `zeroBytes(s.tokenCache)` and sets `s.tokenCache = nil` before
  returning, ensuring the bearer token is cleared from memory when the
  process is shutting down.

- **Rate limiter client map cap** (V1.0-SEC-H06): the in-memory per-client
  token-bucket map is now bounded by `maxRateLimitClients = 100 000`
  entries. Requests from clients beyond that limit are served without
  rate limiting rather than expanding the map without bound, preventing
  a slow-path memory exhaustion attack.

- **TLS config for audit HTTP sink** (V1.0-SEC-H07): the audit HTTP sink
  now accepts a `SinkTLSConfig` block (`ca_file`, `cert_file`, `key_file`,
  `insecure_skip_verify`, `min_version`). `min_version` is validated at
  startup and only `"1.2"` and `"1.3"` are accepted. The configured
  `tls.Config` is wired into the sink's `http.Transport`, replacing the
  previous default (system CA pool, TLS 1.0 minimum). New config keys:
  `audit.http.tls.*`.

- **Policy manager reloaded on hot-reload** (V1.0-SEC-M06):
  `ApplyConfigChanges` now calls `policyManager.LoadPolicies` after
  successfully applying a config file update. Previously, policy files
  were only read at startup; a hot-reload could silently leave stale
  policy in effect.

- **Hot-reload config path guard corrected** (V1.0-SEC-M03): the
  `configPath != "config.yaml"` string comparison that prevented
  hot-reload from triggering for any config file named something other
  than the default has been removed. Hot-reload now triggers for any
  non-empty `configPath`.

- **Valkey TLS `min_version` validated** (V1.0-SEC-M07): `buildTLSConfig`
  for the Valkey connection now validates the configured `min_version`
  string via an explicit switch. Unknown values return an error at
  startup rather than silently defaulting to the Go TLS minimum. Empty
  string and `"1.3"` default to TLS 1.3; `"1.2"` is accepted explicitly.

- **Batch-sink flush errors routed through `slog`** (V1.0-SEC-M02):
  `BatchSink` flush errors are now emitted via `slog.Error(...)` instead
  of being written to `os.Stderr` with `fmt.Fprintf`. Audit infrastructure
  errors now appear in structured log output alongside all other server
  errors, and are visible in log aggregation pipelines.

- **Unknown YAML config keys rejected** (V1.0-SEC-L04): the config YAML
  decoder now calls `dec.KnownFields(true)`. Typos and unrecognised keys
  in `config.yaml` are rejected at startup rather than silently ignored,
  preventing misconfiguration from going undetected.

#### Post-RC1 Security Hardening

- **Token file permission check at startup** (V1.0-SEC-M08): `buildTokenSource()`
  now calls `os.Stat()` on the admin bearer-token file before reading it and
  hard-fails startup if the file is group- or world-readable (`perm & 0077 != 0`).
  Previously only the periodic refresh loop checked permissions, allowing a
  world-readable token file to be silently accepted on initial load.

- **Require CA certificate when `InsecureSkipVerify` is enabled**
  (V1.0-SEC-M09): `buildCosmianTLSConfig()` now returns a hard error when
  `InsecureSkipVerify=true` but no `ca_cert` is configured. This prevents a
  fully unverified TLS connection to the KMS endpoint with no pinned trust
  anchor.

- **Harden TLS config in `forwardSignatureV4Request`** (V1.0-SEC-M10):
  the request-forwarding path used by CopyObject/UploadPartCopy now enforces
  TLS 1.2 minimum, restricted cipher suites, and curve preferences matching
  the main S3 client.

- **`ForceHTTPS` config for HSTS behind reverse proxies** (V1.0-SEC-M11):
  a new `server.force_https` setting unconditionally sends the
  `Strict-Transport-Security` header regardless of `r.TLS`. In deployments
  behind TLS-terminating reverse proxies, HSTS was previously never emitted
  because Go sees `r.TLS == nil`, leaving clients vulnerable to SSL-stripping.

- **ProxyClient TLS hardening** (V1.0-SEC-M12): `NewProxyClient` replaces
  the bare `&http.Client{}` with a fully configured transport enforcing TLS 1.2
  minimum, restricted cipher suites (AES-256-GCM / CHACHA20-POLY1305), X25519/P-256
  curves, and connection timeouts (60s total, 90s idle, 10s response header).
  This aligns the proxy transport with the hardened TLS configs used elsewhere.

- **`x-amz-tagging` redacted from traces and logs** (V1.0-SEC-M13): `x-amz-tagging`
  moved from the safe-headers list to the sensitive-headers list in tracing
  middleware and added to the sensitive-query-params list in logging middleware.
  Object tags can contain PII or business-sensitive metadata.

- **SigV2 time-bound validation** (V1.0-SEC-M14): `ValidateSignatureV2` now
  validates the `Date` header (±5 min clock skew) and `Expires` query parameter
  against server time, preventing indefinite replay of captured SigV2 requests.
  Previously SigV2 had no temporal checks at all.

- **Query-param secret-key extraction flagged** (V1.0-SEC-M15): a new
  `FromQueryParam` field on `ClientCredentials` lets callers detect when the
  secret key was extracted from the URL query string (Method 1) and log a
  security warning. Methods 2 (presigned URL) and 3 (Authorization header)
  set `FromQueryParam=false`.

### Added

- **Dedicated unauthenticated metrics listener** (V1.0-OBS-2): a new
  `metrics.addr` configuration key (`METRICS_ADDR`) enables serving `/metrics`
  on a dedicated HTTP port separate from both the S3 data-plane and the admin
  port. Access control is delegated to Kubernetes NetworkPolicy. Fallback chain
  preserved: if `metrics.addr` is empty and admin is enabled, `/metrics` stays on
  the admin port; if admin is also disabled, it falls back to the S3 port.
  Helm chart templates (service, ServiceMonitor, PodMonitor, NetworkPolicy)
  are updated for the dedicated listener.

- **S3 passthrough handlers for bucket/object subresources** (V1.0-S3-2):
  generic passthrough (`handlePassthrough` + `forwardToBackend`) proxies S3
  subresource requests to the upstream backend with hop-by-hop header stripping
  and SigV4 signing. New routes include `ListBuckets`, `DeleteBucket`, bucket
  subresources (location, versioning, ACL, policy, CORS, lifecycle, encryption,
  notification, replication, logging, requestPayment, website, inventory,
  analytics, intelligent-tiering, uploads), object subresources (tagging get/put/delete,
  ACL get/put, restore), `POST /{bucket}/{key}?select` (`501 NotImplemented`),
  and `OPTIONS` CORS preflight. See `docs/S3_API_IMPLEMENTATION.md`.

### Changed

- **Multipart upload encryption now defaults to `true`** (V0.6-SEC-3 follow-up):
  `EncryptMultipartUploads` changed from `bool` to `*bool` so an omitted field
  defaults to `true`. Buckets without an explicit policy now require MPU
  encryption by default; operators must set `encrypt_multipart_uploads: false`
  to opt out.

### Fixed

- **XML injection prevention in ListObjects response**: `generateListObjectsXML`
  now uses `encoding/xml.Marshal` instead of raw string concatenation, preventing
  XML injection when object keys contain XML-special characters.

- **Object lock handlers routed to correct client**: `PutObjectRetention`,
  `GetObjectRetention`, `PutObjectLegalHold`, `GetObjectLegalHold` now use the
  proxied backend client instead of the service-account client, fixing
  `AccessDenied` failures when `auth.credentials` is in use.

- **SeaweedFS conformance test disk-full handling**: the conformance test suite
  now handles `OutOfSpace` errors from SeaweedFS gracefully instead of failing
  the entire suite.

- **Orphaned MPU manifest cleanup on object deletion** (#140): `DeleteObject`
  and `DeleteObjects` now issue a best-effort delete for the companion
  `<key>.mpu-manifest` file after a successful primary delete. A 404 on the
  manifest delete is silently ignored; unexpected errors are logged but never
  propagate as primary delete failures.

- **Backend error body truncation in CopyObject / UploadPartCopy**: backend
  error response bodies are now truncated to 1 KiB via `io.LimitReader`,
  preventing unbounded backend internals (stack traces, infrastructure URLs)
  from leaking into application logs.

- **BoundedQueue context-cancellation hang** (V1.0-S3-2): blocked `Read`/`Write`
  callers in `BoundedQueue` are now broadcast-woken when the queue's context is
  cancelled, preventing indefinite hangs during server shutdown.

- **ListObjects performance and v1 pagination correctness** (V1.0-S3-2): removed
  the serial per-object `HeadObject` loop that caused N-fold latency explosion
  for large listings. `ListObjects` now returns backend ciphertext sizes directly;
  accurate plaintext sizes remain available via `HeadObject` and `GetObject`.
  Fixed `<MaxKeys>` XML element to emit the requested limit instead of the
  returned count. Fixed v1 marker query parameter being ignored; mapped to
  `StartAfter` with `<NextMarker>` in the XML response.

- **Canonical original-size metadata key** (V1.0-S3-2): removed duplicate
  `x-amz-meta-original-content-length` metadata key in favour of the canonical
  `x-amz-meta-encryption-original-size`. `handlePutObject` now passes the
  original size as `Content-Length`, which the engine already reads;
  `filterS3Metadata` strips the standard header before sending to S3.
  Backward-compatible fallback to `original-content-length` retained for
  existing objects.

- **Hot-reload gracefully disabled when config file is absent**: when running
  with environment-variable-only configuration (e.g. Helm deployments), the
  server now detects the missing config file and disables hot-reload instead
  of failing.

### Dependencies

- Updated `golang.org/x/crypto` to v0.51.0
- Updated `golang.org/x/sys` to v0.44.0
- Updated `golang.org/x/perf` digest to 3cf3409
- Updated `github.com/alicebob/miniredis/v2` to v2.38.0

### Documentation

- Added V1.0-AUTH-1 design documentation (ADR-0012, architecture, deployment,
  and README updates) for the unified credential store.
- Added CRYPTO-2 issue tracking Valkey at-rest encryption for a future release.
- Added prominent production warning to `InsecureAllowPlaintext` in config
  example and Helm chart values.
- Added `SECURITY.md` with security policy and vulnerability reporting
  procedures.

## [0.7.2] — 2026-05-07

### Fixed

- **Default `ReadTimeout` disabled** (#135 follow-up): the default 15-second
  `ReadTimeout` set a hard TCP connection deadline that fired mid-stream on
  large object downloads regardless of `WriteTimeout` settings.  `ReadTimeout`
  now defaults to `0` (disabled); `ReadHeaderTimeout` (10s) continues to guard
  against slow-loris attacks.  Helm values `config.server.readTimeout` and
  `config.server.writeTimeout` are both updated to `"0s"`.

- **Active streaming write-deadline refresh** (#135 follow-up): even when
  `WriteTimeout` is set to a non-zero value (either explicitly in config or
  via `SERVER_WRITE_TIMEOUT`), the gateway now extends the HTTP write deadline
  every `timeout/2` interval while bytes are actively flowing. This prevents
  long-running S3 object downloads from being killed mid-stream, regardless of
  the configured timeout value.

- **Network-error handling on standard encrypted GET path**: the non-MPU
  `GetObject` streaming path now also distinguishes network aborts from
  decryption failures and logs them at Warn level rather than Error, matching
  the MPU path introduced in 0.7.1.

### Dependencies

- Updated `github.com/aws/aws-sdk-go-v2/service/s3` to v1.101.0

## [0.7.1] — 2026-05-06

### Fixed

- **MPU large-object restore timeout** (#135): the default 15-second HTTP
  `WriteTimeout` caused the server to abort TCP connections mid-stream when
  restoring large encrypted multipart-upload objects (e.g. CNPG backups with
  multi-part data). The default `WriteTimeout` is now disabled (0) so the
  gateway can stream arbitrarily large objects without artificial cut-offs.
  Operators who rely on a hard deadline can still set `write_timeout` in the
  server configuration. (Note: `ReadTimeout` also required disabling — see 0.7.2.)

- **Misleading tamper-detection log on network errors**: when a client
  disconnect or network timeout occurred during an MPU object stream, the
  gateway logged it as `"MPU decrypt failed mid-stream after 200 OK"` and
  emitted `mpu_tamper_detected_midstream` audit/metric events. The handler
  now distinguishes `*net.OpError` timeouts, `ECONNRESET`, and `EPIPE` from
  actual authentication failures, logging network aborts at Warn level with
  no tamper side-effects.

## [0.7.0] — 2026-05-04

### Security

- **HKDF-based chunk-IV derivation** (V1.0-SEC-2): new chunked objects now
  use HKDF-SHA256 instead of XOR for per-chunk IV derivation. Objects carry
  `x-amz-meta-enc-iv-deriv="hkdf-sha256"`; legacy objects without the flag
  continue to decrypt via the retained XOR read path (deprecated until v3.0).
  Operators can migrate legacy objects with `s3eg-migrate --migration-class sec2`.

- **Restrict AAD fallback to explicitly marked legacy objects** (V1.0-SEC-4):
  the blind `gcm.Open(..., nil)` fallback is now gated behind
  `x-amz-meta-enc-legacy-no-aad="true"`. New objects never receive this flag.
  Recovery path: `s3eg-migrate backfill-legacy-no-aad` followed by
  `s3eg-migrate --migration-class sec4`.

- **Streaming chunked metadata-fallback format v2** (V1.0-SEC-27): eliminates
  the redundant outer `aead.Seal` from `encryptChunkedWithMetadataFallback`.
  The fallback body is now a streaming
  `[4-byte BE metadata_length][metadata_json][chunked_stream]`. Peak allocation
  is now O(chunkSize + metadataSize) regardless of object size. A new
  `x-amz-meta-encryption-fallback-version: "2"` header identifies the format;
  legacy objects remain readable via the preserved v1 decoder.

- **UploadPartCopy buffer caps** (V1.0-SEC-29): capped two unbounded
  `io.ReadAll` calls in chunked-source `UploadPartCopy` handling at
  `maxCopyPartRangeBytes` (5 GiB). All `io.ReadAll` sites now have consistent
  bounding comments.

### Added

- **Offline migration tool** (`s3eg-migrate`) (V1.0-MAINT-1): new CLI for
  batch re-encryption and format migration. Supports scoped migration
  (`--migration-class all | sec2 | sec4 | sec27`), dry-run, post-write
  verification, resumable state file, and a `backfill-legacy-no-aad`
  sub-command. See `docs/MIGRATION.md`.
- `Makefile` targets `migrate`, `migrate-multiarch`, `build-multiarch`.
- `.github/workflows/helm.yml` now builds and attaches `s3eg-migrate` binaries
  (linux/amd64, linux/arm64, darwin/arm64) to every Helm chart release.

### Changed

- Exported `IsEncryptionMetadata` and `IsCompressionMetadata` from
  `internal/crypto/engine.go` so the migration tool can reuse them.

### Fixed

- **Constant-time token comparison** in `internal/admin/auth.go`: replaced
  string equality with `hmac.Equal` for bearer-token validation.
- **Chunked-mode startup warning** in `cmd/server/main.go`: emits an explicit
  `WARN`-level log when `chunked_mode: true` is set, reminding operators that
  chunked encryption is opt-in and has provider-specific compatibility
  implications.

### Dependencies

- Updated `github.com/fsnotify/fsnotify` to v1.10.1

---

## [0.6.4] — 2026-04-29

### Security

This patch release addresses eighteen security findings from the v1.0 deep
security analysis (DAF-01 through DAF-18). All fixes are non-breaking; no
configuration changes are required unless noted.

- **SigV4 header auth: clock-skew / replay protection** (V1.0-SEC-11):
  `ValidateSignatureV4` now validates `X-Amz-Date` against server time for
  header-based SigV4 requests using a configurable clock-skew tolerance
  (`auth.sigv4_clock_skew`, default 5 minutes). A monotonic request counter
  (`X-Amz-Nonce`) is supported as an optional anti-replay mechanism.

- **Remove key padding in `deriveKey`** (V1.0-SEC-12):
  Removed the catastrophic fallback that repeated the key prefix to reach
  `keySize`. Keys shorter than 32 bytes now return an error immediately.
  Companion validation added in `decryptChunked` and `DecryptRange`
  (V1.0-SEC-15), so unexpectedly short KMS keys are rejected rather than
  padded.

- **Bounded goroutine spawning in audit BatchSink** (V1.0-SEC-13):
  `BatchSink.WriteEvent` now uses a semaphore (`maxConcurrentFlushes`)
  instead of spawning unbounded goroutines. Events dropped under backpressure
  are counted by `dropped_audit_events_total`.

- **Streaming chunked encryption** (V1.0-SEC-14):
  `encryptChunked` no longer calls `io.ReadAll` on the entire plaintext.
  Memory usage is now bounded by the chunk pipeline regardless of object size.

- **Trusted-proxy-aware tracing middleware** (V1.0-SEC-16):
  `TracingMiddleware` now uses the existing `TrustedProxies` configuration
  when extracting client IPs for `http.client_ip` span attributes. It no
  longer blindly trusts `X-Real-IP` or the leftmost `X-Forwarded-For` entry.

- **Redact presigned signatures from OTel spans** (V1.0-SEC-17):
  `HTTPURL` span attributes now contain `scheme://host/path` only. The query
  string (including `X-Amz-Signature`) is excluded; a separate redaction-safe
  `http.query` attribute is available when `redactSensitive=false`.

- **Remove debug Printf from S3 client** (V1.0-SEC-18):
  All `debug.Enabled()` blocks in `internal/s3/client.go` now use
  `slog.Debug(..., "len", len(v))` instead of `fmt.Printf` with 30-character
  value previews. No raw metadata (salt, IV, wrapped key) is ever logged.

- **Remove double-buffering in metadata fallback encrypt** (V1.0-SEC-27):
  `encryptWithMetadataFallback` no longer holds both plaintext and ciphertext
  in memory simultaneously. Peak heap is now `objectSize + overhead` instead
  of `2× objectSize` for large objects.

- **Password loaded as `[]byte` from the start** (V1.0-SEC-19):
  `cmd/server/main.go` now loads the encryption password directly into a
  `[]byte` slice and zeroizes it immediately after passing it to the engine
  constructor. Go's immutable `string` intermediate is eliminated; the
  explicit security guidance in `docs/SECURITY.md` is updated accordingly.

- **TTL-based engine cache with `Close()` on eviction** (V1.0-SEC-20):
  `engineCache` is now a TTL cache with a background sweep goroutine. Engines
  are `Close()`d and their passwords zeroized on eviction and on server
  shutdown, preventing unbounded accumulation of active password buffers.

- **Admin `MaxHeaderBytes`** (V1.0-SEC-21):
  The admin HTTP server now explicitly sets `MaxHeaderBytes` (64 KB default),
  preventing memory exhaustion via oversized headers.

- **Cached admin token with refresh loop** (V1.0-SEC-22):
  The admin bearer token is now read once at startup and cached in a
  `RWMutex`-protected field. A `tokenRefreshLoop` re-reads the file every 30
  seconds and validates permissions, eliminating per-request disk I/O without
  losing the ability to rotate tokens at runtime.

- **Hardened TLS cipher suites** (V1.0-SEC-23):
  Both admin listener and Cosmian KMS TLS configs now explicitly restrict
  `CipherSuites` (ECDHE+AES-256-GCM / CHACHA20-POLY1305) and
  `CurvePreferences` (X25519, P-256). CBC-mode ciphers are rejected.

- **Recovery middleware is outermost** (V1.0-SEC-24):
  Middleware ordering corrected so `RecoveryMiddleware` wraps all other
  middleware (logging, security headers, tracing, bucket validation, rate
  limiting). Panics in any layer now gracefully return HTTP 500 instead of
  crashing the server goroutine.

- **Multipart upload respects configured algorithm** (V1.0-SEC-25):
  `initMPUEncryptionState` now calls `engine.PreferredAlgorithm()` instead of
  hardcoding `"AES256GCM"`. `NewMPUPartEncryptReader` and `NewMPUDecryptReader`
  accept an `algorithm string` parameter. This means policies configured for
  `ChaCha20-Poly1305` are honored for multipart uploads.

- **Audit FileSink permissions** (V1.0-SEC-26):
  Audit log files are now created with `0600` permissions instead of `0644`.

- **Admin token file TOCTOU fix** (V1.0-SEC-28):
  Token file validation now uses `os.Lstat` instead of `os.Stat` to detect
  symlinks and prevent TOCTOU races between permission check and read.

### Dependencies

- Updated `github.com/aws/aws-sdk-go-v2` to v1.41.7
- Updated `github.com/aws/aws-sdk-go-v2/credentials` to v1.19.16
- Updated `github.com/aws/aws-sdk-go-v2/service/s3` to v1.100.1

---

## [0.6.3] — 2026-04-28

### Security

This patch release addresses eight security findings from the v0.6 security
analysis. All fixes are non-breaking; no configuration changes are required
unless noted.

- **Sensitive data zeroization, constant-time audit & crypto hygiene**
  (V1.0-SEC-1): Six concrete crypto-hardening findings in `internal/crypto/`:
  - `engine.password` changed from `string` to `[]byte`; new `Close()` method
    zeroizes the password buffer before deallocation.
  - `mpuDecryptReader.returnEncBuf()` now zeroizes `r.dek` after use; the
    reader defensively copies the caller's DEK so the caller can safely
    `zeroBytes(dek)` immediately after construction.
  - Removed base64-encoded wrapped-key material from error messages; only
    non-secret length information is retained.
  - `computeETag` split into build-tagged files (`etag_default.go` with
    `crypto/md5`, `etag_fips.go` with SHA-256) so FIPS builds never link
    MD5. ETag remains an S3 protocol identifier with no cryptographic
    security requirement.
  - KMIP adapter ECB comment corrected: `keymanager_cosmian.go` now
    documents that AES-KW (RFC 3394) or AES-GCM is used internally and
    that ECB is **not** suitable for key wrapping.
  - Constant-time comparison audit confirmed: all credential/token
    comparisons use `hmac.Equal` or `subtle.ConstantTimeCompare`.

- **Remove debug logging of cryptographic parameters** (V1.0-SEC-3):
  All `fmt.Printf` calls inside `debug.Enabled()` blocks in
  `internal/crypto/engine.go` have been replaced with `slog.Debug(...)`.
  Raw cryptographic values (salt bytes, IV bytes, ciphertext previews) are
  never logged; only lengths are recorded. A startup warning is emitted at
  `WARN` level when debug mode is active.

- **Integer overflow in encrypted range calculation** (V1.0-SEC-5):
  `calculateEncryptedByteRange` in `internal/crypto/range_optimization.go`
  now validates inputs before `int64` promotion and returns an `error` on
  overflow, preventing incorrect byte-range offsets on 32-bit platforms or
  adversarially crafted metadata.

- **X-Forwarded-For header spoofing** (V1.0-SEC-6):
  `getClientIP` and `getClientKey` no longer blindly trust the leftmost IP in
  `X-Forwarded-For`. A new `TrustedProxies []string` configuration field
  (`server.trusted_proxies`) accepts CIDRs; when the immediate remote peer is
  a trusted proxy, the gateway walks the XFF chain right-to-left to find the
  first non-trusted IP. Default is empty (fail-safe: `RemoteAddr` always used).
  See `docs/POLICY_CONFIGURATION.md` for configuration examples.

- **Replaced `math/rand` with `crypto/rand` in retry jitter** (V1.0-SEC-7):
  All four backend retry jitter strategies (`full`, `decorrelated`, `equal`,
  `none`) in `internal/s3/retry.go` now use `crypto/rand.Reader` via the new
  `cryptoRandInt63n` helper. This removes the only `math/rand` usage in the
  codebase and eliminates the suppressed `gosec` G404 finding. Behaviour is
  unchanged; jitter values remain in the expected statistical bounds.

- **Hardened HTTP transport for audit sink** (V1.0-SEC-8):
  `internal/audit/sink.go` now constructs `*http.Client` with a fully
  configured `http.Transport` (TLS handshake timeout, response header timeout,
  idle/max connection limits, per-host concurrency cap). All limits are
  exposed as `HTTPTransportConfig` fields under `audit.http.*` in
  `config.yaml` for operator tuning. Slow or unresponsive audit endpoints
  no longer risk connection exhaustion. A `dropped_audit_events_total`
  Prometheus counter tracks events lost under backpressure.

- **Startup warning for `InsecureSkipVerify`** (V1.0-SEC-9):
  When `InsecureSkipVerify` is enabled for Cosmian KMS or Valkey TLS
  connections, an `ERROR`-level log is emitted at startup with the exact
  environment variable name and a clear MITM warning, ensuring operators
  cannot accidentally run with disabled certificate verification in
  production without an alert-pipeline-visible indication.

- **Rate limiter timing side-channel mitigation** (V1.0-SEC-10):
  `RateLimiter.Allow` in `internal/middleware/security.go` now enforces a
  constant minimum execution time (`minAllowTime = 50µs`) via a deferred
  spin-wait, preventing timing measurements from revealing token-bucket state.
  Benchmark confirms P99 latency stays within `minAllowTime + 20µs`.

### Dependencies

- Updated `github.com/redis/go-redis/v9` to v9.19.0
- Updated `github.com/ovh/kmip-go` to v0.8.1
- Updated `peter-evans/create-or-update-comment` to v5

---

## [0.6.2] — 2026-04-27

### Changed

- **First-class inline bucket policies** (`helm/`): The Helm chart now accepts
  bucket policy definitions directly in `values.yaml` via a top-level
  `policies` list, eliminating the need for manual `extraVolumes` /
  `extraVolumeMounts` to mount policy files. Each entry maps 1:1 to
  `PolicyConfig` (`internal/config/policy.go`) and supports all fields:
  `encrypt_multipart_uploads`, `require_encryption`, `disallow_lock_bypass`,
  and per-bucket `encryption` / `compression` / `rate_limit` overrides.

  The chart renders a `<release>-policies` ConfigMap from the list, mounts it
  at `/etc/s3-gateway/policies/`, and sets `POLICIES=/etc/s3-gateway/policies/*.yaml`
  automatically. The previous `config.policies.value` path-glob approach is
  preserved for operators who mount policy files from an external source; a new
  render-time guard (Guard 6) enforces that both paths cannot be set
  simultaneously. Schema validation (`values.schema.json`) enforces the
  required `id` and `buckets` fields at `helm install --dry-run` time.

  Example:

  ```yaml
  valkey:
    enabled: true

  policies:
    - id: encrypted-uploads
      buckets:
        - "my-important-bucket"
        - "logs-*"
      encrypt_multipart_uploads: true
      require_encryption: true
  ```

### Fixed

- **Gremlins v0.6 API compatibility** (`.github/workflows/mutation.yml`,
  `scripts/mutation-report.sh`): Gremlins v0.6 removed the `--only-covered`
  flag (now the default), renamed `--json-output` to `-o`, and changed the
  JSON output schema from a `.mutants[]` array to flat top-level fields
  (`mutants_total`, `mutants_killed`, etc.). The mutation workflow and report
  script were updated accordingly. Added `permissions.issues: write` so the
  regression-issue step can create and comment on issues via `GITHUB_TOKEN`.

### CI & Infrastructure

- **Helm README synced to `gh-pages`** (`.github/workflows/helm.yml`): The
  release workflow now copies `helm/s3-encryption-gateway/README.md` to the
  `gh-pages` branch automatically so the Artifact Hub listing stays current
  without a manual step.

- **chart-releaser skipped when version is unchanged**
  (`.github/workflows/helm.yml`): The release job now checks whether the chart
  version in `Chart.yaml` has already been published before invoking
  `chart-releaser`, preventing duplicate-release errors on documentation-only
  pushes to `main`.

- **Helm test suite stabilised** (`.github/workflows/helm-test.yml`,
  `helm/s3-encryption-gateway/scripts/test-progressive-delivery.sh`): Fixed
  two categories of failures — flaky assertions in the progressive-delivery
  script and a Helm 3 / Helm 4 API incompatibility in flag handling. Both
  Helm 3 and Helm 4 are now exercised in CI.

- **Removed stale `coverage-fips.out` artefact**: The accidentally-committed
  FIPS coverage profile (72 k lines) has been removed from the repository.

---

## [0.6.1] — 2026-04-25

### Testing & Quality

- **Coverage gate ≥ 75% and mutation testing** (V0.6-QA-2): The project now
  enforces a hard ≥ 75% statement coverage gate on every PR and push to `main`
  via `scripts/coverage-gate.sh`, wired into the `coverage-gate` CI job in
  `.github/workflows/conformance.yml`. The FIPS build profile (`-tags=fips`)
  is gated separately. Nightly mutation testing via
  [Gremlins](https://github.com/go-gremlins/gremlins) runs on `internal/config`,
  `internal/api`, `internal/s3`, and `internal/middleware` with a ≥ 70%
  kill-rate target; `internal/crypto` is covered by fuzz tests instead.
  See [`docs/COVERAGE.md`](docs/COVERAGE.md) for the exclusion policy and
  regeneration guide.

- **Per-provider performance baselines** (V0.6-QA-1): established a
  reproducible measurement methodology and committed baseline corpus
  under `docs/perf/v0.6-qa-1/` (micro-benchmarks for 19 tracked Go
  functions + macro JSON per local provider — MinIO, Garage, RustFS,
  SeaweedFS). A nightly `performance-baseline` GitHub workflow re-runs
  both the micro and per-provider soak suites and fails on > 15 %
  throughput drops, > 20 % p95 growth, > 25 % p99 growth, any new
  `allocs/op`, or any new error where the baseline was zero (thresholds
  per plan §6.1). Pull requests receive a sticky advisory benchstat
  comment (never fails the PR — CI runners are too noisy for per-PR
  gating). Two new benchmarks — `BenchmarkMPUDecryptReader_100MiB` and
  the three `BenchmarkUploadPartCopy_*` variants — close the benchmark
  gaps flagged by PERF-1 and S3-1. See
  [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) and
  [`docs/plans/V0.6-QA-1-plan.md`](docs/plans/V0.6-QA-1-plan.md).

### Operations & Helm

- **Helm values JSON Schema** (V0.6-OPS-2): the chart now ships
  `values.schema.json` (JSON Schema draft-07), validated by `helm lint`,
  `helm install`, and `helm upgrade` before the chart renders.

  - **~140 leaf keys covered** with type constraints, enums, patterns, and
    descriptions. Typos like `config.encriptoin.*` are now caught at lint
    time, not at pod startup.
  - **Schema-encoded invariants** (I1–I3, I5, I7): `track + valkey.enabled`
    conflict, dual-ingress conflict, weighted-without-Traefik conflict,
    KeyManager provider validation, and TLS cert requirement.
  - **New `values.prod.yaml` overlay**: hardened production defaults —
    3-replica HA floor, HPA (3–20 replicas), PDB (minAvailable: 2),
    NetworkPolicy, Prometheus ServiceMonitor, TLS via cert-manager, audit
    logging, rate limiting, preStop hook, and zone-level topology spread.
  - **New `values.dev.yaml` overlay**: minimal local-development defaults —
    1 replica, debug log level, audit logging, in-cluster Valkey subchart.
  - **15 negative schema tests** (`tests/schema/bad-*.yaml`) and 6 positive
    tests (`tests/schema/good-*.yaml`), with `run-negative.sh` harness.
  - **CI extended** with 5 new jobs: `lint-base`, `lint-overlays`,
    `schema-negative`, `schema-drift`, `render-overlays`.
  - **Chart version bumped 0.5.10 → 0.6.0** (additive, non-breaking for
    valid values; schema rejects values that always silently produced broken
    deployments).

  See `docs/plans/V0.6-OPS-2-plan.md` and the "Values Validation" section in
  `helm/s3-encryption-gateway/README.md`.

- **Blue/green and canary deployment recipes** (V0.6-OPS-1): the Helm chart
  now ships production-safe progressive-delivery topologies for zero-downtime
  upgrades of the S3 Encryption Gateway.

  - **New chart value `track`** (default `""`): labels pods for selector-based
    traffic routing. Set to `"blue"`, `"green"`, `"stable"`, or `"canary"`.
    Single-release deployments see no change (backward compatible; empty track
    emits no label).

  - **New `ingress.traefik.*` values**: first-class Traefik v3 CRD support.
    - `ingress.traefik.enabled: true` renders a `traefik.io/v1alpha1`
      `IngressRoute` as the replacement for the standard `networking.k8s.io/v1`
      Ingress. Mutually exclusive with `ingress.enabled` (chart enforces this).
    - `ingress.traefik.weighted.enabled: true` renders a `kind: Weighted`
      `TraefikService` + companion `IngressRoute` for the canary traffic-split
      topology. Weights must sum to 100 (chart enforces this).

  - **New `terminationGracePeriodSeconds` and `lifecycle` values**: expose
    pod lifecycle knobs for safe connection draining during traffic flips.
    Default `terminationGracePeriodSeconds: 30` preserves existing behaviour.

  - **Template-time guard-rails** (`templates/validate.yaml`):
    - `track` + `valkey.enabled: true` → render-time error (shared Valkey
      required for MPU state continuity across traffic flips).
    - `track` without a Valkey address → render-time error.
    - `ingress.enabled` + `ingress.traefik.enabled` both true → render-time error.
    - `ingress.traefik.weighted.enabled` without `ingress.traefik.enabled` → error.
    - Weighted services not summing to 100 → render-time error.

  - **New chart templates**: `templates/ingressroute.yaml`,
    `templates/traefikservice.yaml` (both opt-in; emit zero output by default).

  - **Per-track Prometheus relabeling**: `ServiceMonitor` and `PodMonitor`
    templates now emit a `track` relabel rule when `track` is set, enabling
    per-track PromQL queries and Grafana dashboard filtering.

  - **Example values files** (`helm/s3-encryption-gateway/examples/`):
    `values-blue.yaml`, `values-green.yaml`, `values-canary-stable.yaml`,
    `values-canary-canary.yaml`, `values-traefik-single.yaml`.

  - **Raw manifest examples** (`docs/examples/`):
    - `bluegreen/service.yaml` — operator-owned shared Service for the
      selector-flip pattern.
    - `bluegreen/external-valkey.yaml` — minimal shared Valkey StatefulSet.
    - `bluegreen/cutover.sh` — cutover and rollback script.
    - `canary/traefikservice.yaml`, `canary/ingressroute.yaml` — operator-owned
      Traefik resources for the weighted canary split.
    - `canary/promote.sh` — progressive weight promotion (5 → 25 → 50 → 100).
    - `canary/rollback.sh` — emergency rollback script.
    - `gateway-api/httproute.yaml` — portable Gateway API `HTTPRoute` equivalent
      (documentation appendix; not a chart template in v0.6).

  - **Operator runbook**: `docs/OPS_DEPLOYMENT.md` is the single authoritative
    source for blue/green and canary procedures, including the stateful
    invariants (shared Valkey, key-version parity, draining semantics),
    per-track observability, troubleshooting guide, Gateway API appendix,
    and Argo Rollouts / Flagger optional overlay recipe.

  - **CI**: `.github/workflows/helm-test.yml` extended with progressive-delivery
    render checks and guard-rail smoke tests.

  - See `docs/plans/V0.6-OPS-1-plan.md` for full design rationale.

### Observability

- **Admin pprof profiling endpoints** (V0.6-OBS-1): production-safe runtime
  profiling is now available at `/admin/debug/pprof/*` on the **admin
  listener** when `admin.profiling.enabled: true`.

  - **Disabled by default.** Enabling requires `admin.enabled: true`;
    on non-loopback addresses also requires `admin.tls.enabled: true`.

  - **Security-inheriting.** All 11 pprof endpoints (index, cmdline,
    profile, symbol, trace, heap, goroutine, allocs, block, mutex,
    threadcreate) reuse the existing admin bearer-token auth, rate
    limiter, and TLS — no new auth surface.

  - **Semaphore-bounded.** `/profile` and `/trace` are bounded by
    `max_concurrent_profiles` (default 2) and `max_profile_seconds`
    (default 60); excess requests return `429 Retry-After: 1`.

  - **Block/mutex profiling knobs.** `block_rate` and `mutex_fraction`
    (both default 0/off) are passed to
    `runtime.SetBlockProfileRate` / `SetMutexProfileFraction` at startup.

  - **Audited.** Every fetch emits a `pprof_fetch` audit event with
    endpoint, duration, and HTTP status.

  - **New Prometheus metrics:** `s3_gateway_admin_pprof_requests_total
    {endpoint, outcome}` (bounded cardinality: 11 × 4 = 44 label
    combinations) and `gateway_admin_profiling_enabled` gauge.

  - **Dockerfile `STRIP_SYMBOLS` build-arg.** Both `Dockerfile` and
    `Dockerfile.fips` now accept `--build-arg STRIP_SYMBOLS=false` to
    produce a symbolicated binary for profiling sessions without
    permanently removing symbols from production images. Use
    `make profile-image` as a convenience shortcut.

  - **Operator recipes** added to `docs/OBSERVABILITY.md §"Runtime
    Profiling"` (CPU flamegraph, heap snapshot, goroutine-leak workflow).

  - **Admin API reference** updated in `docs/ADMIN_API.md` with the
    route table and response code semantics.

  - **New config keys** (all optional, default `false`/`0`):
    `admin.profiling.enabled`, `.block_rate`, `.mutex_fraction`,
    `.max_concurrent_profiles` (default 2), `.max_profile_seconds`
    (default 60). See `config.yaml.example` for the annotated stanza.

  - **ADR 0011** filed: `docs/adr/0011-admin-profiling-endpoints.md`.

  - See `docs/plans/V0.6-OBS-1-plan.md` for full design rationale.

### Performance

- **Configurable S3 backend retry policy** (V0.6-PERF-2):
  Replaced the SDK-default retryer with a gateway-specific `aws.RetryerV2`
  implementation (`internal/s3/retry.go`) backed by the new
  `backend.retry.*` configuration stanza:

  - **Operator-configurable knobs** (all optional, defaults match SDK
    behaviour): `mode` (`standard` | `adaptive` | `off`),
    `max_attempts` (1–10, default 3), `initial_backoff` (default 100 ms),
    `max_backoff` (default 20 s), `jitter`
    (`full` | `decorrelated` | `equal` | `none`, default `full`),
    `per_operation` override map, `safe_copy_object` gate.

  - **Idempotency safeguards**: `CompleteMultipartUpload` now defaults to
    `max_attempts: 1` (non-idempotent post-commit); retrying a successful
    Complete would return `NoSuchUpload` and confuse the caller. Callers
    that need retry should do so at the application layer.

  - **HTTP 429 classified as retryable** for all backends (the SDK's
    default classifier only retries 429 if the response body contains a
    known throttle error code, which Wasabi and Hetzner do not include).

  - **Crypto errors are hard non-retryable** (`ErrInvalidEnvelope`,
    `ErrUnwrapFailed`, `ErrKeyNotFound`, `ErrProviderUnavailable`) — no
    auto-retry on tamper-detected objects.

  - **Context-aware sleep** — request cancellation interrupts a sleeping
    retry without goroutine leaks.

  - **`Retry-After` header honoured** for HTTP 429/503 responses.

  - **Three new Prometheus metrics**:
    `s3_backend_retries_total{operation, reason, mode}`,
    `s3_backend_attempts_per_request{operation}`,
    `s3_backend_retry_give_ups_total{operation, final_reason}`, and
    `s3_backend_retry_backoff_seconds` histogram.

  - **Audit event** `backend.retry_give_up` emitted on data-plane write
    give-ups (not on read-path give-ups to avoid noise).

  - **`adaptive` mode** available for contended backends; wraps the SDK's
    `retry.AdaptiveMode` token bucket.

  - **`off` mode** disables retries entirely for debug and
    conformance-test isolation.

  - See `docs/adr/0010-backend-retry-policy.md` and
    `config.yaml.example` for the full knob reference.

- **Zero-copy streaming on hot data paths** (V0.6-PERF-1): eliminated
  full-object in-memory buffers on the most allocation-heavy paths:

  - **`handleGetObject` optimised range path**: the `io.ReadAll` at the
    partial-content response stage is replaced with `io.CopyBuffer`
    directly to the response writer using a pooled 64 KiB buffer.
    `Content-Length` is computed from the already-known plaintext range,
    so no intermediate `[]byte` slice is needed.

  - **`handleCopyObject`**: the double-allocation
    (`ReadAll(decryptedReader)` → `Encrypt(bytes.NewReader(decryptedData))`
    → `ReadAll(encryptedReader)`) is reduced to a single allocation
    inside the engine. `decryptedReader` is now passed directly to
    `Encrypt`, eliminating the intermediate `decryptedData []byte`. A
    legacy-source size cap (`Server.MaxLegacyCopySourceBytes`, default
    256 MiB) is now also enforced on `handleCopyObject` (previously
    only on `UploadPartCopy`).

  - **`handleUploadPart`**: `io.ReadAll(r.Body)` and
    `io.ReadAll(encReader)` are replaced with a pooled
    `SeekableBody` wrapper (`internal/s3/seekable_body.go`) that
    satisfies the AWS SDK V2 SigV4 seekable-body contract while capping
    heap per part at `Server.MaxPartBuffer` (new config knob, default
    **64 MiB**). Parts above the cap are refused with HTTP 413 before
    any backend write occurs.

  - **Compression engine** (`internal/crypto/compression.go`):
    `Compress` now returns a streaming `io.Pipe` reader instead of
    buffering the full compressed output; `Decompress` returns a
    `*gzip.Reader` wrapping the plaintext directly. The post-hoc
    "skip if compressed ≥ original" size check is removed in favour of
    the `ShouldCompress` pre-filter (size + content-type), consistent
    with nginx / Envoy precedent. ADR 0006 addendum documents the
    behaviour change.

  - **Engine compression branch** (`internal/crypto/engine.go`): the
    `bytes.NewReader(compressedData)` intermediate re-wrap is eliminated;
    the compression pipe reader flows directly into the AEAD boundary.
    The engine Decrypt path also drops a redundant `io.ReadAll →
    bytes.NewReader` round-trip.

  - **Streaming MPU part encrypt reader**
    (`internal/crypto/mpu_encrypter.go`, Phase G): `NewMPUPartEncryptReader`
    now returns a true streaming `io.Reader` (`*mpuEncryptReader`) that
    encrypts one 64 KiB AEAD chunk per `Read` call. Peak heap per part
    is O(chunkSize + tagSize) ≈ 65 KiB regardless of part size, down
    from O(plaintext + ciphertext). The DEK is defensively copied by
    the reader so that callers may safely zero their DEK slice
    immediately after the constructor returns (fixing a latent bug
    where `defer zeroBytes(dek)` would corrupt IVs under the previous
    streaming design). IV derivation remains deterministic — retries
    produce byte-identical ciphertext.

### Added

- **Unified multi-provider conformance test suite** (V0.6-QA-4):
  Introduced `test/provider/`, `test/harness/`, and
  `test/conformance/` packages implementing a three-tier test taxonomy
  (Unit / Conformance / Soak+Load+Chaos). The new `Provider` interface
  and Testcontainers-Go-backed MinIO (`minio/minio:RELEASE.2024-11-07T00-52-20Z`),
  Garage (`dxflrs/garage:v2.3.0`), and Valkey (`valkey/valkey:8.0-alpine`)
  implementations replace the four inconsistent test harness variants
  that existed previously. 32 provider-agnostic conformance tests
  cover PutGet, Head, List, Delete, BatchDelete, CopyObject, ranged
  reads (including cross-chunk boundaries), chunked and legacy AEAD
  encryption, multipart upload (basic / abort / list-parts),
  UploadPartCopy (full / range / plaintext / legacy / mixed / abort /
  cross-bucket), object tagging, presigned URLs, key-rotation
  dual-read window, Object Lock retention / legal-hold / bypass-refused,
  metadata round-trip, and concurrent operations under `-race`.
  External S3 vendors (AWS, Wasabi, Backblaze B2, Hetzner) plug in
  via a one-file pattern and activate automatically when credentials
  are set. A mechanical `matrix_guard_test.go` AST check prevents
  provider-name literals from appearing in conformance test bodies;
  `scripts/test-isolation.sh` prevents regression to `docker-compose`
  / hard-coded ports / binary backend invocations.

  New `make` targets: `test-conformance`, `test-conformance-local`,
  `test-conformance-minio`, `test-conformance-external`,
  `test-isolation-check`. `make test-comprehensive` now runs
  tier-1 + local conformance + isolation check without requiring
  `docker-compose up`. See `docs/TESTING.md`.

  **Phase-1 hotfix**: `StartSharedMinIOServerForProvider` in
  `test/minio.go` now creates the bucket before returning, fixing the
  root cause of the `TestProvider_Compatibility` /
  `TestGateway_ProviderIntegration` failures in `make test-comprehensive`
  step 3.

### Fixed

- **User metadata was silently dropped on PUT / CopyObject / MPU**
  (uncovered by V0.6-QA-4). Four sites in `internal/api/handlers.go`
  (`handlePutObject`, `filterS3Metadata`, `handleCreateMultipartUpload`,
  `handleCopyObject`) compared `k[:11] == "x-amz-meta-"` against keys
  from `r.Header`. Go canonicalises HTTP headers to `X-Amz-Meta-Foo`
  on parse, so the case-sensitive comparison never matched and all
  `x-amz-meta-*` headers were discarded. Replaced with
  `strings.HasPrefix(strings.ToLower(k), "x-amz-meta-")` and
  lowercase the map key for downstream consistency.

- **`DeleteObjects` failed against MinIO and older S3-compatible
  backends** (uncovered by V0.6-QA-4). MinIO
  (pre-`RELEASE.2024-11-07T00-52-20Z` era) and many other backends
  only validate the legacy `Content-MD5` integrity header; AWS SDK
  v2 migrated to `x-amz-checksum-*` and no longer auto-computes
  `Content-MD5`. Added a smithy finalize-stage middleware in
  `internal/s3/client.go` that computes and sets `Content-MD5`
  from the serialised body when not already present. Idempotent
  against AWS (which also accepts the header).

### Added

- **Object Lock / Retention / Legal Hold pass-through** (V0.6-S3-2):
  the six Object-Lock subresource endpoints are now routed
  (`PUT/GET /{bucket}/{key}?retention`, `?legal-hold`, and
  `PUT/GET /{bucket}?object-lock`) with strict XML validation, and
  the three `x-amz-object-lock-*` request headers are now forwarded
  end-to-end on `PutObject`, `CopyObject`, and
  `CompleteMultipartUpload`. `GetObject` / `HeadObject` responses
  surface the backend's `x-amz-object-lock-mode`,
  `x-amz-object-lock-retain-until-date`, and
  `x-amz-object-lock-legal-hold` headers. New ADR 0008 documents
  ciphertext-locking semantics and the interaction with key rotation.

### Changed

- **`x-amz-bypass-governance-retention` is now refused rather than
  silently dropped** (V0.6-S3-2). Any request carrying a truthy value
  for this header on `PutObjectRetention`, `DeleteObject`, or
  `DeleteObjects` now returns `403 AccessDenied` with an audit event
  (`reason=admin_authorization_not_implemented`). The previous
  behaviour (silent drop plus no retention effect) produced a false
  sense of compliance. Admin-gated forwarding lands with V0.6-CFG-1.

- **`Client` interface signatures** for `PutObject`, `CopyObject`,
  and `CompleteMultipartUpload` now take an optional
  `*ObjectLockInput`. Passing `nil` preserves the pre-change
  behaviour.

### Added

- **Admin API for Key Rotation** (V0.6-CFG-1): Separate admin listener with
  bearer-token authentication providing a safe drain-and-cutover key rotation
  workflow. Endpoints: `start`, `status`, `commit`, `abort`. Includes
  `RotatableKeyManager` extension interface for adapters that support runtime
  rotation, a `RotationState` state machine with atomic in-flight wrap
  tracking, and Prometheus metrics (`kms_active_key_version`,
  `kms_rotation_operations_total`, `kms_rotation_duration_seconds`,
  `kms_rotation_in_flight_wraps`, `gateway_admin_api_enabled`).
  Documentation: `docs/ADMIN_API.md`, ADR 0007.

- **Pluggable KeyManager Interface** (V0.6-SEC-1): Refactored to a pluggable
  `KeyManager` interface with adapters for in-memory, Cosmian KMIP, and HSM
  (build-tagged). Conformance test suite shared across all adapters.

- **FIPS-Compliant Crypto Profile** (V0.6-SEC-2): Optional FIPS build profile
  via `-tags=fips`; ChaCha20-Poly1305 excluded, AES-256-GCM only. PBKDF2
  migrated to stdlib. `Dockerfile.fips` and Helm FIPS overlay provided.

- **Multipart Copy Support** (V0.6-S3-1): `UploadPartCopy` handler with
  three source-class strategies (chunked, legacy, plaintext). 5 GiB per-call
  cap, legacy source OOM-defense cap, cross-bucket copy support.

- **Encrypted Multipart Uploads** (V0.6-SEC-3, ADR 0009): Closes the
  plaintext-at-rest gap for multipart uploads. Opt-in per bucket via
  `encrypt_multipart_uploads: true` in policy files. Architecture:
  - Per-upload 32-byte DEK wrapped by the configured `KeyManager`.
  - Per-part, per-chunk AEAD IVs derived via
    `HKDF-Expand(SHA-256, dek, salt=sha256(uploadId), info=ivPrefix||BE32(part)||BE32(chunk))`.
  - Finalization manifest stored as a companion object (`<key>.mpu-manifest`),
    with a metadata pointer on the final object.
  - `UploadPartCopy` into encrypted MPU destinations re-encrypts through
    the destination DEK schedule regardless of source class.
  - Range GETs supported: part-boundary arithmetic translates plaintext
    offsets to backend ciphertext offsets.
  - Tamper detection: AES-GCM tag failure on any chunk returns 500 + audit event.
  - **Requires Valkey** for in-flight state storage (`multipart_state.valkey.addr`).
    Startup fail-closed when Valkey is unreachable and any bucket policy enables
    encrypted MPU. Emergency escape hatch: `server.disable_multipart_uploads: true`.
  - New Prometheus metrics: `gateway_mpu_encrypted_total`,
    `gateway_mpu_parts_total`, `gateway_mpu_state_store_ops_total`,
    `gateway_mpu_state_store_latency_seconds`, `gateway_mpu_valkey_up`,
    `gateway_mpu_valkey_insecure`, `gateway_mpu_manifest_bytes`,
    `gateway_mpu_manifest_storage_total`.
  - New admin endpoints (gated by existing admin bearer auth):
    `POST /admin/mpu/abort/{uploadId}`, `GET /admin/mpu/list`.
  - New audit events: `mpu.create`, `mpu.part`, `mpu.complete`,
    `mpu.abort`, `mpu.tamper_detected`, `mpu.valkey_unavailable`.
  - `/readyz` endpoint extended with per-dependency checks (kms,
    valkey) returning a 503 with a JSON `checks` map when any
    configured dependency is unhealthy. K8s-convention aliases
    `/healthz`, `/readyz`, `/livez` added.
  - Helm chart: optional `valkey` subchart dependency
    (https://valkey.io/valkey-helm/, Apache-2.0, verified
    publisher); `VALKEY_ADDR` auto-wired when
    `valkey.enabled=true`. All Valkey config keys also accept env
    var overrides (`VALKEY_ADDR`, `VALKEY_TLS_ENABLED`, etc.).
  - FIPS-compliant: AES-256-GCM + HKDF-SHA256 primitives only; no
    ChaCha20 dependency. All SEC-3 code passes `go test -tags=fips
    -race` cleanly.
  - Default: `false` in v0.6 for soak. v0.7 flips default to `true`.

- **UploadPartCopy + Encrypted MPU Integration Test Suite** (V0.6-S3-3,
  plan: `docs/plans/V0.6-S3-3-plan.md`): 18 new integration tests closing
  every gap flagged during V0.6-S3-1 and V0.6-SEC-3 delivery:
  - Tests 1–10 (`TestUploadPartCopy_{Chunked,Chunked_WithRange,Legacy,Plaintext,
    LargeSource_MustUseRange,CrossBucket,AbortMidway,MixedWithUploadPart,
    CrossBucket_ReadDenied_Integration,PlaintextSource_EncryptedDestBucket_Refused_Integration}`)
    run against a real MinIO backend.
  - Tests 11–13 (`TestUploadPartCopy_MPU_{PlaintextSource_EncryptedDest,
    ChunkedSource_EncryptedDest_WithRange,LegacySource_EncryptedDest}`)
    close the Phase-E zero-coverage gap: UploadPartCopy into encrypted-MPU
    destinations is now exercised end-to-end against MinIO + Valkey.
  - Tests 14–17 (`TestEncryptedMPU_PasswordKeyManager_{SmallObject,Ranged_GET,
    AtRestCiphertext,AbortDeletesState}`) replace the env-gated
    `test/encrypted_mpu_test.go` smoke test with proper CI-runnable assertions
    including at-rest ciphertext checks and Valkey state-deletion verification.
  - Test 18 (`TestCosmianKMS_EncryptedMPU_RoundTrip`) adds Cosmian-wrapped
    DEK coverage to the encrypted-MPU code path.
  - Test harness extensions: `StartGateway` now accepts variadic
    `TestGatewayOption` values (`WithPolicyManager`, `WithKeyManager`,
    `WithMPUStateStore`, `WithAuditLogger`, `WithHeadObjectOverride`);
    all 16 existing gateway tests compile and pass unchanged.
  - New `test/mpu_fixtures.go` with `NewTestMPUStateStore`,
    `NewTestPasswordKeyManager`, `NewRawBackendS3Client`,
    `NewTestPolicyManager`, `EncryptedMPUPolicy`, `TestBucketPrefix`.
  - `MinIOTestServer.SeedMinIOUser` helper for multi-credential tests
    (skips cleanly if `mc` CLI is absent).

### Fixed

- **`UploadPartCopy` Phase-E silent data loss** (`internal/api/upload_part_copy.go`):
  when `mpuStateStore.AppendPart` fails during an UploadPartCopy into an
  encrypted-MPU destination, the handler previously logged a warning and
  returned 200 OK, leaving the encryption state store inconsistent. The fix
  aligns this path with `handlers.go:2730-2757`: the handler now logs at
  error level, records `RecordS3Error("AppendMPUPartState", "StateUnavailable")`,
  emits a `mpu.valkey_unavailable` audit event, and returns **503
  ServiceUnavailable** so the client retries. A duplicate backend part from
  a retry is discarded by `CompleteMultipartUpload`'s ETag-set reconciliation.
  New unit test: `TestUploadPartCopy_MPU_AppendPartFailure_Returns503`.

### CI & Dependencies

- **Disabled Dependabot Go module updates**: Renovate now handles all Go
  dependency updates; Dependabot configuration removed for Go modules to
  prevent duplicate PRs.

- **Fixed Helm chart release CI pipeline**: resolved failures in the Helm
  release GitHub Actions workflow caused by incompatible action versions.

- **Fixed FIPS coverage gate**: corrected the FIPS-tagged build coverage test
  that was failing due to a test setup issue in the mutation workflow.

- **Fixed mutation testing workflow**: repaired the nightly Gremlins mutation
  CI job that had broken after the coverage gate refactor.

- Updated `github.com/aws/aws-sdk-go-v2/service/s3` to v1.100.0
- Updated `github.com/aws/smithy-go` to v1.25.1
- Updated `github.com/ovh/kmip-go` to v0.8.0
- Updated `actions/checkout` to v6
- Updated `actions/setup-go` to v6
- Updated `actions/setup-python` to v6
- Updated `actions/github-script` to v9
- Updated `actions/upload-artifact` to v7
- Updated `azure/setup-helm` to v5
- Updated Python dependency to 3.14
- Updated Go Docker base image to v1.26

### Documentation

- Migrated password-based key management docs to the KMS-centric model
  (`V0.6-DOC-1`): `docs/` updated throughout to reflect the pluggable
  `KeyManager` interface as the canonical configuration path; the legacy
  single-password stanza is documented as a compatibility alias only.

- Finalised v0.6 issue tracker (`docs/issues/v0.6-issues.md`): all
  planned items marked complete.

---

## [0.5.10] — 2026-04-17

### Security

- **Hardened authentication error handling to prevent information leakage**:
  introduced sentinel error types (`ErrSignatureMismatch`, `ErrUnknownAccessKey`,
  `ErrMissingCredentials`, `ErrSigV4NotSupportedWithPassthrough`) for reliable
  error classification without relying on string matching. Errors are now
  classified via `errors.Is()` rather than brittle message parsing, eliminating
  the risk of leaking computed HMAC signatures into response bodies. Signature
  validation now uses constant-time comparison (`hmac.Equal`) to prevent timing
  side channels. All error diagnostics are logged server-side while opaque
  responses are returned to clients.

- **Fixed possible credential exposure in logs**: sanitised log output paths
  where credential material could appear in structured log fields.

### Dependencies

- Updated `github.com/aws/aws-sdk-go-v2/config` to v1.32.15
- Updated `github.com/aws/smithy-go` to v1.25.0

---

## [0.5.9] — 2026-04-15

### Added

- **`HeadBucket` endpoint**: implemented `HEAD /{bucket}` handler with proper
  404/403 responses, closing a compatibility gap with AWS SDKs and tools that
  probe bucket existence before operations.

- **Tightened object route matching**: improved HTTP router regex to prevent
  query-parameter routes from incorrectly shadowing object-key routes.

- **CODEOWNERS file**: added repository ownership configuration.

### Dependencies

- Updated OpenTelemetry Go monorepo to v1.43.0 and v1.42.0
- Updated `golang.org/x/crypto` to v0.50.0
- Updated `golang.org/x/sys` to v0.43.0
- Updated `github.com/aws/smithy-go` to v1.24.3
- Updated AWS SDK Go v2 monorepo (multiple packages)
- Updated `actions/setup-python` to v6
- Updated `actions/github-script` to v9
- Updated `actions/deploy-pages` to v5
- Updated `actions/configure-pages` to v6
- Updated `azure/setup-helm` to v5

---

## [0.5.8] — 2026-03-02

### Dependencies

- Updated `github.com/aws/smithy-go` to v1.24.2, v1.24.1
- Updated AWS SDK Go v2 monorepo (multiple rounds)
- Updated `golang.org/x/crypto` to v0.48.0
- Updated Go Docker base image to v1.26

---

## [0.5.7] — 2026-02-09

### Documentation

- Added AI usage disclaimer document and badge to README.

### Dependencies

- Updated `golang.org/x/sys` to v0.41.0
- Updated OpenTelemetry Go monorepo to v1.40.0
- Updated `github.com/aws/aws-sdk-go-v2/service/s3` to v1.96.0
- Updated `github.com/sirupsen/logrus` to v1.9.4
- Updated `golang.org/x/crypto` to v0.47.0

---

## [0.5.6] — 2026-01-15

### Added

- **Garage S3 server integration tests**: added robust Garage S3-compatible
  server tests with automatic process cleanup for reliable CI execution.

- **Improved test output handling**: redirected comprehensive test suite output
  to log files and clarified load test steps.

- **Garage environment support in load tests**: added environment management
  helpers for Garage in the load test suite.

### Fixed

- Updated Cosmian KMS Docker run commands to use explicit entrypoint for
  compatibility with updated container images.

### Dependencies

- Updated Cosmian KMS Docker image to version 5.14.1 across documentation
  and tests.

---

## [0.5.5] — 2026-01-12

### Added

- **AWS chunked transfer encoding support**: implemented `AwsChunkedReader`
  (`internal/api/aws_chunked_reader.go`) to correctly decode the
  `aws-chunked` transfer encoding used by SDKs for streaming uploads with
  `x-amz-decoded-content-length`. Includes comprehensive unit tests and a
  regression test suite for chunked multipart uploads.

- **Renovate dependency management**: migrated from Dependabot to Renovate
  for automated dependency updates (`renovate.json`).

### Dependencies

- Updated `golang.org/x/sys` to v0.40.0
- Updated AWS SDK Go v2 monorepo (multiple packages)
- Updated `github.com/prometheus/common` to v0.67.5
- Updated `actions/checkout` to v6
- Updated `github.com/ovh/kmip-go` to v0.7.2

---

## [0.5.4] — 2025-12-09

### Dependencies

- Updated `go.opentelemetry.io/otel/exporters/stdout/stdouttrace`
- Updated `github.com/aws/aws-sdk-go-v2/service/s3`
- Updated `golang.org/x/sys` from v0.38.0 to v0.39.0
- Updated `go.opentelemetry.io/otel/sdk` from v1.38.0 to v1.39.0

---

## [0.5.3] — 2025-12-06

### Added

- **Enhanced bucket creation handling**: improved `handleCreateBucket` to
  differentiate between proxied and non-proxied bucket scenarios, returning
  correct `BucketAlreadyExists` or `NotImplemented` errors as appropriate.
  Added comprehensive test coverage for bucket creation paths.

### Dependencies

- Updated `github.com/aws/smithy-go` from v1.23.2 to v1.24.0
- Updated `github.com/aws/aws-sdk-go-v2/service/s3` and `config` (multiple)
- Updated Alpine base image from 3.22 to 3.23

---

## [0.5.2] — 2025-11-24

### Added

- **Improved error handling and bucket creation logic**: added `NoSuchBucket`
  error translation in `TranslateError` for more descriptive S3 error
  responses. Updated route definitions for proper regex matching. Added
  integration tests verifying bucket creation behaviour through the gateway.

### Fixed

- Ensured consistent code formatting across multiple source files.

---

## [0.5.1] — 2025-11-22

### Dependencies

- Updated `golang.org/x/crypto` from v0.44.0 to v0.45.0
- Updated `github.com/aws/aws-sdk-go-v2/service/s3`

---

## [0.5.0] — 2025-11-22

### Added

- **Object tagging support**: implemented `PutObjectTagging`, `GetObjectTagging`,
  and `DeleteObjectTagging` endpoints with full XML validation and pass-through
  to the backend.

- **Presigned URL support**: implemented presigned URL generation and validation,
  allowing time-limited pre-authenticated access to objects through the gateway.

- **Per-bucket policy configuration**: introduced a policy manager enabling
  per-bucket configuration of encryption settings, key management, and
  behavioural overrides from YAML policy files.

- **Parallel chunk encryption/decryption**: implemented concurrent AEAD chunk
  processing to improve throughput on multi-core systems for large object
  transfers.

- **Key rotation policy and metrics**: added key rotation scheduling with
  associated Prometheus metrics tracking active key version and rotation events.

- **Hardware acceleration detection**: added detection and metrics reporting
  for AES-NI and other CPU crypto acceleration features.

- **Enhanced audit logging configuration**: expanded audit log options with
  configurable fields, output formats, and filtering capabilities.

- **Enhanced metrics with context support**: propagated request context through
  metrics recording to enable per-request labelling.

- **Chaos testing for backend resilience**: added chaos test scenarios
  simulating backend failures, network partitions, and latency injection.

- **Fuzz testing for metadata and range calculations**: added Go fuzzing targets
  covering metadata parsing edge cases and range offset arithmetic.

- **External S3 provider integration testing**: extended the integration test
  suite with support for testing against real external S3 providers (AWS,
  Wasabi, Backblaze B2, Hetzner) when credentials are configured.

- **Shared MinIO server for provider tests**: implemented a shared MinIO
  instance for provider-agnostic conformance test execution without per-test
  container startup overhead.

### Changed

- **Enhanced security context and network policies**: tightened Kubernetes
  security contexts and network policy egress/ingress rules in Helm chart.

---

## [0.4.2] — 2025-11-18

### Documentation

- Updated configuration and deployment documentation for improved clarity
  and completeness.

### Dependencies

- Updated `github.com/prometheus/common` from v0.66.1 to v0.67.2

---

## [0.4.1] — 2025-11-17

### Added

- **Backblaze B2 integration tests**: added a comprehensive integration test
  suite for Backblaze B2 S3-compatible storage, covering encryption round-trips,
  multipart uploads, and error handling.

- **Cosmian KMIP integration**: integrated Cosmian KMIP support for enterprise
  key management. Includes Docker-based Cosmian KMS setup for CI and development,
  comprehensive KMIP configuration documentation, and health check functionality
  for KMS connectivity.

- **Debug logging**: added a `debug` log level with structured fields for
  detailed request/response tracing, controllable at runtime without restart.

- **KMS health check**: implemented a readiness check for the configured KMS
  endpoint surfaced on the `/readyz` endpoint.

### Changed

- Enhanced Makefile with additional testing commands and targets for
  comprehensive test execution.

---

## [0.4.0] — 2025-11-16

### Added

- **Range request optimisation for chunked encryption**: implemented efficient
  range GET handling that translates plaintext byte ranges to ciphertext chunk
  boundaries, avoiding full object decryption for partial reads.

- **Metadata compaction policy** (V0.4-SEC-2): implemented a metadata fallback
  storage strategy for backends with strict object metadata size limits (e.g.
  AWS S3's 2 KB limit). Encryption metadata that exceeds the limit is stored
  as a sidecar object, with a pointer in the object's user metadata.

- **Multipart upload stability and interop** (V0.4-S3-2): improved multipart
  upload compatibility across S3-compatible backends. Note: multipart uploads
  in v0.4 are stored without client-side encryption (encryption gap closed in
  v0.6-SEC-3); `server.disable_multipart_uploads: true` can be set to prevent
  unencrypted multipart objects at the cost of large-file support.

- **List operations parity** (V0.4-S3-1): implemented full `ListObjectsV2`
  and `ListObjects` (v1) parity including `delimiter`, `prefix`, `continuation-token`,
  `max-keys`, and `fetch-owner` parameters.

- **Hot-reload of non-crypto configuration** (V0.4-CFG-1): the gateway now
  watches the config file for changes and reloads non-cryptographic settings
  (log level, rate limits, access log format, etc.) without restart using
  `fsnotify`.

- **OpenTelemetry distributed tracing** (V0.4-OBS-1): added OTLP trace export
  for all gateway request handlers with span attributes covering request method,
  bucket, key, response status, and encryption operation type.

- **Access log presets** (V0.4-OBS-2): structured access logging with
  configurable JSON and Common Log Format (CLF) presets. Sensitive headers
  (`Authorization`, `x-amz-security-token`) are redacted automatically.

- **Backpressure and streaming tuning** (V0.4-PERF-2): added configurable
  read/write buffer sizes, connection timeouts, and goroutine pool limits to
  prevent memory spikes under high concurrency.

- **Buffer pooling** (V0.4-PERF-1): implemented `sync.Pool`-backed byte buffer
  pools for AEAD chunk encryption/decryption, reducing GC pressure and
  allocation overhead on hot paths.

- **Enhanced Helm chart with TLS and monitoring** (V0.4-OPS-1): the Helm chart
  now supports TLS termination at the gateway pod via cert-manager certificates,
  Prometheus `ServiceMonitor` and `PodMonitor` resources, and configurable
  resource requests/limits.

- **Additional Helm chart knobs** (V0.4-OPS-2): exposed extra configuration
  values including replica count, HPA parameters, PodDisruptionBudget, topology
  spread constraints, and extra environment variables.

- **Load and regression test suite** (V0.4-QA-2): added a `k6`-based load
  test suite covering range GET, multipart upload, and concurrent PutObject
  scenarios with MinIO as the backend. Baseline results committed to repository.

- **Architecture Decision Records and diagrams** (V0.4-DOC-1): added exported
  architecture diagrams and ADR documents covering chunked encryption design,
  metadata compaction, multipart limitations, and range request handling.

- **Option to disable multipart uploads**: added `server.disable_multipart_uploads`
  config knob to completely block multipart uploads at the gateway layer, useful
  when maximum at-rest security is required and large-file uploads are not needed.

### Fixed

- Fixed `recordLatency` parameter types causing compilation errors.
- Fixed multipart upload route registration to ensure
  `?uploads` query parameter routes are matched before the generic PUT handler.

---

## [0.3.10] — 2025-11-14

### Documentation

- Added Docker Compose setup instructions and example configuration to the
  project documentation for easier local development and evaluation deployments.

### Dependencies

- Updated `github.com/aws/aws-sdk-go-v2/config`
- Updated `github.com/aws/aws-sdk-go-v2/service/s3`
- Updated `github.com/aws/aws-sdk-go-v2/credentials`
- Updated `golang.org/x/crypto` from v0.43.0 to v0.44.0

---

## [0.3.9] — 2025-11-08

### Dependencies

- Updated `github.com/aws/aws-sdk-go-v2/config`
- Updated `github.com/aws/aws-sdk-go-v2/credentials`
- Updated `github.com/aws/aws-sdk-go-v2/service/s3`

---

## [0.3.8] — 2025-11-04

### Added

- **Multipart upload content-length optimisation**: improved multipart upload
  handling to compute and forward correct `Content-Length` values to the backend,
  reducing compatibility issues with strict S3 implementations.

---

## [0.3.7] — 2025-11-04

### Fixed

- **Multipart upload route registration**: registered the multipart upload
  initiation route (`PUT /{bucket}/{key}?uploads`) before the generic
  `PUT /{bucket}/{key}` route to ensure correct handler dispatch when both
  routes could match.

---

## [0.3.6] — 2025-11-04

### Added

- **TLS support for Helm Service and ServiceMonitor**: the Helm chart now
  supports configuring TLS for the gateway service endpoint and for
  Prometheus `ServiceMonitor` scrape connections.

---

## [0.3.5] — 2025-11-04

### Added

- **Helm NetworkPolicy egress for S3 backend**: enhanced the generated
  `NetworkPolicy` to include egress rules allowing the gateway pods to reach
  the configured S3 backend endpoint, preventing silent connectivity failures
  in strict network environments.

---

## [0.3.4] — 2025-11-04

### Added

- **Helm NetworkPolicy namespace isolation**: added namespace-scoped ingress
  rules to the generated `NetworkPolicy`, allowing operators to restrict which
  namespaces can reach the gateway.

---

## [0.3.3] — 2025-11-04

### Added

- **Liveness and readiness probe TLS support**: enhanced the Helm chart's
  probe configuration to support TLS-enabled health check endpoints, ensuring
  Kubernetes probes work correctly when the gateway is configured with TLS.

---

## [0.3.2] — 2025-11-04

### Added

- **cert-manager integration in Helm chart**: added optional cert-manager
  `Certificate` resource support for automatic TLS certificate management and
  rotation. Configurable via `tls.certManager.enabled` in Helm values.

- **Issue tracking and implementation guide**: added `docs/issues/` tracking
  documents covering planned milestones v0.4 through v1.0 with detailed
  implementation notes.

### Dependencies

- Updated `github.com/aws/smithy-go` from v1.23.1 to v1.23.2

---

## [0.3.1] — 2025-11-03

### Fixed

- **Signature V4 with client credential passthrough**: fixed a compatibility
  issue where using `use_client_credentials: true` in the backend configuration
  would break AWS Signature V4 request signing. The gateway now correctly
  passes through client-provided credentials for backend requests.

### Documentation

- Enhanced README with improved clarity and completeness.
- Updated roadmap milestone versions in `ROADMAP.md`.

---

## [0.3.0] — 2025-11-02

### Added

- **Client credentials in backend configuration**: added `use_client_credentials`
  configuration option allowing the gateway to forward the connecting client's
  AWS credentials directly to the backend S3 service instead of using a fixed
  service account. Enables transparent credential pass-through for multi-tenant
  deployments.

### Dependencies

- Updated Alpine base image from 3.20 to 3.22

---

## [0.2.0] — 2025-11-02

### Added

- **Chunked encryption for streaming and multipart uploads**: implemented
  AEAD chunked encryption that splits objects into fixed-size chunks (default
  64 KiB), each independently encrypted with AES-256-GCM or ChaCha20-Poly1305.
  Enables efficient range requests without full object decryption.

- **Optimised range requests for chunked encryption**: implemented range GET
  translation that maps plaintext byte ranges to the minimum required set of
  ciphertext chunks, decrypts only those chunks, and returns the requested
  plaintext slice. Documented in `docs/CHUNKED_ENCRYPTION.md`.

- **Optional `Content-Length` on `PutObject`**: the gateway now correctly
  handles `PutObject` requests with or without `Content-Length`, computing
  the encrypted output size when needed.

- **Initial Helm chart**: added a production-ready Helm chart for deploying
  the S3 Encryption Gateway on Kubernetes, including `Deployment`,
  `Service`, `ServiceAccount`, `ConfigMap`, `NetworkPolicy`, and optional
  `Ingress` resources.

- **GitHub Actions CI/CD workflows**: added workflows for Helm chart linting,
  testing (`helm/chart-testing-action`), and release (`helm/chart-releaser-action`).

- **Streaming and reduced buffering**: optimised the request proxy pipeline
  to stream request and response bodies where possible, reducing peak memory
  usage for large objects.

- **AAD binding and key rotation support**: bound Additional Authenticated
  Data (AAD) in AEAD operations to the object path, preventing ciphertext
  transplantation attacks. Added a key resolver interface enabling transparent
  read-side decryption with old keys while encrypting new objects with the
  current key.

- **Service account and network policy in Helm**: added Kubernetes
  `ServiceAccount` with optional IRSA/Workload Identity annotations and a
  `NetworkPolicy` restricting ingress to labeled sources.

### Fixed

- Stripped `x-amz-meta-` prefix before passing user metadata to the AWS
  SDK `PutObject` call to prevent `InvalidArgument` errors from backends
  that do not accept the prefix in the SDK input struct.

- Removed `MetaChunkCount` from the initial metadata write to prevent
  S3 rejection on `CreateMultipartUpload`; chunk count is now written only
  on `CompleteMultipartUpload`.

- Corrected `Range` header handling in `GetObject`, fixed header ordering,
  and returned the real ETag on `CopyObject` responses.

- Resolved a nil pointer panic in integration tests when Docker is
  unavailable.

---

## [0.1.0] — 2025-11-02

### Added

- **Initial release** of S3 Encryption Gateway.

- **Transparent AES-256-GCM encryption proxy**: a Go HTTP reverse proxy that
  encrypts objects on upload and decrypts on download, storing ciphertext on
  any S3-compatible backend without requiring client-side changes beyond
  pointing the S3 endpoint at the gateway.

- **ChaCha20-Poly1305 cipher support**: alternative AEAD cipher selectable
  via configuration for environments where AES-NI hardware acceleration is
  unavailable.

- **Password-based key derivation**: PBKDF2-derived encryption keys from a
  master password, with per-object random IVs stored in object user metadata.

- **Phase 3 S3 API compatibility**: implemented `PutObject`, `GetObject`,
  `HeadObject`, `DeleteObject`, `DeleteObjects`, `CopyObject`,
  `ListObjectsV2`, `CreateMultipartUpload`, `UploadPart`,
  `CompleteMultipartUpload`, `AbortMultipartUpload`, and `ListParts`
  handlers.

- **TLS support and security hardening**: configurable TLS for the gateway
  listener with mutual TLS option; hardened HTTP server timeouts.

- **Configurable S3 provider support**: generic endpoint-based backend
  configuration compatible with AWS S3, MinIO, Garage, and any
  S3-compatible service.

- **Proxied bucket configuration**: per-bucket proxy configuration mapping
  gateway bucket names to backend bucket names with optional path-style
  addressing.

- **Request body size logging**: middleware capturing and logging request
  body sizes for observability.

- **MinIO integration test infrastructure**: test harness for running
  integration tests against a local MinIO instance.

- **MIT License**.
