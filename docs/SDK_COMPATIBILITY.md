# SDK / Tool Compatibility Matrix

> **Source baseline:** v0.12.3; documentation reviewed October 4, 2026.
> Local CI schedules compatibility scenarios against MinIO, Garage, RustFS, and SeaweedFS,
> subject to provider capability gates. External suites are scheduled nightly when credentials are available.

## Overview

This matrix describes the automated SDK/tool scenarios in the released source,
not a certification of every operation or application using those tools. Check
the [application compatibility matrix](S3_API_IMPLEMENTATION.md#application-compatibility-matrix)
first for backend dependencies, browser POST/CORS gaps, listing-size and ETag
caveats, multipart requirements, and known reverse-proxy issues.
Use the [complete action inventory](S3_OPERATIONS.md) for individual operations
and the [option contract](S3_COMPATIBILITY.md) for supported request/response fields.

The basic runners cover upload, download, listing, and deletion; some also check
HEAD. The AWS SDK Go v2 runner additionally exercises multipart upload and copy.
Separate AWS CLI and boto3 HTTPS scenarios exercise multipart uploads, and an
AWS CLI scenario checks copy metadata. Listed versions are source pins, not new
test results from this documentation update. Inspect CI for current pass/skip/fail results.

### Status Symbols

| Symbol | Meaning |
|---|---|
| ✅ | Explicitly exercised by an automated compatibility scenario |
| ⚠️ | Exercised with the noted command/configuration caveat |
| ➖ | Not independently exercised for this tool by these scenarios; does not mean unsupported |

## Compatibility Matrix

| Tool | Version | PutObject | GetObject | HeadObject | DeleteObject | ListObjects | Multipart | CopyObject | Notes |
|---|---|---|---|---|---|---|---|---|---|
| AWS SDK Go v2 | S3 module v1.114.0 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Full seven-operation runner |
| boto3 | 1.43.107 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ➖ | Multipart in separate HTTPS trailer scenario |
| awscli | 2.37.8 | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | HEAD via `s3api`; multipart and copy in separate scenarios |
| s5cmd | 2.3.0 | ✅ | ✅ | ➖ | ✅ | ✅ | ➖ | ➖ | Listing command, not plaintext ETag, is checked |
| rclone | 1.75 | ✅ | ✅ | ➖ | ✅ | ✅ | ➖ | ➖ | Additional size-cache/fallback sync checks; copy not independently tested |
| minio-py | 7.2.20 | ✅ | ✅ | ✅ | ✅ | ✅ | ➖ | ➖ | HEAD via `stat_object` |

The generic multipart scenarios do not imply that every tool has been tested
with gateway-encrypted multipart state. Check the fixture's policy, Valkey,
and key-manager configuration when interpreting results. Separately, restic
0.19.1 has init/backup/restore scenarios with gateway encryption bypassed
(restic encrypts its own repository); these are not certification of gateway-encrypted MPUs.

## Tool Version Policy

The version table records the v0.12.3 pins from
[`compat_runners.go`](../test/conformance/compat_runners.go) and
[`go.mod`](../go.mod). Later branches may contain newer pins; updating a pin
does not by itself prove that a compatibility scenario passed.

Maintained conformance images use explicit, Renovate-managed version pins.
Updates are reviewed through pull requests and the compatibility matrix; a
versioned tag is reproducible by version but is not claimed to be immutable.

| Tool | Image | Tag |
|---|---|---|
| awscli | `amazon/aws-cli` | `2.37.8` |
| s5cmd | `peakcom/s5cmd` | `v2.3.0` |
| rclone | `rclone/rclone` | `1.75` |
| restic | `restic/restic` | `0.19.1` |
| boto3 / minio-py | `python` | `3.14-slim` (packages pinned separately above) |

## Caveats

### awscli — HeadObject

The high-level `aws s3` sub-commands do not expose `HeadObject` directly.
The smoke test uses `aws s3api head-object` (low-level API) for this operation.

### s5cmd — ETag and CopyObject

s5cmd's `ls -e` flag prints listing ETags. The gateway returns backend ETags
in listings, not plaintext MD5 for encrypted objects. The basic smoke test
checks listing behavior but does not assert ETag values.

The s5cmd runner does not independently test server-side copy or version-selection
flags. The gateway supports version-qualified copy-source headers when the backend
supports versioning; see the [copy-source contract](S3_API_IMPLEMENTATION.md#copy-source-encoding-and-identity-gh-346).

### rclone — Server-Side Copy

The basic runner uses `--s3-no-check-bucket=true` and `--s3-copy-cutoff=1`, but
it tests local upload/download rather than an S3-to-S3 copy. The copy-cutoff
flag selects rclone's threshold for multipart copy; it is not a universal gateway
requirement or proof that server-side copy is covered by this runner.

The gateway implements CopyObject and UploadPartCopy. Tool-specific copy behavior
needs separate verification with the actual client configuration. For sync/check
workloads, configure the plaintext-size cache (and optional HEAD fallback for
older objects); listing ETags remain backend ETags.

### minio-py — Endpoint URL Handling

minio-py expects the endpoint without the `http://` or `https://` scheme
prefix. The runner strips the scheme before constructing `Minio` and sets
`secure=False` for its HTTP fixture. Application code must choose `secure=True`
when using an HTTPS gateway endpoint.

## Running the Tests Locally

Prerequisites:
- Docker (for Testcontainers)
- Go 1.27.1+ (see `go.mod`)

```bash
# Run all compat smoke tests against all local providers (MinIO + Garage + RustFS + SeaweedFS):
make test-conformance-compat

# Run a single tool against MinIO only:
GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_SEAWEEDFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
  go test -count=1 -tags=conformance -race -v -timeout 15m \
  -run 'TestConformance/minio/Compat_Boto3' ./test/conformance/...

# Verify the matrix guard (no provider name literals in test bodies):
go test -count=1 -tags=conformance -v \
  -run 'TestConformance_NoProviderNameLiterals' ./test/conformance/...
```

## Known Limitations

1. **AWS SDK Go v1** is excluded from the matrix. SDK v1 reached security-patch
   end-of-life in July 2025. Users should migrate to SDK Go v2. See the
   [AWS SDK v2 migration guide](https://docs.aws.amazon.com/sdkref/latest/guide/migrate.html).

2. **AWS SDK Java v2** and **AWS SDK JS v3** are not yet in the matrix. They
   require JVM and Node.js Docker images respectively, which add significant
   CI time. Tracked as a future enhancement.

3. **Presigned URL** behavior has dedicated conformance coverage, including
   GH-345 lifetime and error cases, but not an exhaustive per-tool matrix.
   Browser POST Object and complete browser CORS remain planned features, not
   implied by a presigned GET/PUT test. See the
   [application compatibility matrix](S3_API_IMPLEMENTATION.md#application-compatibility-matrix).

4. **KMS mode** does not have a complete per-tool matrix. Basic tool fixtures
   use password-based encryption, while external KMS integration has dedicated
   conformance scenarios (`CapKMSIntegration`). Do not extrapolate those results
   to every tool/KMS/multipart combination.

5. **Windows and macOS** are not tested in CI. The conformance suite runs only
   on `ubuntu-latest`. Caveats for other platforms are documented if reported.

## Related Documents

See also the backend and encryption-mode coverage tables below. They distinguish
test eligibility from results and full feature parity.

- [V1.0-COMPAT-1 Implementation Plan](../docs/plans/V1.0-COMPAT-1-plan.md)
- [Conformance Test Suite](../test/conformance/)
- [Application Compatibility Matrix](S3_API_IMPLEMENTATION.md#application-compatibility-matrix)
- [Complete Operation Inventory](S3_OPERATIONS.md)
- [Request / Response Option Contract](S3_COMPATIBILITY.md)

## Backend and Encryption-Mode Coverage

**These tables describe the v0.12.3 source's test selection, not fresh test
results or provider product certification.** `S` means the fixture declares
the corresponding capability, making gated scenarios eligible. `—` means it
does not select that capability; this can mean missing provider functionality,
missing fixture setup, unverified behavior, or omitted coverage. Never interpret
`S` as proof that all options, SDKs, or workflows pass.

The source of truth is [`test/provider/`](../test/provider/) and
[`suite_test.go`](../test/conformance/suite_test.go). Ungated cases still run
without a capability bit. Some cases add their own skips or deliberately fake an
upstream response, so even an executed scenario is not always proof of native
backend behavior. Selected CORS forwarding tests do not certify encrypted browser uploads.

### Object and Encryption Test Selection

| Fixture | MPU | Part copy | Object tagging | Inline PUT tags | Versioning | Object Lock | Encrypted MPU | Size cache |
|---|---|---|---|---|---|---|---|---|
| MinIO | S | S | S | S | — | — | S | S |
| Garage | S | S | — | S | — | — | S | S |
| RustFS | S | S | S | S | — | — | S | S |
| SeaweedFS | S | S | S | S | S | — | S | S |
| AWS (external) | S | S | S | S | S | S | S | S |
| Backblaze B2 (external) | S | S | — | — | — | — | S | S |
| Hetzner (external) | S | S | S | S | — | — | S | — |
| Wasabi (external) | S | S | S | S | — | — | S | — |
| GCS configured endpoint | S | — | S | — | — | — | — | — |
| Azure configured endpoint | S | — | S | — | — | — | — | — |

GCS/Azure registrations are opt-in configured endpoints, not proof of native
non-S3 API support or a turnkey cloud deployment. Providers not registered in
this suite (for example Ceph, Cloudflare R2, DigitalOcean Spaces, and Swift)
have no blanket certification from these matrices.

### Bucket / Other Capability Selection

| Fixture | Create/delete buckets | Policy | Lifecycle | CORS | Bucket ACL | Object ACL | Bucket encryption | Conditional PUT / native SSE |
|---|---|---|---|---|---|---|---|---|
| MinIO | S | S | S | — | — | — | — | S / — |
| Garage | — | — | — | — | — | — | — | — / — |
| RustFS | — | — | — | — | — | — | — | — / — |
| SeaweedFS | — | — | — | — | — | — | — | — / — |
| AWS (external) | — | — | — | — | — | — | — | S / S |
| Backblaze B2 (external) | — | — | — | — | — | — | — | — / — |
| Hetzner / Wasabi (external) | — | — | — | — | — | — | — | — / — |
| GCS / Azure configured endpoint | — | — | — | — | — | — | — | S / — |

The last two flags describe fixture/backend selection only. The typed gateway
PUT path does **not** implement conditional If-Match/If-None-Match or per-upload
SSE mapping; a flag does not fix that missing contract. An absent AWS bucket
capability here does not assert that AWS lacks the API—it means the gated tests
are not selected by this fixture.

Batch-delete and presigned-URL bits are selected for all fixtures above. Load-test
eligibility is selected for the four locals, not external/cloud fixtures.
Backend TLS fixture selection is conditional on MinIO TLS setup; it is not a
cross-provider TLS certification.

### SDK / Tool Selection by Backend

| Fixture | Go v2 | boto3 | AWS CLI | s5cmd | rclone | minio-py | restic |
|---|---|---|---|---|---|---|---|
| MinIO / Garage / RustFS / SeaweedFS | S | S | S | S | S | S | S |
| AWS (external) | S | S | S | S | S | S | S |
| Backblaze B2 (external) | — | S | S | S | — | — | — |
| Hetzner / Wasabi (external) | — | — | — | — | — | — | — |
| GCS / Azure configured endpoint | — | — | — | — | — | — | — |

This selects the tool scenarios, **not every operation** for each tool. minio-go
also has a separate Multipart_MinIOGo scenario gated on multipart support, not
a complete operation matrix. Java v2, JS v3, PHP, Rust rust-s3, .NET, and other
clients have no exhaustive tool suite. PHP-informed copy-source fixes and the
unreleased rust-s3 proxy fix are not complete SDK certifications.

### Encryption Modes and Fixtures

| Mode / feature | Existing scenario evidence | Coverage boundary |
|---|---|---|
| Password-derived single objects | Basic/tool runners, chunked and KDF cases | Not every tool option/size; KDF variants have dedicated tests, not a full tool matrix. |
| Bypass encryption | Bypass metadata/body and restic init/backup/restore, including hybrid restore | No gateway confidentiality for bypass buckets; restic encrypts itself. Not encrypted MPU certification. |
| Encrypted MPU | EncryptedMPU / SEC38 / SEC46 and metadata-matrix cases with Valkey | Explicit fixture wiring required; generic tool MPU tests do not establish this mode. |
| Local AES/RSA envelope keys | SelfContained and metadata-matrix scenarios | Dedicated envelope/MPU tests, not every tool × key type × backend. |
| Cosmian KMS | CapKMSIntegration selected on four locals, AWS, B2 | Dedicated tests, not all tools or every failure/recovery combination. |
| OpenBao / Vault Transit | CapOpenBaoKMS selected on four locals | Dedicated KMS/rotation/failure cases, not a complete provider/tool matrix. |
| FIPS | Unit/race and vet build-profile jobs | No separate complete SDK/backend matrix. |
| AWS streaming / trailers | Signed integrity and HTTPS CLI/boto3 cases | Accepted protocol modes verified; no durable plaintext-checksum retrieval API. |
| Legacy object formats | Golden read fixtures and compatibility cases | Not arbitrary backend moves, historical MPU recovery, or every cross-format copy. |

Evidence: [`compat_test.go`](../test/conformance/compat_test.go),
[`selfcontained_envelope_test.go`](../test/conformance/selfcontained_envelope_test.go),
[`selfcontained_mpu_test.go`](../test/conformance/selfcontained_mpu_test.go),
[`kms_test.go`](../test/conformance/kms_test.go),
[`openbao_kms_test.go`](../test/conformance/openbao_kms_test.go),
[`metadata_matrix_test.go`](../test/conformance/metadata_matrix_test.go), and
[`object_headers_golden_harness_test.go`](../internal/api/object_headers_golden_harness_test.go).

Local CI selects MinIO/Garage/RustFS/SeaweedFS on PR/main runs. External suites
are credential-gated in nightly/release jobs; missing credentials can skip them.
Source pins and capability bits are not historical pass results. Inspect the
[conformance workflow](../.github/workflows/conformance.yml), actual CI logs,
fixture policy/Valkey/KMS wiring, and per-test skips before asserting compatibility.

### Workflows Not Independently Certified

No complete matrix covers every unsupported action's wire error; all listing/part
pagination inputs; conditional requests; checksum-mode retrieval; per-request SSE,
ownership/requester-pays/MFA; analytics/inventory pagination; replication/event
delivery; archive restore; anonymous website hosting; historical MPU version
recovery; every SDK/proxy; or every SDK/backend/key-manager combination. Known
missing mappings are limitations, not merely test gaps: see the [option contract](S3_COMPATIBILITY.md).

## Streaming Upload Compatibility

AWS SigV4 streaming payloads are supported only with the exact protocol modes
documented in [`SECURITY.md`](../SECURITY.md). AWS CLI and SDK-style signed multi-chunk uploads
are verified atomically before storage. Signed trailers and all five supported
checksum trailers are verified before storage; unknown or ambiguous modes are
rejected rather than decoded as plaintext.

The accepted checksum trailers are CRC64NVME, CRC32, CRC32C, SHA-1, and SHA-256.

Header-authenticated non-streaming SigV4 requests may provide a concrete
lowercase SHA-256 `X-Amz-Content-Sha256` value. The gateway hashes and spools
that body before dispatch, rejects body changes with `SignatureDoesNotMatch`,
and replays the verified bytes with the exact content length. Requests using
`UNSIGNED-PAYLOAD` remain compatible and intentionally do not receive this
preflight integrity guarantee.
