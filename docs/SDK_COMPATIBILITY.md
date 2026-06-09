# SDK / Tool Compatibility Matrix

> **Generated:** 2026-06-01 (v1.0 release).
> Automated smoke tests run against MinIO (local) and all local providers (Garage, RustFS, SeaweedFS).
> External providers (AWS S3, Backblaze B2) are checked nightly.

## Overview

This matrix certifies which S3 SDKs and CLI tools can be used as drop-in clients
against the **s3-encryption-gateway**. Each row represents a tool that has been
verified against the smoke-test baseline (PutObject, GetObject, HeadObject,
DeleteObject, ListObjectsV2, Multipart, CopyObject) through automated
conformance tests in CI.

### Status Symbols

| Symbol | Meaning |
|---|---|
| ✅ | Pass — operation certified |
| ⚠️ | Pass with caveat (see Caveats section) |
| ❌ | Fail — known incompatibility |
| ➖ | Not supported by the tool |

## Compatibility Matrix

| Tool | Version | PutObject | GetObject | HeadObject | DeleteObject | ListObjects | Multipart | CopyObject | Notes |
|---|---|---|---|---|---|---|---|---|---|
| AWS SDK Go v2 | v1.102 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| boto3 | 1.35 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| awscli | 2.22 | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | HeadObject via `s3api` |
| s5cmd | 2.3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ETag caveat |
| rclone | 1.68 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | Needs `--s3-copy-cutoff=1` |
| minio-py | 7.2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |

## Tool Version Policy

The matrix pins specific Docker image tags for container-based smoke tests.
These tags correspond to the latest stable release at the time of certification.
Requests to update pinned versions should be filed as a GitHub issue.

| Tool | Image | Tag |
|---|---|---|
| awscli | `amazon/aws-cli` | `2.22.0` |
| s5cmd | `peak/s5cmd` | `v2.3.0` |
| rclone | `rclone/rclone` | `1.68` |
| boto3 / minio-py | `python` | `3.13-slim` |

## Caveats

### awscli — HeadObject

The high-level `aws s3` sub-commands do not expose `HeadObject` directly.
The smoke test uses `aws s3api head-object` (low-level API) for this operation.

### s5cmd — ETag and CopyObject

s5cmd's `ls -e` flag prints ETags. The gateway returns the ciphertext ETag
(not the plaintext MD5) for encrypted objects. The smoke test verifies the
key is present in the listing but does not assert the ETag value.

Server-side copy (`cp`) works but the `--source-version-id` flag is
unsupported by the gateway's passthrough mechanism (the gateway does not
expose version IDs for server-side copy).

### rclone — Server-Side Copy

rclone requires `--s3-copy-cutoff=1` to force server-side copy instead of
falling back to client-side copy (download-then-upload). Without this flag,
rclone downloads the object and re-uploads it, which bypasses the gateway's
server-side copy passthrough. The smoke test applies this flag automatically.

The gateway does not support rclone's `--s3-use-multipart-uploads` for
copy operations; use the default (auto) setting.

### minio-py — Endpoint URL Handling

minio-py expects the endpoint without the `http://` or `https://` scheme
prefix. The SDK's `Minio` constructor strips the scheme from the endpoint
URL; the smoke test passes the raw endpoint as-is (the SDK handles
stripping internally).

## Running the Tests Locally

Prerequisites:
- Docker (for Testcontainers)
- Go 1.26+

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

3. **Presigned URL** smoke tests per tool are deferred to V1.0-S3-1 (Presigned
   URL conformance).

4. **KMS mode** is not tested per tool. All compat tests run in single-password
   (passphrase) mode. KMS-mode compatibility is validated by the existing KMS
   conformance tests (`CapKMSIntegration`).

5. **Windows and macOS** are not tested in CI. The conformance suite runs only
   on `ubuntu-latest`. Caveats for other platforms are documented if reported.

## Related Documents

- [V1.0-COMPAT-1 Implementation Plan](../docs/plans/V1.0-COMPAT-1-plan.md)
- [Conformance Test Suite](../test/conformance/)
