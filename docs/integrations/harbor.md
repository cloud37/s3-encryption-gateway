# Harbor Integration

> **For compatible operation, Harbor must be configured with `redirect.disable: true` in its storage backend configuration.**

## Overview

[Harbor](https://goharbor.io/) is an open-source container registry. It uses
[Docker Distribution](https://github.com/distribution/distribution) as its
underlying registry engine, which in turn uses an S3 storage driver.

When the encryption gateway is placed between Harbor and your S3-compatible
backend (e.g. Ceph, MinIO), the gateway transparently encrypts all objects.
Harbor requires one specific configuration setting to work correctly with
the gateway.

## Required Configuration

Set `redirect.disable: true` in Harbor's storage configuration.

### Helm Chart

```yaml
# values.yaml
imageChartStorage:
  disableredirect: true
  s3:
    bucket: harbor
    existingSecret: s3-credentials
    region: us-east-1
    regionendpoint: https://<gateway-host>:<gateway-port>
    secure: true
    type: s3
```

### Standalone (harbor.yml)

```yaml
# harbor.yml or harbor.yml.tmpl
storage_service:
  s3:
    accesskey: <gateway-access-key>
    secretkey: <gateway-secret-key>
    region: us-east-1
    bucket: harbor
    regionendpoint: https://<gateway-host>:<gateway-port>
    encrypt: false
    secure: true
    skipverify: false
    v4auth: true
    rootdirectory: /
    redirect:
      disable: true
```

### Why `redirect.disable: true` Is Required

Without this setting (`redirect.disable: false`, the default), Harbor tells
Docker clients to download blobs directly from the S3 endpoint via presigned
redirect URLs:

```
Client → Harbor → 302 redirect → Gateway → Backend
```

This path is incompatible with the gateway because:

1. **Host mismatch**: The presigned URL is signed with `Host: <gateway-host>`,
   but the Docker client connects using the gateway's internal endpoint, which
   may not match the certificate or the URL Harbor constructed. This causes
   signature verification failures.

2. **Blob length verification**: Docker Distribution's S3 driver tracks
   plaintext byte offsets during upload. After `CompleteMultipartUpload`,
   it validates the blob size by querying the backend. With `redirect.disable:
   true`, all S3 calls happen server-side through Harbor's own S3 driver,
   which compares the gateway's reported plaintext size against its internal
   counter. With `redirect.disable: false`, the redirect path may bypass
   this validation or observe inconsistent state.

With `redirect.disable: true`, Harbor proxies all blob data through its own
HTTP server:

```
Client → Harbor → Gateway → Backend
```

This ensures:
- All S3 calls originate from Harbor's server process.
- The gateway's plaintext size translation (HeadObject, ListObjects,
  ListParts) is consistently observed.
- Multi-registry setups work correctly since the client never connects
  directly to the gateway.

## Compatibility

The gateway has been tested with Harbor v2.x against the following S3
backends:

| Backend | Status | Notes |
|---|---|---|
| Ceph (RADOS Gateway) | ✅ Working | Requires `redirect.disable: true` |
| MinIO | ✅ Working | Requires `redirect.disable: true` |
| AWS S3 | ✅ Working | Requires `redirect.disable: true` |

## Known Behaviour

### Multipart Upload Blob Validation

Harbor's Docker Distribution S3 driver uses several S3 API calls to track
upload progress and validate completed blobs:

| S3 Call | Purpose | Gateway Behaviour |
|---|---|---|
| `ListObjects` (max-keys=1) | `statList()` — check upload object size | Returns plaintext size via Valkey state (in-progress) or `.mpu-manifest` (completed) |
| `HeadObject` | `statHead()` — verify blob after Complete | Returns plaintext `Content-Length` from `.mpu-manifest` |
| `ListParts` | Track part offsets during upload | Returns plaintext part sizes from Valkey |
| `CopyObject` / `UploadPartCopy` | `moveBlob()` — copy staging upload to content-addressed location | Recognises encrypted-MPU source, decrypts via manifest, re-encrypts into destination |

All gateway-side fixes are fail-soft: if a manifest or state lookup fails,
the original backend (ciphertext) value is returned.

### Large Images

Harbor uses `UploadPartCopy` for blobs larger than the `MultipartCopyThresholdSize`
(default 32 MiB). The gateway correctly classifies encrypted-MPU sources and
decrypts them before copying.

### Image GC

Harbor's garbage collection issues S3 `HEAD` and `DELETE` requests. The
gateway proxies these transparently. No special configuration is required
for GC to work.
