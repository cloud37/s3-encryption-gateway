# ADR 0006: UploadPartCopy Implementation and Source-Format Dispatch

## Status
Accepted

## Context

The S3 Encryption Gateway currently has a silent-failure trap on the `UploadPartCopy` operation (PUT request with `x-amz-copy-source` header on a multipart part URL). The operation is not routed to a dedicated handler, and requests that should copy a byte range from a source object are instead treated as regular UploadPart requests, reading the body as part data and uploading zero bytes.

UploadPartCopy is critical for:
- Efficient server-side copying without downloading/re-uploading through the client
- Large object copies that benefit from range operations on encrypted sources
- Cross-bucket object assembly without bandwidth overhead
- Compliance with S3 API completeness

The gateway's multipart parts are stored plaintext (per ADR 0002), but the **source** object may be:
1. **Plaintext** – can use backend-native `UploadPartCopy` for zero-gateway-overhead
2. **Chunked-encrypted** – can be efficiently range-decrypted using the chunked decryption infrastructure
3. **Legacy single-AEAD encrypted** – requires full object decryption (costly but correct)

This decision document records the architectural choices for dispatching and executing UploadPartCopy based on source encryption format, and the security controls around cross-key-space operations.

## Problem Statement

1. **Silent failures**: UploadPartCopy requests silently produce empty/corrupt parts with no error indication.
2. **Incomplete dispatch**: The route table does not distinguish UploadPartCopy from regular UploadPart.
3. **Plaintext fast path is unused**: Backend-native copy capabilities are never invoked because every operation is mediated for encryption.
4. **ProxyClient stub is incomplete**: The `ProxyClient.CopyObject` method returns "not implemented", breaking copy operations in proxy/passthrough deployments.
5. **Cross-key-space hazards**: When source and destination buckets use different encryption engines/KEKs, the handler must correctly resolve both; mismatch between plaintext source and encrypted-destination bucket config must be detected.

## Decision

Implement a dedicated `handleUploadPartCopy` handler that:

1. **Routes correctly**: Requests with `x-amz-copy-source` header on multipart PUT URLs are dispatched to `handleUploadPartCopy` before the body is read.

2. **Classifies sources**: A single `HeadObject` call determines the source's encryption class:
   - **Plaintext**: No encryption metadata → fast path (backend-native `UploadPartCopy`)
   - **Chunked-encrypted**: `x-amz-meta-encryption-chunked=true` → mediated range-decrypt path
   - **Legacy single-AEAD**: `x-amz-meta-encrypted=true` (no chunked flag) → full-decrypt fallback

3. **Applies strategies per class**:
   - **Plaintext**: Call backend's native `UploadPartCopy` directly, forward the result as-is (zero bytes through gateway).
   - **Chunked**: Use `CalculateEncryptedRangeForPlaintextRange` to translate the requested plaintext range to encrypted byte offsets; fetch that range; call `DecryptRange` to get a plaintext stream; pipe to `UploadPart`.
   - **Legacy**: Fetch full object; decrypt full; slice plaintext; pipe to `UploadPart`. Log warning.

4. **Enforces S3 MPU part-size rules**:
   - Non-final parts: `5 MiB ≤ size ≤ 5 GiB`
   - Any single copy source range: `≤ 5 GiB`
   - Source > 5 GiB without range: `400 InvalidRequest`

5. **Respects cross-key-space correctness**: Source and destination may resolve to different encryption engines (different KEKs). Reuse the engine resolution pattern from `handleCopyObject`.

6. **Detects config mismatches**: If destination bucket config mandates encryption but the classified source is plaintext, return `500 InternalError` and emit an audit event (trust-on-first-read hazard mitigation per *Real-World Cryptography* Ch. 16).

7. **Maintains bounded memory**: Chunked path buffers only one chunk (~64 KiB default, 1 MiB max) plus a transfer buffer. Legacy path buffers the full object with a configurable cap (default 256 MiB, opt-out safety posture).

8. **Fixes ProxyClient stubs**: Both `ProxyClient.UploadPartCopy` and `ProxyClient.CopyObject` forward HTTP requests to the backend with appropriate headers and parse responses.

## Implementation Details

### Source Classification

The `classifyCopySource` helper issues one `HeadObject` to the source, examining:
- `x-amz-meta-encryption-chunked` header → `SourceClassChunked`
- `x-amz-meta-encrypted` header (without chunked flag) → `SourceClassLegacy`
- Neither → `SourceClassPlaintext`

### Plaintext Fast Path

```go
copyResult, err := s3Client.UploadPartCopy(ctx, dstBucket, dstKey, uploadID, partNumber,
    srcBucket, srcKey, srcVersionID, srcRange)
// Result forwarded as-is; zero bytes through gateway
```

This delegates to the backend's native implementation, achieving zero-copy for unencrypted sources.

### Chunked Mediated Path

```go
// 1. Translate plaintext range to encrypted range
encStart, encEnd, err := CalculateEncryptedRangeForPlaintextRange(srcMetadata, plaintextStart, plaintextEnd)

// 2. Fetch encrypted range
rangeHeader := fmt.Sprintf("bytes=%d-%d", encStart, encEnd)
srcReader, _, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, &rangeHeader)

// 3. Decrypt range to plaintext
plainReader, _, err := srcEngine.DecryptRange(srcReader, srcMetadata, plaintextStart, plaintextEnd)

// 4. Upload plaintext part
etag, err := s3Client.UploadPart(ctx, dstBucket, dstKey, uploadID, partNumber, plainReader, nil)
```

This path is efficient because `DecryptRange` skips chunks outside the requested range and seeks within the encrypted stream.

### Legacy Fallback Path

```go
// 1. Fetch full object
srcReader, srcMetadata, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)

// 2. Decrypt full
plainReader, _, err := srcEngine.Decrypt(srcReader, srcMetadata)

// 3. Read into memory and slice
plaintext := io.ReadAll(plainReader)
if srcRange != nil {
    plaintext = plaintext[srcRange.First : srcRange.Last+1]
}

// 4. Upload sliced part
etag, err := s3Client.UploadPart(ctx, dstBucket, dstKey, uploadID, partNumber, bytes.NewReader(plaintext), nil)
```

This path is necessary for single-AEAD sources but is documented as slow. A warning is logged with the object size to help operators spot the slow path in dashboards.

### Config Mismatch Detection

If the destination bucket policy mandates encryption (`PolicyConfig.RequireEncryption=true`) but the classified source is plaintext, the handler returns `500 InternalError` and emits an audit event. The check is implemented in `handleUploadPartCopy` (see `internal/api/upload_part_copy.go`):

```go
if sourceClass.Class == SourceClassPlaintext &&
    h.policyManager != nil &&
    h.policyManager.BucketRequiresEncryption(bucket) {
    // Hard refusal: 500 InternalError + audit event with reason=destination_requires_encryption
}
```

Policy is declared per-bucket via glob patterns in policy YAML:

```yaml
id: my-secure-bucket-policy
buckets:
  - secure-*
require_encryption: true
```

This prevents silent security degradation caused by configuration drift. Verified by integration test `TestUploadPartCopy_PlaintextSource_EncryptedDestBucket_Refused`.

### Source-Bucket Read Authorisation

The handler enforces source read authorisation implicitly by issuing the source `HeadObject` / `GetObject` through the same caller-derived S3 client (`h.getS3Client(r)`) used for the destination. When `UseClientCredentials` is enabled, each request carries the caller's SigV4 credentials; a caller without `s3:GetObject` on the source bucket receives `AccessDenied` from the backend, which `TranslateError` maps to HTTP 403.

This avoids a dual-authorisation check implementation while guaranteeing that no cross-bucket read escalation is possible via UploadPartCopy. Verified by integration test `TestUploadPartCopy_CrossBucket_ReadDenied`.

### Legacy Fallback Cap

`Server.MaxLegacyCopySourceBytes` (default **256 MiB**) caps the legacy-source full-object buffer. A pre-flight check uses the `HeadObject` Content-Length; a defensive post-decrypt check via `io.LimitReader` backs it up against backends that misreport size. Exceeding the cap returns `400 InvalidRequest` with a message pointing operators at the chunked-encryption migration path or the config knob.

### Error Codes and Semantics

Per AWS S3 spec and `docs/S3_API_IMPLEMENTATION.md`:

| Condition | HTTP | Code |
|---|---|---|
| Missing `uploadId` / `partNumber` | 400 | `InvalidRequest` |
| Malformed `x-amz-copy-source` | 400 | `InvalidArgument` |
| Malformed `x-amz-copy-source-range` | 400 | `InvalidArgument` |
| Source not found | 404 | `NoSuchKey` |
| Source bucket not found | 404 | `NoSuchBucket` |
| Source > 5 GiB with no range | 400 | `InvalidRequest` |
| Source range start ≥ object size | 416 | `InvalidRange` |
| Multipart uploads disabled | 501 | `NotImplemented` |
| Proxy mode, mediation not supported | 501 | `NotImplemented` |
| Destination requires encryption, source is plaintext | 500 | `InternalError` |

## Rationale

### Why Classify by Metadata Instead of Object Content

Classifying by `x-amz-meta-encryption-*` headers (not by re-reading the object) is fast and avoids double-reads. The metadata is set by the gateway on encryption and is trusted as the single source of truth for the source object's encryption format.

### Why Plaintext Fast Path is Safe

The plaintext fast path uses backend-native `UploadPartCopy`. This is safe because:
- The source is genuinely unencrypted (verified by absence of encryption metadata).
- The destination part remains plaintext (per ADR 0002).
- No encryption state transitions occur.
- Audit logging records the operation.

### Why Config Mismatch is a Hard Refusal

If destination policy says "must be encrypted" but source is plaintext, uploading plaintext violates policy. A hard refusal (with audit event) is more secure than a best-effort attempt. This aligns with *Building Secure and Reliable Systems* Ch. 5 §"Design for Least Privilege" and *Real-World Cryptography* Ch. 16 §"Cryptography is not an island".

### Why Legacy Fallback Has a Configurable Cap

Full-object buffering for legacy sources is necessary but dangerous. A conservative default (256 MiB) with an explicit opt-out requirement forces operators to acknowledge the risk. This implements the opt-out safety posture from *Building Secure and Reliable Systems* Ch. 10 §"Self-Inflicted Attacks".

### Why ProxyClient is Fixed in the Same PR

`ProxyClient.CopyObject` and `UploadPartCopy` are HTTP-forwarding implementations that unblock copy operations in proxy deployments. Fixing them together avoids shipping a half-functional copy story.

## Consequences

### Positive
- UploadPartCopy is now routed and implemented correctly (no more silent failures).
- Plaintext sources use backend-native copy (zero gateway overhead).
- Encrypted sources are correctly decrypted and copied (no data corruption).
- Chunked sources are efficiently range-decrypted (only necessary chunks are processed).
- Cross-key-space operations are safe and audited.
- Proxy deployments can use copy operations.
- Config mismatches are detected before silent data compromise.

### Negative
- Legacy encrypted sources require full object buffering (slow path documented with warnings).
- Additional complexity in source classification and strategy dispatch.

### Neutral
- Destination parts remain plaintext (no change from current behavior, per ADR 0002).

## Cross-References

- **ADR 0002**: *Multipart Upload Interoperability* – establishes plaintext-part design; this ADR upholds it.
- **V0.6-SEC-1 Plan**: Provides in-memory KeyManager infrastructure for unit tests.
- **V0.6-QA-1**: Benchmarks for this implementation (`BenchmarkUploadPartCopy_{Chunked_64KiB_Range,Legacy_16MiB_Range,Plaintext_Passthrough_1GiB}` in `internal/s3/upload_part_copy_bench_test.go`) feed the per-provider performance baseline corpus. See [`docs/PERFORMANCE.md`](../PERFORMANCE.md).

## Future Considerations

1. **Encrypted multipart destinations** – A future proposal may introduce chunked-MPU with a finalization manifest on `CompleteMultipartUpload`. Would require a new per-upload envelope scheme (out of scope here).
2. **Backend-native CopyObject when source is plaintext** – Extend the plaintext fast-path optimization to regular `CopyObject`.
3. **Conditional copy headers** – `x-amz-copy-source-if-match`, etc. – forward on fast path; implement HeadObject-based checks on mediated path.
4. **Zero-copy optimizations** – Beyond plaintext, explore streaming decryption pipelines for chunked sources (V0.6-PERF-1).

---

## Addendum — V0.6-PERF-1 (streaming refactor)

Implemented as part of V0.6-PERF-1. The following behaviour changes apply
from the streaming rewrite:

### `Server.MaxPartBuffer` (new, default 64 MiB)

`handleUploadPart` no longer calls `io.ReadAll(r.Body)` or
`io.ReadAll(encReader)`. Both are replaced with a pooled
`*s3.SeekableBody` wrapper that reads at most `Server.MaxPartBuffer`
bytes. Parts whose body exceeds the cap are refused with HTTP 413 before
any backend write occurs. Operators uploading parts > 64 MiB must raise
this value explicitly. See `internal/s3/seekable_body.go`.

### Compression pre-filter (behaviour change)

`compression.go` previously applied compression and then compared the
compressed vs original size, discarding the compressed output when it
was not smaller. This post-hoc size check is **removed** in V0.6-PERF-1
because it is incompatible with streaming (the final size is not known
until the entire compressed payload has been produced).

The `ShouldCompress` pre-filter (size threshold + content-type) is now
the sole compression gate, consistent with nginx, Envoy, and the AWS SDK.
Incompressible payloads (random bytes, pre-compressed content) that slip
through the content-type filter will grow by ≤ ~20 bytes (gzip header
overhead). The content-type exclusion list (`image/*`, `video/*`, etc.)
prevents this from being a concern in practice.

> **Superseded by V1.0-MAINT-2:** The entire compression feature was removed
> in v1.0. See `docs/plans/V1.0-MAINT-2-plan.md`.

### `MaxLegacyCopySourceBytes` now enforced on `handleCopyObject`

Previously only enforced in `uploadPartCopyLegacy`. V0.6-PERF-1 adds the
same cap to `handleCopyObject` to prevent unbounded allocation when the
source is a legacy (non-chunked) encrypted object.
