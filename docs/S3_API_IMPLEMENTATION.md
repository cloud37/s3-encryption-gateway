# S3 API Implementation Strategy

## Overview

The S3 Encryption Gateway must maintain full compatibility with the Amazon S3 API while transparently encrypting and decrypting object data. This document outlines the implementation strategy for S3 API compatibility.

## S3 API Operations Classification

### Operations Requiring Encryption/Decryption

#### PUT Object
- **Endpoint**: `PUT /{bucket}/{key}`
- **Encryption**: Required for object data
- **Implementation**:
  - Parse request body as stream
  - Encrypt data using configured algorithm
  - Preserve original metadata
  - Add encryption metadata markers
  - Forward to backend with encrypted data

#### GET Object
- **Endpoint**: `GET /{bucket}/{key}`
- **Decryption**: Required for object data
- **Implementation**:
  - Check if object is encrypted (metadata marker)
  - Fetch encrypted data from backend
  - Decrypt data stream
  - Restore original metadata
  - Return decrypted response

#### POST Object (Multipart Upload)
- **Endpoints**:
  - `POST /{bucket}/{key}?uploads` - Initiate multipart upload
  - `PUT /{bucket}/{key}?partNumber=X&uploadId=Y` - Upload part
  - `POST /{bucket}/{key}?uploadId=Y` - Complete multipart upload
- **Encryption**: NOT applied (parts stored unencrypted)
- **Implementation**:
  - Parts are forwarded to backend without encryption to avoid concatenation issues
  - Preserve ordering and part ETags
  - Complete uploads by passing part list to backend
  - Multipart uploads bypass encryption for S3 provider compatibility
- **Security Considerations**:
  - **Multipart uploads are not encrypted** due to fundamental architectural limitations
  - Each part cannot be encrypted individually because S3 concatenates parts server-side
  - Encrypting parts separately creates multiple invalid encrypted streams when combined
  - For encrypted multipart uploads, use client-side encryption before sending to the gateway
- **Security Features (V0.4)**:
  - Robust XML parsing with 10MB size limits to prevent DoS
  - Comprehensive validation of part numbers (1-10000 range)
  - ETag format validation with proper quoting requirements
  - Duplicate part number detection and rejection
  - Fuzz-tested XML parser for edge case handling
   - Provider interoperability testing framework

#### PUT Object (Multipart Copy / UploadPartCopy)
- **Endpoint**: `PUT /{bucket}/{key}?partNumber=X&uploadId=Y&x-amz-copy-source=...`
- **Description**: Copies a byte range from a source object as a part in a multipart upload
- **Encryption**: Conditional based on source encryption status
- **Implementation**:
  - **Routing**: Requests with `x-amz-copy-source` header are dispatched to dedicated `handleUploadPartCopy`
  - **Source Classification Matrix**:
    | Source Type | Metadata Flag | Strategy |
    |---|---|---|
    | Plaintext | None | Fast path: backend-native `UploadPartCopy` (zero bytes through gateway) |
    | Chunked-encrypted | `x-amz-meta-encryption-chunked=true` | Mediated: translate plaintext range → encrypted range via `CalculateEncryptedRangeForPlaintextRange`, GET encrypted range, `DecryptRange`, stream to `UploadPart` |
    | Legacy single-AEAD | `x-amz-meta-encrypted=true` (without chunked flag) | Mediated (slow): GET full object, decrypt, slice plaintext by range, stream to `UploadPart` |
  - **Range Handling**: `x-amz-copy-source-range: bytes=first-last` is parsed and respected
    - For chunked sources: efficiently decrypts only the required chunks
    - For legacy sources: full object decryption with warning logged
    - Omitted range: copies entire source object (up to 5 GiB limit)
  - **MPU Part-Size Enforcement**:
    - Non-final parts: `5 MiB ≤ size ≤ 5 GiB`
    - Any single copy source range: `≤ 5 GiB`
    - Source object > 5 GiB without range: returns `400 InvalidRequest`
- **Response Contract**:
  ```xml
  <CopyPartResult>
    <ETag>"..."</ETag>
    <LastModified>2026-04-17T10:00:00.000Z</LastModified>
  </CopyPartResult>
  ```
  - ETag is the backend's raw UploadPart or UploadPartCopy ETag (not re-encrypted)
  - LastModified reflects part write time
- **Error Codes**:
  - `400 InvalidArgument`: Malformed x-amz-copy-source or x-amz-copy-source-range
  - `400 InvalidRequest`: Source object > 5 GiB with no range; or multipart uploads disabled
  - `404 NoSuchKey` / `404 NoSuchBucket`: Source not found
  - `416 InvalidRange`: Range start ≥ object size
  - `501 NotImplemented`: Proxy mode without mediation support
- **Security Considerations**:
  - Destination parts remain plaintext (per ADR 0002)
  - Source-bucket read authorization is explicitly checked independent of destination write authorization
  - Cross-key-space (different source/destination buckets) is supported and tested
  - Config mismatch (plaintext source to encrypted-destination bucket) triggers hard refusal with audit event

#### PUT Object Copy
- **Endpoint**: `PUT /{bucket}/{key}?x-amz-copy-source=...`
- **Encryption**: Conditional based on source encryption status
- **Implementation**:
  - Check if source object is encrypted
  - Copy operation may require decryption then re-encryption

### Operations NOT Requiring Encryption

#### List Objects
- **Endpoints**:
  - `GET /{bucket}?list-type=2` (ListObjectsV2)
  - `GET /{bucket}` (ListObjects)
  - `GET /{bucket}?delimiter=...` (ListObjects with delimiter)
- **Implementation**: Object bodies are passed through unmodified, but
  per-object **sizes are translated** as of V1.0-S3-3 (see below).
- **Size translation (V1.0-S3-3)**: `handleListObjects` resolves plaintext
  sizes via a Valkey-backed write-through size cache (`plainsize:<bucket>`
  hash, single `HMGET` per page) populated by `PutObject`,
  `CompleteMultipartUpload`, and `CopyObject`. Cache hits return plaintext
  sizes with zero per-object `HeadObject` calls; an opt-in bounded HEAD batch
  (`list_size_translate.fallback_head_enabled`) warms misses. **Fail-soft**:
  if Valkey is unavailable, ciphertext sizes are returned (no `5xx`). ETags
  remain ciphertext ETags. See `docs/plans/V1.0-S3-3-plan.md`.

#### Head Bucket
- **Endpoint**: `HEAD /{bucket}`
- **Implementation**:
  - Validate bucket-level existence/access against backend
  - Return `200 OK` with empty body on success
  - Return translated S3 error codes (`NoSuchBucket`, `AccessDenied`, etc.) on failure


#### Head Object
- **Endpoint**: `HEAD /{bucket}/{key}`
- **Implementation**:
  - Fetch metadata from backend
  - If encrypted, modify metadata to show original values
  - Hide encryption-specific metadata

#### Delete Object
- **Endpoints**:
  - `DELETE /{bucket}/{key}`
  - `POST /{bucket}?delete` (DeleteObjects)
- **Implementation**: Pass-through to backend, no decryption needed

#### Bucket Operations
- **Endpoints**: All bucket-level operations (create, delete, policy, etc.)
- **Implementation**: Pass-through to backend, no encryption concerns

## S3 API Coverage Matrix (V1.0-S3-2)

### New Operations — Tier 1 (Critical)

| # | Method | Route | Operation | Handler | Handling |
|---|---|---|---|---|---|
| T1-01 | `DELETE` | `/{bucket}` | **DeleteBucket** | `handleDeleteBucket` | Guarded proxy (+audit) |
| T1-02 | `GET` | `/` | **ListBuckets** | `handleListBuckets` | Proxy verbatim |
| T1-03 | `GET` | `/{bucket}?location` | **GetBucketLocation** | `handleGetBucketLocation` | Proxy verbatim |
| T1-04 | `GET` | `/{bucket}?versioning` | **GetBucketVersioning** | `handleGetBucketVersioning` | Proxy verbatim |
| T1-05 | `PUT` | `/{bucket}?versioning` | **PutBucketVersioning** | `handlePutBucketVersioning` | Proxy verbatim |
| T1-06 | `GET` | `/{bucket}?uploads` | **ListMultipartUploads** | `handleListMultipartUploads` | Proxy verbatim |
| T1-07 | `GET` | `/{bucket}/{key}?tagging` | **GetObjectTagging** | `handleGetObjectTagging` | Proxy verbatim |
| T1-08 | `PUT` | `/{bucket}/{key}?tagging` | **PutObjectTagging** | `handlePutObjectTagging` | Proxy verbatim |
| T1-09 | `DELETE` | `/{bucket}/{key}?tagging` | **DeleteObjectTagging** | `handleDeleteObjectTagging` | Proxy verbatim |
| T1-10 | `GET` | `/{bucket}?acl` | **GetBucketACL** | `handleGetBucketACL` | Proxy verbatim |
| T1-11 | `PUT` | `/{bucket}?acl` | **PutBucketACL** | `handlePutBucketACL` | Proxy verbatim |
| T1-12 | `GET` | `/{bucket}/{key}?acl` | **GetObjectACL** | `handleGetObjectACL` | Proxy verbatim |
| T1-13 | `PUT` | `/{bucket}/{key}?acl` | **PutObjectACL** | `handlePutObjectACL` | Proxy verbatim |

### New Operations — Tier 2 (Common)

| # | Method | Route | Operation | Handler | Handling |
|---|---|---|---|---|---|
| T2-01 | `GET` | `/{bucket}?policy` | **GetBucketPolicy** | `handleGetBucketPolicy` | Proxy verbatim |
| T2-02 | `PUT` | `/{bucket}?policy` | **PutBucketPolicy** | `handlePutBucketPolicy` | Proxy verbatim |
| T2-03 | `DELETE` | `/{bucket}?policy` | **DeleteBucketPolicy** | `handleDeleteBucketPolicy` | Proxy verbatim |
| T2-04 | `GET` | `/{bucket}?cors` | **GetBucketCors** | `handleGetBucketCors` | Proxy verbatim |
| T2-05 | `PUT` | `/{bucket}?cors` | **PutBucketCors** | `handlePutBucketCors` | Proxy verbatim |
| T2-06 | `DELETE` | `/{bucket}?cors` | **DeleteBucketCors** | `handleDeleteBucketCors` | Proxy verbatim |
| T2-07 | `GET` | `/{bucket}?lifecycle` | **GetBucketLifecycle** | `handleGetBucketLifecycle` | Proxy verbatim |
| T2-08 | `PUT` | `/{bucket}?lifecycle` | **PutBucketLifecycle** | `handlePutBucketLifecycle` | Proxy verbatim |
| T2-09 | `DELETE` | `/{bucket}?lifecycle` | **DeleteBucketLifecycle** | `handleDeleteBucketLifecycle` | Proxy verbatim |
| T2-10 | `OPTIONS` | `/{bucket}\|/{bucket}/{key}` | **CORS Preflight** | `handleCORSPreflight` | Gateway-handled |
| T2-11 | `POST` | `/{bucket}/{key}?restore` | **RestoreObject** | `handleRestoreObject` | Proxy verbatim |
| T2-12 | `GET` | `/{bucket}?encryption` | **GetBucketEncryption** | `handleGetBucketEncryption` | Proxy verbatim |
| T2-13 | `PUT` | `/{bucket}?encryption` | **PutBucketEncryption** | `handlePutBucketEncryption` | Proxy verbatim |
| T2-14 | `DELETE` | `/{bucket}?encryption` | **DeleteBucketEncryption** | `handleDeleteBucketEncryption` | Proxy verbatim |

### New Operations — Tier 3 (Specialised)

| # | Method | Route | Operation | Handler | Handling |
|---|---|---|---|---|---|
| T3-01 | `GET` | `/{bucket}?notification` | **GetBucketNotification** | `handleGetBucketNotification` | Proxy verbatim |
| T3-02 | `PUT` | `/{bucket}?notification` | **PutBucketNotification** | `handlePutBucketNotification` | Proxy verbatim |
| T3-03 | `GET` | `/{bucket}?replication` | **GetBucketReplication** | `handleGetBucketReplication` | Proxy verbatim |
| T3-04 | `PUT` | `/{bucket}?replication` | **PutBucketReplication** | `handlePutBucketReplication` | Proxy verbatim |
| T3-05 | `DELETE` | `/{bucket}?replication` | **DeleteBucketReplication** | `handleDeleteBucketReplication` | Proxy verbatim |
| T3-06 | `GET` | `/{bucket}?logging` | **GetBucketLogging** | `handleGetBucketLogging` | Proxy verbatim |
| T3-07 | `PUT` | `/{bucket}?logging` | **PutBucketLogging** | `handlePutBucketLogging` | Proxy verbatim |
| T3-08 | `GET` | `/{bucket}?requestPayment` | **GetBucketRequestPayment** | `handleGetBucketRequestPayment` | Proxy verbatim |
| T3-09 | `PUT` | `/{bucket}?requestPayment` | **PutBucketRequestPayment** | `handlePutBucketRequestPayment` | Proxy verbatim |
| T3-10 | `GET` | `/{bucket}?website` | **GetBucketWebsite** | `handleGetBucketWebsite` | Proxy verbatim |
| T3-11 | `PUT` | `/{bucket}?website` | **PutBucketWebsite** | `handlePutBucketWebsite` | Proxy verbatim |
| T3-12 | `DELETE` | `/{bucket}?website` | **DeleteBucketWebsite** | `handleDeleteBucketWebsite` | Proxy verbatim |
| T3-13 | `GET` | `/{bucket}?inventory` | **GetBucketInventory** | `handleGetBucketInventory` | Proxy verbatim |
| T3-14 | `PUT` | `/{bucket}?inventory` | **PutBucketInventory** | `handlePutBucketInventory` | Proxy verbatim |
| T3-15 | `DELETE` | `/{bucket}?inventory` | **DeleteBucketInventory** | `handleDeleteBucketInventory` | Proxy verbatim |
| T3-16 | `GET` | `/{bucket}?analytics` | **GetBucketAnalytics** | `handleGetBucketAnalytics` | Proxy verbatim |
| T3-17 | `POST` | `/{bucket}/{key}?select` | **SelectObjectContent** | `handleSelectObjectContent` | 501 NotImplemented |
| T3-18 | `PUT` | `/{bucket}?intelligent-tiering` | **PutBucketIntelligentTiering** | `handlePutBucketIntelligentTiering` | Proxy verbatim |

### Known Limitations (V1.0-S3-2)

| Operation | Reason |
|---|---|
| `SelectObjectContent` | Requires server-side SQL evaluation on encrypted data — not feasible in a proxy model |
| `WriteGetObjectResponse` | S3 Object Lambda integration — proxy model incompatible |
| `ListObjects` / `ListObjectsV2` ETags | ETags in listings remain **backend (ciphertext) ETags**. Accurate plaintext ETag is available via `HeadObject` and `GetObject`, which decrypt metadata on a per-object basis. ETag correction in listings is tracked as a separate follow-up. |
| `ListObjects` / `ListObjectsV2` sizes | **Fixed in V1.0-S3-3.** Sizes are translated to plaintext via a Valkey-backed write-through size cache (`plainsize:<bucket>`), populated on `PutObject`/`CompleteMultipartUpload`/`CopyObject` and evicted on delete. Cache misses return ciphertext sizes (fail-soft); opt-in `list_size_translate.fallback_head_enabled` warms misses with a bounded HEAD batch. Objects uploaded before the feature was deployed are not auto-warmed. The earlier per-object HEAD translation was removed because it caused an N-fold latency explosion; the cache restores correctness without that cost. |

### Helper Infrastructure (V1.0-S3-2)

| Helper | File | Purpose |
|---|---|---|
| `copyProxyResponse` | `internal/api/utils.go` | Copies status code, filtered headers, and body from upstream response to client |
| `forwardToBackend` | `internal/api/utils.go` | Creates and sends a signed request to the configured S3 backend, returns the raw response |
| `handlePassthrough` | `internal/api/utils.go` | Generic proxy handler wrapper: forward → copy → metric → audit |

All handlers in tiers 1-3 use `handlePassthrough` as their implementation body, reducing each new handler to ~3 lines.

### Request/Response Processing Strategy

### Request Parsing
```go
type S3Request struct {
    Method      string
    Bucket      string
    Key         string
    QueryParams map[string]string
    Headers     map[string]string
    Body        io.Reader
    IsEncrypted bool // For GET requests
}
```

### Response Modification
```go
type S3Response struct {
    StatusCode  int
    Headers     map[string]string
    Body        io.Reader
    IsEncrypted bool
}
```

## Authentication and Authorization

### Strategy
- **Default mode**: Gateway uses its own configured backend credentials for all requests
- **Client credentials mode** (`use_client_credentials: true`): Gateway extracts credentials from client requests
  - **Supported**: Query parameter authentication (`?AWSAccessKeyId=...&AWSSecretAccessKey=...`)
  - **Presigned URLs**: Supported for `GET` and `PUT` operations.
    - The gateway validates the Presigned URL signature using the configured backend credentials.
    - This requires the client to sign requests using the *same* credentials that the gateway is configured to use for the backend.
    - **Constraint**: The gateway essentially validates the signature on behalf of the backend, as it cannot forward the signed request directly (host header mismatch invalidates signature).
  - **NOT supported**: AWS Signature V4 (Authorization header) - signature includes Host header which prevents forwarding
- **No additional auth**: Gateway trusts client authentication
- **Future enhancement**: Support for gateway-specific authentication

### Implementation
```go
// Default mode: Use configured backend credentials for S3 client
// Client credentials mode: Extract credentials from request query parameters
// Note: Signature V4 (Authorization header) is not supported in client credentials mode
backendClient := s3.New(session.Must(session.NewSession(&aws.Config{
    Credentials: credentials.NewStaticCredentials(accessKey, secretKey, ""),
})))
```

### Presigned URL Compatibility Caveats
1.  **Host Header Mismatch**: Presigned URLs generated by clients usually sign the `Host` header. When the gateway forwards this request to the real backend, the `Host` header changes, invalidating the signature.
    *   **Solution**: The gateway intercepts the Presigned URL request, validates the signature locally using its configured backend credentials, and then creates a *new* request to the backend using the gateway's backend credentials.
    *   **Requirement**: The client must use the same Access Key and Secret Key as the gateway's backend configuration. If the client uses different credentials, the gateway cannot validate the signature (unless it has access to those credentials, which it currently doesn't).
2.  **Path Style vs Virtual Host Style**: Clients should prefer Path Style addressing when generating presigned URLs for the gateway to avoid DNS resolution issues, though the gateway handles virtual host style if DNS is configured correctly.

## Header and Metadata Handling

### Preserved Headers
- `Content-Type`
- `Content-Length` (modified for encryption overhead)
- `ETag` (modified for encrypted content)
- `Last-Modified`
- `x-amz-meta-*` (user metadata)
- `x-amz-tagging` (validated: max 10 tags, key ≤128 chars, value ≤256 chars)
- `x-amz-version-id`

### Added Encryption Metadata
- `x-amz-meta-encrypted`: "true"
- `x-amz-meta-encryption-algorithm`: "AES256-GCM" or "ChaCha20-Poly1305"
- `x-amz-meta-encryption-key-salt`: base64-encoded salt
- `x-amz-meta-encryption-original-size`: original size (canonical key)
- `x-amz-meta-original-etag`: original ETag

### Encrypted Metadata (Opt-in)
When `metadata_encryption_key_file` or `metadata_encryption_key` is configured,
all gateway-generated encryption metadata is stored as a single encrypted blob:
- `x-amz-meta-enc-metadata`: Base64-encoded AES-256-GCM ciphertext (JSON payload)
- `x-amz-meta-encrypted`: still `"true"` (outside the blob, for `IsEncrypted`)
- User-supplied `x-amz-meta-*` headers: remain visible in S3

### Hidden Headers
- Never expose backend-specific headers
- Filter internal encryption metadata from client responses

## Object Tagging Support

### PUT Object Tagging
- **Endpoint**: `PUT /{bucket}/{key}?tagging`
- **Implementation**:
  - Validates tag format and limits before forwarding to backend
  - Tags are passed through unchanged to maintain compatibility

### GET Object Tagging
- **Endpoint**: `GET /{bucket}/{key}?tagging`
- **Implementation**:
  - Retrieves tags from backend and returns them unchanged

### Tag Validation (PUT Operations)
- **Maximum Tags**: 10 tags per object
- **Key Constraints**:
  - Length: 1-128 characters
  - Characters: alphanumeric, spaces, and symbols: `+ - = . _ : /`
  - Cannot be empty or contain only whitespace
- **Value Constraints**:
  - Length: 0-256 characters (empty values allowed)
  - Characters: alphanumeric, spaces, and symbols: `+ - = . _ : /`
- **Error Response**: InvalidArgument (400) with descriptive message for validation failures

## Encryption Metadata Format

### Storage Format
```json
{
  "encrypted": true,
  "algorithm": "AES256-GCM" | "ChaCha20-Poly1305",
  "key_salt": "base64-encoded-salt",
  "original_size": 12345,
  "original_etag": "original-etag-value",
  "iv": "base64-encoded-iv"
}
```

### Metadata Keys
- Use `x-amz-meta-` prefix for S3 compatibility
- Compress metadata if it exceeds header size limits
- Store in separate metadata object for large metadata

## Error Handling and Translation

### Backend Error Translation
```go
// Map backend errors to appropriate S3 errors
switch backendErr.Code {
case "NoSuchBucket":
    return s3error.NoSuchBucket
case "AccessDenied":
    return s3error.AccessDenied
case "InvalidObjectName":
    return s3error.KeyTooLongError
default:
    return s3error.InternalError
}
```

### Encryption Error Handling
- **Decryption failures**: Return 500 Internal Server Error
- **Key derivation errors**: Return 500 Internal Server Error
- **Corrupted data**: Return 500 Internal Server Error with specific message

### Client Error Responses
- **Invalid requests**: 400 Bad Request
- **Authentication failures**: 403 Forbidden
- **Not found**: 404 Not Found
- **Method not allowed**: 405 Method Not Allowed

## Streaming vs Buffered Operations

### Streaming Strategy
- **PUT operations**: Stream encryption to avoid memory pressure
- **GET operations**: Stream decryption for large objects
- **Memory limits**: Configure maximum buffer size
- **Fallback**: Buffer small objects, stream large ones

### Implementation
```go
type StreamProcessor interface {
    Process(reader io.Reader) io.Reader
}

func (e *EncryptionEngine) EncryptStream(reader io.Reader) io.Reader {
    return &encryptReader{source: reader, cipher: e.cipher}
}

func (e *EncryptionEngine) DecryptStream(reader io.Reader) io.Reader {
    return &decryptReader{source: reader, cipher: e.cipher}
}
```

## Multipart Upload Handling

### Strategy
- Encrypt each part individually
- Maintain part boundaries and sizes
- Store encryption metadata per part
- Reassemble with correct encryption order

### Metadata Storage
- Store part encryption metadata in separate object
- Use multipart upload ID as key for metadata
- Clean up metadata on completion/failure

## Edge Cases and Special Handling

### Range Requests
- **GET with Range header**: Optimized for chunked encryption format
- **Implementation**:
  - If object uses chunked encryption: compute encrypted byte range and fetch only needed chunks from backend; decrypt only those chunks, respond with 206 and correct Content-Range
  - If legacy (buffered) encryption or plaintext: forward client range to backend or decrypt fully then apply range
- **Performance impact**: Significantly reduced bandwidth and CPU for chunked format

### Object Versioning
- **Versioned objects**: Encrypt/decrypt specific versions
- **Version metadata**: Store encryption info per version
- **Delete markers**: Handle appropriately

### Object Locking (V0.6-S3-2)

Implemented as of v0.6. See `docs/adr/0008-object-lock-ciphertext-semantics.md`
for the full rationale. High-level contract:

- **Subresource endpoints routed and forwarded to backend**:
  - `PUT  /{bucket}/{key}?retention` — PutObjectRetention
  - `GET  /{bucket}/{key}?retention` — GetObjectRetention
  - `PUT  /{bucket}/{key}?legal-hold` — PutObjectLegalHold
  - `GET  /{bucket}/{key}?legal-hold` — GetObjectLegalHold
  - `PUT  /{bucket}?object-lock` — PutObjectLockConfiguration
  - `GET  /{bucket}?object-lock` — GetObjectLockConfiguration
- **Request headers forwarded end-to-end** on `PutObject`,
  `CopyObject`, and `CompleteMultipartUpload`:
  `x-amz-object-lock-mode`, `x-amz-object-lock-retain-until-date`,
  `x-amz-object-lock-legal-hold`. Invalid values produce `400
  InvalidArgument` at the gateway; zero silent drops.
- **Response headers surfaced** on `GET` and `HEAD` from
  `HeadObjectOutput` / `GetObjectOutput`.
- **`x-amz-bypass-governance-retention` is refused** with `403
  AccessDenied` on PutObjectRetention, DeleteObject, and
  DeleteObjects — pending V0.6-CFG-1's admin authorization.
  Operators needing to reduce a governance-mode retention must
  target the backend directly in v0.6.
- **Ciphertext-locking.** Retention/LegalHold apply to the
  ciphertext blob the backend stores. Key-rotation workers skip
  locked objects and emit `gateway_rotation_skipped_locked_total`.
  Operators must align KMS/KEK retention with the maximum Object
  Lock retention window in use.

#### Provider support matrix

| Provider | Retention | Legal Hold | Bucket Config | Notes |
|---|---|---|---|---|
| AWS S3 | yes | yes | yes | Reference implementation. |
| MinIO >= RELEASE.2021-01-30 | yes | yes | yes | Bucket must be created with `--with-lock`. |
| Ceph RGW >= Pacific | yes | yes | yes | Feature-flagged; operator must enable. |
| Wasabi (Immutable Storage) | yes | yes | yes | Underlying primitive is Wasabi Immutable Storage. |
| Backblaze B2 S3-compat | partial | partial | partial | 501 on the unsupported subset. |
| Hetzner Object Storage | partial | partial | partial | 501 on the unsupported subset. |
| DigitalOcean Spaces | no | no | no | Returns 501 NotImplemented. |
| Cloudflare R2 | no | no | no | Returns 501 NotImplemented. |
| Garage | no | no | no | Returns 501 NotImplemented. |

Unsupported providers return `501 NotImplemented`; the response
references this matrix.

### Compression (Removed in v1.0)

Built-in compression was removed in V1.0-MAINT-2. For client-side compression,
compose with s4 upstream.

## Testing Strategy

### API Compatibility Testing
- **AWS SDK tests**: Use official AWS SDK test suites
- **Third-party tools**: Test with rclone, s3cmd, MinIO client
- **S3 compatibility suites**: Use existing S3 compatibility test frameworks

### Encryption Testing
- **Round-trip tests**: Encrypt → Decrypt → Verify identical
- **Corruption tests**: Test behavior with corrupted encrypted data
- **Key rotation tests**: Test key change scenarios
- **Large file tests**: Test with objects > 5GB

### Performance Testing
- **Throughput**: Measure encryption/decryption speeds
- **Concurrent requests**: Test under load
- **Memory usage**: Monitor memory consumption
- **Latency**: Measure request latency impact

## Implementation Phases

### Phase 1: Basic Operations
- Implement PUT/GET for simple objects
- Basic encryption/decryption
- Single backend provider (AWS)

### Phase 2: Advanced Operations
- Multipart uploads
- Range requests
- Object versioning
- Multiple backend providers

### Phase 3: Production Hardening
- Error handling improvements
- Performance optimizations
- Comprehensive testing
- Monitoring and metrics

### Phase 4: Advanced Features
- Key rotation
- Compression integration
- Custom encryption algorithms
- Advanced S3 features support

---

## Inline Header Passthrough

The gateway forwards S3 standard inline headers transparently in most cases. The following tables document the exact disposition for PutObject and CreateMultipartUpload. Headers marked **Forwarded** reach the backend verbatim. Headers marked **Passed through verbatim** are forwarded with the re-signed request without being extracted into SDK struct fields.

### PutObject Inline Headers

| Header | Disposition | Mechanism | Notes |
|---|---|---|---|
| `x-amz-tagging` | **Forwarded** | Extracted, validated, passed to `PutObjectInput.Tagging` | |
| `x-amz-acl` | **Forwarded** | Extracted, mapped to `types.ObjectCannedACL`, passed to `PutObjectInput.ACL` | |
| `x-amz-grant-full-control` | **Forwarded** | Extracted, passed to `PutObjectInput.GrantFullControl` | |
| `x-amz-grant-read` | **Forwarded** | Extracted, passed to `PutObjectInput.GrantRead` | |
| `x-amz-grant-read-acp` | **Forwarded** | Extracted, passed to `PutObjectInput.GrantReadACP` | |
| `x-amz-grant-write-acp` | **Forwarded** | Extracted, passed to `PutObjectInput.GrantWriteACP` | |
| `x-amz-storage-class` | Passed through verbatim | Not extracted by gateway; forwarded on re-signed request | Provider quirk: MinIO ignores; AWS S3 respects |
| `x-amz-server-side-encryption` | Passed through verbatim | Not extracted; backend applies its own SSE layer | Gateway performs client-side encryption independently |
| `x-amz-object-lock-mode` | **Forwarded** | Extracted via `extractObjectLockInput`, passed to SDK | |
| `x-amz-object-lock-retain-until-date` | **Forwarded** | As above | |
| `x-amz-object-lock-legal-hold` | **Forwarded** | As above | |
| `x-amz-meta-*` | **Forwarded** | Extracted as user metadata map | All user-defined metadata headers forwarded |
| `Content-Type` | **Forwarded** | Standard header | |
| `Content-Encoding` | **Forwarded** | Standard header | |
| `Cache-Control` | **Forwarded** | Standard header | |

### CreateMultipartUpload Inline Headers

| Header | Disposition | Notes |
|---|---|---|
| `x-amz-acl` | **Forwarded** | Extracted, mapped to `CreateMultipartUploadInput.ACL` |
| `x-amz-grant-full-control` | **Forwarded** | Extracted, passed to SDK `GrantFullControl` |
| `x-amz-grant-read` | **Forwarded** | Extracted, passed to SDK `GrantRead` |
| `x-amz-grant-read-acp` | **Forwarded** | Extracted, passed to SDK `GrantReadACP` |
| `x-amz-grant-write-acp` | **Forwarded** | Extracted, passed to SDK `GrantWriteACP` |
| `x-amz-tagging` | **Not forwarded** | Tags must be set via `?tagging` subresource after CompleteMultipartUpload. **Known limitation.** |
| `x-amz-meta-*` | **Forwarded** | Extracted and passed to SDK |
| `x-amz-server-side-encryption` | Passed through verbatim | Not extracted by gateway |

### CopyObject ACL Note

On CopyObject, the destination ACL is set independently of the source. The gateway passes empty strings for all ACL headers on the destination PutObject call (re-encrypt path). Callers must set `x-amz-acl` explicitly on CopyObject if they want a non-default ACL. This is consistent with S3 semantics where CopyObject does not copy ACLs by default.

### Lifecycle Response Headers

When a backend applies a lifecycle rule to an object, the following response headers are forwarded verbatim by `copyProxyResponse`. Only 8 hop-by-hop headers are stripped; all `x-amz-*` headers survive.

| Header | Direction | Gateway Disposition |
|---|---|---|
| `x-amz-expiration` | Response | **Forwarded verbatim** |
| `x-amz-restore` | Response | **Forwarded verbatim** |
| `x-amz-delete-marker` | Response | **Forwarded verbatim** |

### Provider Quirks

| Feature | AWS S3 | MinIO (default) | Garage | Wasabi |
|---|---|---|---|---|
| `x-amz-acl` on PutObject | ✅ Full support | ⚠️ Default container requires IAM policy | ⚠️ Limited; `private` and `public-read` accepted | ✅ Full support |
| `x-amz-grant-*` on PutObject | ✅ Full support | ❌ Not supported in default container | ❌ | ✅ Full support |
| `x-amz-tagging` on PutObject | ✅ | ✅ | ✅ | ✅ |
| `?tagging` subresource | ✅ | ✅ | ✅ | ✅ |
| `?acl` subresource (bucket) | ✅ | ⚠️ Not in default cap bitmap | ⚠️ | ✅ |
| `?acl` subresource (object) | ✅ | ⚠️ Same | ⚠️ | ✅ |
| `?lifecycle` subresource | ✅ | ⚠️ Not in default cap bitmap | ✅ | ✅ |
| `x-amz-expiration` response | ✅ | Returned when lifecycle rule matches | ✅ | ✅ |
| `x-amz-storage-class` | ✅ | ⚠️ Ignored in most configs | ❌ | ✅ |
