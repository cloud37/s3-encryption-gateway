# S3 API Implementation Strategy

Bucket configuration PUT/DELETE subresources require scoped
`bucket_permissions: [manage]`; object `rw` and bucket `create`/`delete` grants
remain independent. Raw configuration payloads are limited to 1 MiB before
backend forwarding, while Object Lock retains its dedicated 100 KiB parser.

## Overview

The S3 Encryption Gateway implements common S3 operations while transparently encrypting and decrypting object data. It is not a complete replacement for every Amazon S3 feature. The application-facing matrix below describes released behavior; the later route and handler tables provide implementation detail.

## Application Compatibility Matrix

**Release baseline: v0.12.3 (released October 2, 2026). Status reviewed October 4, 2026.**
This is the canonical user-facing feature matrix. Work on an implementation branch
is not released support. For other versions, consult the [changelog](../CHANGELOG.md)
and [release notes](https://github.com/cloud37/s3-encryption-gateway/releases).

- **Supported**: implemented, subject to the requirements and caveats in Notes.
- **Not supported**: unavailable in this release, with the reason given below.
- **Planned**: unavailable in this release, with accepted work linked to its issue.
  This is not a release-date commitment.

All actual S3 operations require gateway credentials, bucket scope, and the relevant
permissions. The narrow credential-free browser preflight exception is described
below. **Backend-dependent passthrough** means the gateway forwards an authorized,
re-signed request; it does not implement a missing backend feature. Backend IAM
permissions remain required. See [authorization](#authentication-and-authorization),
[SDK / tool test coverage](SDK_COMPATIBILITY.md), and [deployment guidance](DEPLOYMENT.md).

For an explicit status for every action, see the [complete S3 operation inventory](S3_OPERATIONS.md).
For addressing, conditional requests, checksums, pagination, and field-level
limitations, see the [request/response compatibility contract](S3_COMPATIBILITY.md).

| Feature | Status | Notes / tracking |
|---|---|---|
| PutObject / GetObject / HeadObject / DeleteObject / DeleteObjects | Supported | Encryption follows the bucket policy. GET/HEAD project plaintext size and metadata; deleting encrypted MPU objects also cleans up their companion manifest. |
| Range GET | Supported | Returns plaintext byte ranges. Chunked formats fetch only the required encrypted chunks; legacy single-AEAD formats require a full read/decrypt. See [range requests](#range-requests). |
| CopyObject / UploadPartCopy | Supported | Encrypted copies are mediated through the gateway; source read and destination write permissions are checked independently. URL-encoded source identities are fixed in v0.12.3 ([GH-346](https://github.com/cloud37/s3-encryption-gateway/issues/346)). Legacy encrypted sources have a configurable memory cap. Request ACLs are not applied by re-encrypted CopyObject; use `?acl` afterward. See [copy-source handling](#copy-source-encoding-and-identity-gh-346). |
| Encrypted multipart upload (initiate, parts, complete, abort, list) | Supported | Requires configured Valkey-backed state and key management; encryption is enabled by default unless the bucket policy opts out. `UploadPart` defaults to a 64 MiB buffer cap (`SERVER_MAX_PART_BUFFER`). See [setup and limits](../README.md#encrypted-multipart-uploads). |
| Retry / replace an encrypted multipart part | Supported | Identical-content retries are supported. Concurrent reservations or different replacement content return `409 OperationAborted`; abort and create a new upload to change a claimed part. This also applies to UploadPartCopy. See [multipart handling](#multipart-upload-handling). |
| SigV4 header-signed requests | Supported | Authentication and scope checks apply before backend access. Header timestamps use the configured clock-skew window, default 5 minutes. |
| SigV4 presigned GET / PUT | Supported | Sign for the gateway endpoint using gateway credentials. Since v0.12.3, lifetime follows signed `X-Amz-Expires` (1–604800 seconds), not the header clock-skew window. Browser CORS remains a separate requirement. See [expiration rules](#sigv4-request-time-and-presigned-expiration). |
| Browser form upload (POST Object with policy) | Planned | Not implemented in v0.12.3; distinct from multipart upload. [GH-353](https://github.com/cloud37/s3-encryption-gateway/issues/353) tracks SigV4 policy validation, encrypted uploads, and success responses. Browser compatibility also depends on GH-322. |
| Browser CORS: preflight plus headers on gateway responses | Planned | v0.12.3 forwards genuine unauthenticated preflights to the backend, but encrypted handlers do not propagate backend CORS headers. Backend bucket CORS alone does not make these browser flows work. [GH-322](https://github.com/cloud37/s3-encryption-gateway/issues/322) tracks gateway-managed CORS; [GH-318](https://github.com/cloud37/s3-encryption-gateway/issues/318) explains the preflight-authentication fix and remaining response gap. |
| Bucket CORS / lifecycle / policy / versioning configuration APIs | Supported | Backend-dependent passthrough, not gateway-side policy evaluation. PUT/DELETE configuration requires `bucket_permissions: [manage]`, independently of object `rw`. The backend must implement the requested API. |
| ListBuckets / HeadBucket / GetBucketLocation | Supported | Backend-dependent. ListBuckets is filtered to the credential's effective bucket scope, including `PROXIED_BUCKET` when configured. |
| CreateBucket / DeleteBucket | Supported | Backend-dependent. CreateBucket requires `ALLOW_BUCKET_CREATION=true` and the explicit `create` grant; DeleteBucket requires `delete`. Object `rw` grants neither. See [bucket management](../README.md#authorized-bucket-management). |
| Object tagging / ACL APIs | Supported | Backend-dependent passthrough; providers differ. `x-amz-tagging` on CreateMultipartUpload is not forwarded: set tags using the object `?tagging` API after completion. See [inline headers](#inline-header-passthrough). |
| Version-specific object reads, deletes, and copy sources | Supported | Requires a versioning-capable backend. GET/HEAD/DELETE accept `versionId`; copy sources accept `?versionId=...`. This does not imply support for every S3 version-listing operation. |
| Object Lock / retention / legal hold | Supported | Backend-dependent explicit subresource APIs; retention protects ciphertext. Inline PUT/initiation lock fields are not persisted by the typed adapter. Governance bypass is refused with `403 AccessDenied`. Keep decryption keys for the retention period. See [Object Lock and provider support](#object-locking-v06-s3-2). |
| ListObjects / ListObjectsV2 sizes | Supported | Plaintext sizes use a configured Valkey write-through cache. Unresolved cache misses, disabled translation, or unavailable Valkey can leave ciphertext sizes. Optional `list_size_translate.fallback_head_enabled` resolves misses using extra backend reads; disabled by default. See [size-cache setup](../README.md#listobjects-plaintext-size-translation). |
| ListObjects / ListObjectsV2 ETags | Supported | Listings expose backend ETags, not plaintext MD5. GET/HEAD can restore a recorded original ETag for single-object encryption formats; MPU objects retain backend multipart ETags. Plaintext ETag translation in listings is not implemented and has no committed release date. |
| SigV2 authentication | Supported | Deprecated, disabled by default. Temporary migration opt-in: `AUTH_ALLOW_LEGACY_SIGNATURE_V2=true`. Prefer SigV4. |
| Per-upload storage-class / backend SSE headers on typed PutObject and CreateMultipartUpload | Not supported | These typed upload paths do not forward the request settings; backend-configured defaults still apply. Gateway encryption is independent of backend SSE. See [inline header handling](#inline-header-passthrough); no release date is committed for extending it. |
| Reverse-proxy deployment | Supported | TLS termination with plain HTTP to the gateway is supported; preserve the signed Host, path, query, and S3 headers. [GH-338](https://github.com/cloud37/s3-encryption-gateway/issues/338)'s outbound proxy-header signing fix shipped in v0.12.2. A known v0.12.3 exception remains when a proxy drops signed `Content-Length: 0` on bodiless requests (for example rust-s3 DELETE); [GH-356](https://github.com/cloud37/s3-encryption-gateway/issues/356) tracks an implemented but unreleased fix. See [proxy guidance](DEPLOYMENT.md#reverse-proxies-and-backend-load-balancers). |
| SelectObjectContent | Not supported | By design: backend SQL evaluation cannot operate on gateway-encrypted objects. Returns `501 NotImplemented`; no implementation is planned. |
| WriteGetObjectResponse (S3 Object Lambda) | Not supported | No route or integration; incompatible with the gateway's proxy model. No implementation is planned. |
| Virtual-host-style inbound addressing | Not supported | Use `https://gateway/bucket/key`; DNS alone does not add host-to-bucket routing. Backend addressing is independent. See [addressing](S3_COMPATIBILITY.md#addressing-and-authentication). |
| Conditional GET/HEAD/PUT/DELETE/completion | Not supported | Typed object paths do not enforce/map If-Match/If-None-Match and related conditions. Do not rely on atomic conditional-write semantics. See [option contract](S3_COMPATIBILITY.md). |
| Full listing / multipart pagination option parity | Not supported | ListObjectsV2 `start-after`/`fetch-owner`/`encoding-type` and ListParts pagination are ignored. ListParts emits `IsTruncated=false` for its backend page. Basic listing and token pagination remain supported; see [listing caveats](S3_COMPATIBILITY.md#listings-and-pagination). |
| ListObjectVersions / GetObjectAttributes and other specialized actions | Not supported | Version-specific reads and upload verification do not implement version inventory or plaintext checksum retrieval. See all supported/unsupported actions in the [operation inventory](S3_OPERATIONS.md). |

**Before migrating:** check the application's upload style, part sizes, listing
size/ETag assumptions, backend configuration APIs, and reverse-proxy behavior.
An SDK smoke-test pass is not a guarantee of every application workflow.

**Maintenance:** update this matrix when a feature or compatibility fix is released,
including its minimum version and remaining caveats. Keep accepted unreleased work
linked here without marking it supported; use the [roadmap](ROADMAP.md) for context,
not a second independent support matrix.

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

#### Multipart Upload (Create / UploadPart / Complete)
- **Endpoints**:
  - `POST /{bucket}/{key}?uploads` - Initiate multipart upload
  - `PUT /{bucket}/{key}?partNumber=X&uploadId=Y` - Upload part
  - `POST /{bucket}/{key}?uploadId=Y` - Complete multipart upload
- **Encryption**: Conditional per bucket policy. Encrypted MPUs use a per-upload
  DEK, chunked ciphertext, and a finalization manifest.
- **Implementation**:
  - Plaintext MPUs are forwarded unchanged; encrypted parts are claimed before encryption.
  - Preserve ordering and part ETags
  - Complete uploads by passing part list to backend
  - Identical encrypted retries return the stored ETag without rewriting the part.
- **Security Considerations**:
   - Encrypted MPU parts are encrypted by the gateway with a per-upload DEK and authenticated chunk framing before they are sent to the backend.
   - Each part is reserved by an authenticated content claim before encryption. Identical retries return the stored ETag without rewriting; changed content returns `409 OperationAborted`.
   - Complete validates the exact ordered selected part set against durable committed state and writes the corresponding manifest before backend completion.
   - Legacy records are accepted only for the abort migration path. New uploads always use the current state schema; legacy uploads must be aborted and recreated before writing parts or completing.
- **Security Features**:
  - Robust XML parsing with 10MB size limits to prevent DoS
  - Comprehensive validation of part numbers (1-10000 range)
  - ETag format validation with proper quoting requirements
  - Duplicate part number detection and rejection
  - Fuzz-tested XML parser for edge case handling
   - Provider interoperability testing framework

This is the S3 multipart API, not the HTML `multipart/form-data` POST Object
operation. Browser form policies are not implemented in v0.12.3; see
[GH-353](https://github.com/cloud37/s3-encryption-gateway/issues/353).

#### AbortMultipartUpload

- **Endpoint:** `DELETE /{bucket}/{key}?uploadId=...`
- **Permission:** object `rw`, scoped to the bucket.
- **Behavior:** aborts the backend upload and coordinates encrypted-state
  lifecycle/cleanup; returns 204 on success. Missing tracked uploads can return
  `NoSuchUpload`; lifecycle conflicts can return 409 `OperationAborted`.
- **Limitations:** respects the global multipart-disable gate; typed abort does
  not forward newer conditional/expected-owner/requester-pays options.

#### ListParts

- **Endpoint:** `GET /{bucket}/{key}?uploadId=...`
- **Permission:** object `ro` or `rw`, scoped to the bucket.
- **Behavior:** returns part numbers, backend ETags, timestamps, and sizes;
  stored positive plaintext sizes replace encrypted part sizes when available.
- **Limitations:** only one backend page is fetched. `max-parts` and
  `part-number-marker` are ignored, and the response emits `IsTruncated=false`
  and `MaxParts=1000`. This is not complete pagination support for large uploads.
  See the [option contract](S3_COMPATIBILITY.md#listings-and-pagination).

#### PUT Object (Multipart Copy / UploadPartCopy)
- **Endpoint**: `PUT /{bucket}/{key}?partNumber=X&uploadId=Y`, with the
  `x-amz-copy-source` request header
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
- **Encrypted MPU replacement contract**: encrypted destinations claim the
  first plaintext for each part number. An identical retry returns `200` and
  the stored ETag without destination encryption or mutation. A concurrent
  reservation or changed source returns `409 OperationAborted`; clients must
  abort and create a new upload. Legacy encrypted in-flight state is also
  abort-only and returns `409`.
- **Error Codes**:
  - `400 InvalidArgument`: Malformed x-amz-copy-source or x-amz-copy-source-range
  - `400 InvalidRequest`: Source object > 5 GiB with no range; or multipart uploads disabled
  - `404 NoSuchKey` / `404 NoSuchBucket`: Source not found
  - `416 InvalidRange`: Range start ≥ object size
  - `501 NotImplemented`: Proxy mode without mediation support
- **Security Considerations**:
   - Destination parts remain plaintext only for non-encrypted MPUs (per ADR
     0002); encrypted MPU destinations are re-encrypted after claim validation
  - Source-bucket read authorization is explicitly checked independent of destination write authorization
  - Cross-key-space (different source/destination buckets) is supported and tested
  - Config mismatch (plaintext source to encrypted-destination bucket) triggers hard refusal with audit event

#### PUT Object Copy
- **Endpoint**: `PUT /{bucket}/{key}`, with the `x-amz-copy-source` request header
- **Encryption**: Conditional based on source encryption status
- **Implementation**:
  - Check if source object is encrypted
  - Copy operation may require decryption then re-encryption

#### Copy-source encoding and identity (GH-346)

Both copy operations accept a URL-encoded `x-amz-copy-source` header in the
form `bucket/key` or `/bucket/key`, optionally followed by
`?versionId=<version>`. This is a **header**, not a destination URL parameter.

The gateway separates the raw version suffix before percent-decoding the path
exactly once with path semantics. A literal `+` stays `+`; `%20` becomes a
space; `%2F` inside a key becomes a slash. A key containing the literal text
`%2F` must be sent as `%252F`. Encoded `?`, `#`, and `?versionId=` remain key
data rather than selecting a query or fragment. Only the optional slash before
the bucket is removed; leading/repeated key slashes and dot segments are not
normalized. An opaque version ID is decoded separately, preserving literal
`+` and `/`; an empty version suffix retains the existing latest-version
behavior.

| Source key | Valid header value for bucket `b` |
|---|---|
| `dir/with space.txt` | `b/dir/with%20space.txt` |
| `dir/umlaut-ä.txt` | `b/dir/umlaut-%C3%A4.txt` |
| `dir/a+b&c.txt` | `b/dir/a%2Bb%26c.txt` |
| `dir/plain.txt` (PHP-style escaped slashes) | `/b/dir%2Fplain.txt` |
| `dir/literal%2F.txt` | `b/dir/literal%252F.txt` |
| `name?versionId=literal`, version `v+/=` | `b/name%3FversionId%3Dliteral?versionId=v%2B%2F%3D` |

Authorization and backend reads use the same decoded bucket/key identity.
The incoming signed header is never rewritten. Backend-native CopyObject and
UploadPartCopy construct a separate correctly encoded header from the decoded
identities; the AWS SDK for Go v2 does not escape `CopySource` automatically.

Malformed percent escapes in the path/version and empty bucket/key components
return `400 InvalidArgument` with `Invalid x-amz-copy-source header`, without
backend requests. After authentication and destination permission checks,
malformed syntax is distinct from a valid source outside the credential or
`PROXIED_BUCKET` scope, which returns `403 AccessDenied`. Existing authentication
and read-only/destination-denial precedence is retained.

See [operator compatibility guidance](DEPLOYMENT.md#url-encoded-copy-sources-gh-346)
and [regression commands](TESTING.md#copy-source-encoding-regressions-gh-346).

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
- **Endpoints**: Registered bucket-level operations (create, delete, policy, etc.)
- **Implementation**: Authorized passthrough to the backend; support depends on the backend. A registered route does not add a feature missing from the backend.

## S3 API Coverage Matrix (V1.0-S3-2)

### New Operations — Tier 1 (Critical)

| # | Method | Route | Operation | Handler | Handling |
|---|---|---|---|---|---|
| T1-01 | `DELETE` | `/{bucket}` | **DeleteBucket** | `handleDeleteBucket` | Guarded proxy (+audit) |
| T1-02 | `GET` | `/` | **ListBuckets** | `handleListBuckets` | Filtered to effective scope |
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
| T2-10 | `OPTIONS` | `/{bucket}\|/{bucket}/{key}` | **CORS Preflight** | `handleCORSPreflight` | Backend passthrough |
| T2-11 | `POST` | `/{bucket}/{key}?restore` | **RestoreObject** | `handleRestoreObject` | Proxy verbatim |
| T2-12 | `GET` | `/{bucket}?encryption` | **GetBucketEncryption** | `handleGetBucketEncryption` | Proxy verbatim |
| T2-13 | `PUT` | `/{bucket}?encryption` | **PutBucketEncryption** | `handlePutBucketEncryption` | Proxy verbatim |
| T2-14 | `DELETE` | `/{bucket}?encryption` | **DeleteBucketEncryption** | `handleDeleteBucketEncryption` | Proxy verbatim |

Browser CORS preflight requests are permitted to reach the `OPTIONS` handler
without gateway SigV4 credentials when they contain both `Origin` and
`Access-Control-Request-Method` and no gateway authentication material. This is
required because browsers do not send the credentials from a subsequent
presigned request on the preflight. The gateway still authenticates the actual
presigned `PUT`, and `proxied_bucket` remains enforced for unauthenticated
preflights. Incomplete or credentialed `OPTIONS` requests continue through the
normal authentication and authorization path.

This exception only lets the preflight reach the backend; it does not evaluate
CORS rules or add CORS headers to gateway-generated encrypted responses. Browser
uploads can therefore fail even after a successful backend preflight. See
[GH-322](https://github.com/cloud37/s3-encryption-gateway/issues/322).

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

### Known Limitations

The [application compatibility matrix](#application-compatibility-matrix) is the
authoritative overview of missing features, backend dependencies, listing-size
and ETag caveats, encrypted-part replacement rules, and known proxy issues. In
particular, a routed CORS preflight is not complete browser CORS support, and
cached plaintext listing sizes are not guaranteed for unresolved objects.

### Helper Infrastructure (V1.0-S3-2)

| Helper | File | Purpose |
|---|---|---|
| `copyProxyResponse` | `internal/api/utils.go` | Copies status code, filtered headers, and body from upstream response to client |
| `forwardToBackend` | `internal/api/utils.go` | Creates and sends a signed request to the configured S3 backend, returns the raw response |
| `handlePassthrough` | `internal/api/utils.go` | Generic proxy handler wrapper: forward → copy → metric → audit |

Most configuration handlers use `handlePassthrough` or its body-limited variant.
ListBuckets, bucket lifecycle, Object Lock, and explicitly unsupported operations
have additional handling; the tables describe routing, not blanket feature parity.

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
- **Per-credential gateway authentication**: Every inbound request must present a valid access key configured in `auth.credentials`. The gateway validates AWS Signature V4 (and V2) against the stored secret before any backend interaction.
- **Per-credential bucket scope**: Each credential can be restricted to exact bucket names and trailing-`*` prefixes. An omitted `buckets` list or explicit `[*]` means unrestricted; an explicit empty list `[]` denies all buckets. A bare `*` is broad authority and is appropriate only for trusted provisioning credentials.
- **Object permissions**: `ro` permits reads only; `rw` permits reads and mutations. Both default to `rw` when omitted.
- **Bucket permissions**: Explicit grants `create` and `delete` are required for CreateBucket and DeleteBucket. `rw` does not imply either.

CreateBucket is disabled by default and requires the global gate, credential
scope, and explicit create grant. Authorized requests preserve the raw
LocationConstraint body and backend response. DeleteBucket is independently
authorized by scope and explicit delete grant; backend IAM remains authoritative.
- **Global intersection**: If `PROXIED_BUCKET` is set, the effective scope is the credential's buckets intersected with the proxied bucket name.
- **Copy operations**: Both the source bucket and destination bucket must be within the credential's scope, and destination mutations require `rw`.
- **ListBuckets**: Responses are filtered to only buckets the credential is authorized to access.
- **Audit**: Every request generates an `auth.authorization_denied` event with a bounded reason (`bucket_scope`, `read_only`, `bucket_create`, `bucket_delete`, `unknown_operation`) when access is denied.

### Implementation
Credentials are stored in an atomic snapshot compiled from `config.yaml`, environment variables, or an external credentials file. Changes to the main configuration file or `AUTH_CREDENTIALS_FILE` trigger a reload that validates the complete configuration before atomically replacing the snapshot. Credentials supplied through process environment variables, including Helm-rendered values, require a process restart when changed.

### Presigned URL Compatibility Caveats
1.  **Host Header Mismatch**: Presigned URLs generated by clients usually sign the `Host` header. When the gateway forwards this request to the real backend, the `Host` header changes, invalidating the signature.
    *   **Solution**: The gateway intercepts the Presigned URL request, validates the signature locally using the gateway's configured credentials, and then creates a *new* request to the backend using the gateway's backend credentials.
    *   **Requirement**: The client must use credentials that are configured in `auth.credentials`. The gateway validates the signature against the principal's secret before any backend interaction.
2.  **Path Style vs Virtual Host Style**: Use inbound path-style URLs (`https://gateway/bucket/key`). The gateway extracts bucket/key from the path and does not implement host-to-bucket routing; DNS alone does not enable virtual-host addressing. Backend path/virtual-host settings are independent. See [addressing compatibility](S3_COMPATIBILITY.md#addressing-and-authentication).

### SigV4 Request Time and Presigned Expiration

Header-signed requests and presigned URLs have different validity windows:

- **Header authentication:** the absolute difference between the signing
  timestamp and server time must not exceed `auth.clock_skew_tolerance`
  (`AUTH_CLOCK_SKEW_TOLERANCE`, default `5m`). The header-auth replay window is
  unchanged by the GH-345 fix.
- **Presigned authentication:** `X-Amz-Date` may not be more than the configured
  skew tolerance in the future. Past signature age is bounded by
  `X-Amz-Date + X-Amz-Expires`, not by the clock-skew window. The tolerance does
  not extend this deadline; requests strictly after it are expired. Expiration
  is checked when authentication begins;
  an accepted download is not interrupted merely because its deadline passes.
- **Required expiry:** `X-Amz-Expires` must occur exactly once and contain a
  decimal integer from `1` through `604800` seconds (seven days), inclusive.
  Empty, signed, fractional, negative, duplicate, and overflowing values are
  invalid. Bounds are checked before duration conversion.
- **Authentication still applies:** the credential must remain configured and
  permitted for the operation. The scope date must match the signing
  timestamp's UTC date, not the current server date. Crossing midnight does
  not invalidate a URL. Changing the URL's expiry without re-signing fails
  signature verification; the expiry check follows HMAC verification.

The gateway returns fixed S3 XML messages without signatures or internal
diagnostic details:

| Failure | HTTP status | S3 code | Message |
| --- | --- | --- | --- |
| Authenticated presigned URL past its deadline | 403 | `AccessDenied` | `Request has expired.` |
| Header timestamp outside the skew window, or presigned timestamp too far in the future | 403 | `RequestTimeTooSkewed` | `The difference between the request time and the server's time is too large.` |
| Authenticated presigned request with invalid/missing expiry | 400 | `InvalidArgument` | `X-Amz-Expires must be a single integer between 1 and 604800 seconds.` |
| Incorrect HMAC signature | 403 | `SignatureDoesNotMatch` | Existing fixed signature-mismatch message |

All rejected requests stop before backend interaction. Other malformed
authentication errors retain the existing opaque response. Legacy SigV2 timing
and its opt-in policy are unchanged. See the AWS references for
[presigned parameters](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html)
and [S3 error codes](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html).

## Header and Metadata Handling

The canonical encrypted-object metadata inventory, field ownership, and
response precedence rules are documented in
[`docs/METADATA_MODEL.md`](METADATA_MODEL.md).

The shared response projector restores the six standard fields
(`Content-Type`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`,
`Content-Language`, and `Expires`) across HEAD, full/ranged GET, MPU, and cache
responses. It filters all registered reserved metadata; authenticated GET
`response-*` overrides precede encrypted protected metadata; backend version
IDs precede the requested `versionId` fallback. The Tier 2 matrix asserts PUT,
COPY, COPY REPLACE, encrypted MPU, and UploadPartCopy in chunked/non-chunked
self-contained configurations, along with real cache hit and ETag-mismatch
refresh behavior. See `docs/TESTING.md` for fixtures and the full validation
matrix.

For response ETags, encrypted single-object formats restore the quoted original
ETag when recorded; MPU responses retain the backend multipart ETag and
plaintext objects retain their backend ETag. ListObjects continues to expose
backend ETags as documented separately below.

### Preserved Headers
- `Content-Type`
- `Content-Length` (modified for encryption overhead)
- `ETag` (modified for encrypted content)
- `Last-Modified`
- `x-amz-meta-*` (user metadata)
- `x-amz-tagging` (validated: max 10 tags, key ≤128 chars, value ≤256 chars)
- `x-amz-version-id`

This is not a promise to preserve every backend header on every operation.
Typed write/delete handlers do not consistently expose backend destination
version/delete-marker headers, and typed object reads use a fixed projector.
See [field-level response compatibility](S3_COMPATIBILITY.md#object-reads-and-responses).

### Passthrough Request Header Contract

`forwardToBackend` is an S3 forwarding boundary, not a generic HTTP proxy.
Before backend SigV4 signing it builds an independent header set containing:

- `x-amz-*` operation headers (including metadata, checksums, ACLs,
  expected-owner, requester-pays, and MFA), except client authentication fields.
- `Content-Type`, `Content-MD5`, `Cache-Control`, `Content-Disposition`,
  `Content-Encoding`, `Content-Language`, and `Expires`.
- `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`,
  `If-Range`, and `Range`.
- CORS inputs: `Origin`, `Access-Control-Request-Method`, and
  `Access-Control-Request-Headers`.

Client `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`, and
`X-Amz-Security-Token` are not copied. Existing SigV2/SigV4 query authentication
is removed without rewriting the remaining raw S3 subresource selectors.
The gateway supplies the backend host, derives Content-Length from the buffered
body, and generates its own authentication fields when backend credentials are
configured. The same filtering applies to unsigned backend requests.

Everything else is excluded, including `X-Forwarded-*`, `Forwarded`, `Via`,
`X-Real-IP`, cookies, client request IDs, and tracing headers. Fixed hop-by-hop
fields and every field nominated by any `Connection` value are removed
case-insensitively, even if an otherwise allowed S3 header is nominated.
Filtering does not mutate inbound headers used for gateway auditing and
trusted-proxy IP extraction. An HTTP transport may add its own unsigned
transport headers; these are not copied client identity.

The policy covers both the generic passthrough wrapper and the direct
ListBuckets forwarding call. Proxy responses retain end-to-end S3/CORS headers
but strip fixed and `Connection`-nominated hop-by-hop fields, including `Trailer`.
See [reverse-proxy deployment](DEPLOYMENT.md#reverse-proxies-and-backend-load-balancers)
and [GH-338 testing](TESTING.md#reverse-proxy-header-regressions-gh-338).

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

`internal/api/errors.go:TranslateError` maps wrapped S3 SDK error codes to
fixed client-facing messages. Backend diagnostics remain in structured logs,
not in response messages.

| Backend S3 code | Client S3 code | HTTP status |
|---|---|---|
| `NoSuchBucket` | `NoSuchBucket` | 404 |
| `NoSuchKey`, `NotFound` | `NoSuchKey` | 404 |
| `AccessDenied` | `AccessDenied` | 403 |
| `InvalidBucketName`, `InvalidArgument` | Same code | 400 |
| `SlowDown` | `SlowDown` | 503 |
| `ServiceUnavailable` | `ServiceUnavailable` | 503 |
| Unrecognized errors, including unclassified transport timeouts | `InternalError` | 500 |

**Object-read preflight (GH-344):** Chunked-v2 terminal acquisition and
planning HEAD calls retain explicit storage-error provenance through the
shared planner and plaintext-size resolver. Full/ranged GET, cache validation,
HEAD, CopyObject, and UploadPartCopy translate these failures as backend
errors, without failed-decrypt or tamper accounting. HEAD error responses have
no body. Copy preflight errors identify the source resource and are returned
before destination writes. A successful initial GET followed by terminal
`NoSuchKey` therefore returns 404, even on a backend with inconsistent
read-after-delete behavior; a cached body must not bypass failed validation.

Storage provenance is not inferred from an SDK error interface: a key-manager
SDK failure remains a crypto failure. A missing gateway-owned MPU companion
manifest remains `ErrMissingMPUManifest`, not a claim that the parent object is
missing; its established GET/copy diagnostic and HEAD/list fail-soft policy
are retained. Other marked companion storage failures use backend translation.

This classification does not eliminate separate backend reads or provide
snapshot consistency. The full ciphertext stream still authenticates its
records and terminal independently. Errors while consuming an already-open
crypto stream retain the existing stream-integrity policy.

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

Encrypted multipart uploads use immutable first-content claims for each part
number. A byte-identical retry returns the committed ETag without rewriting the
backend part. A different replacement is rejected with `OperationAborted`
(HTTP 409); clients must abort the upload and create a new one. `Complete`
requires strictly ascending selected parts with committed, matching ETags and
returns `InvalidPart` or `InvalidPartOrder` before manifest/backend I/O when
validation fails. `UploadPartCopy` applies the same rules after source
plaintext acquisition and before destination encryption or mutation.

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

GET/HEAD/DELETE map `versionId` to backend inputs, and copy-source headers can
select a version. Backend versioning support is required. ListObjectVersions is
not implemented, and write/delete-marker response fields are not fully projected.
Historical encrypted-MPU recovery requires matching companion manifests and keys;
the key-based manifest pointer is not a certified parent-version-to-manifest-version
history contract. See [recovery caveats](S3_COMPATIBILITY.md#backend-managed-features-and-recovery).

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
- **Inline lock headers:** PutObject validates mode/date/hold values, but the
  production typed PutObject adapter does not map them into backend input.
  CreateMultipartUpload does not capture initiation lock fields. Re-encrypted
  CopyObject has the same PutObject limitation; native backend copy maps lock
  input. Completion applies requested retention/hold through separate calls
  after completion, not atomically. Use backend defaults or explicit lock APIs
  and verify actual retention; an accepted inline request is not proof of a lock.
- **Response headers surfaced** on `GET` and `HEAD` from
  `HeadObjectOutput` / `GetObjectOutput`.
- **`x-amz-bypass-governance-retention` is refused** with `403
  AccessDenied` on PutObjectRetention, DeleteObject, and
  DeleteObjects — pending V0.6-CFG-1's admin authorization.
  Operators needing to reduce a governance-mode retention must
  use an independently authorized backend workflow; no gateway bypass is enabled
  in v0.12.3.
- **Ciphertext-locking.** Retention/LegalHold apply to the
  ciphertext blob the backend stores. Key-rotation workers skip
  locked objects and emit `gateway_rotation_skipped_locked_total`.
  Operators must align KMS/KEK retention with the maximum Object
  Lock retention window in use.

#### Provider support matrix

Backend product support, bucket setup, and gateway test coverage are different
questions. The current [backend test-selection matrix](SDK_COMPATIBILITY.md#backend-and-encryption-mode-coverage)
records the released fixtures: Object Lock scenarios are selected for external
AWS but not the four local fixture bitmaps. This is not a blanket claim that
those products lack Object Lock. Consult the provider's current documentation,
create a lock-enabled bucket where required, and verify explicit API persistence.
Provider rejections are translated/forwarded according to the code path; there is
no universal provider-name check that guarantees 501 for unsupported Object Lock.

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

The following tables describe the typed SDK PutObject and CreateMultipartUpload
paths in v0.12.3. Headers marked **Forwarded** are mapped to the corresponding
backend input. These paths do not clone arbitrary inbound headers; do not infer
their behavior from the generic [passthrough header contract](#passthrough-request-header-contract).

### PutObject Inline Headers

| Header | Disposition | Mechanism | Notes |
|---|---|---|---|
| `x-amz-tagging` | **Forwarded** | Extracted, validated, passed to `PutObjectInput.Tagging` | |
| `x-amz-acl` | **Forwarded** | Extracted, mapped to `types.ObjectCannedACL`, passed to `PutObjectInput.ACL` | |
| `x-amz-grant-full-control` | **Forwarded** | Extracted, passed to `PutObjectInput.GrantFullControl` | |
| `x-amz-grant-read` | **Forwarded** | Extracted, passed to `PutObjectInput.GrantRead` | |
| `x-amz-grant-read-acp` | **Forwarded** | Extracted, passed to `PutObjectInput.GrantReadACP` | |
| `x-amz-grant-write-acp` | **Forwarded** | Extracted, passed to `PutObjectInput.GrantWriteACP` | |
| `x-amz-storage-class` | **Not forwarded** | Not mapped to the typed PutObject input | Backend defaults apply; generic passthrough behavior is different |
| `x-amz-server-side-encryption` | **Not forwarded** | Not mapped to the typed PutObject input | Backend-configured default SSE is independent of gateway encryption |
| `x-amz-object-lock-mode` | **Not persisted by typed adapter** | Parsed/validated by handler, but not assigned to backend PutObject input | Use explicit lock APIs or backend defaults |
| `x-amz-object-lock-retain-until-date` | **Not persisted by typed adapter** | As above | Accepted input is not proof of retention |
| `x-amz-object-lock-legal-hold` | **Not persisted by typed adapter** | As above | Verify backend state explicitly |
| `x-amz-meta-*` | **Forwarded** | Extracted as user metadata map | Gateway-reserved metadata names are rejected; backend metadata filters still apply |
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
| `x-amz-server-side-encryption` | **Not forwarded** | Not mapped to the typed CreateMultipartUpload input; backend defaults apply |
| `x-amz-storage-class` | **Not forwarded** | Not mapped to the typed CreateMultipartUpload input |
| `x-amz-object-lock-*` | **Not captured at initiation** | Use backend defaults or explicit post-completion lock APIs; these are not atomic initiation guarantees |

### CopyObject ACL Note

On CopyObject, the destination ACL is not copied from the source. The re-encrypt
path passes empty ACL/grant values to its destination PutObject call, so supplying
`x-amz-acl` on that copy request does not set the destination ACL. Use the object
`?acl` API afterward when the backend supports it.

### Lifecycle Response Headers

The following headers are retained on generic passthrough responses by
`copyProxyResponse`, unless nominated by `Connection`. Fixed and
`Connection`-nominated hop-by-hop fields are stripped. This does not promise these
headers on typed GET/HEAD or gateway-generated encrypted responses.

| Header | Direction | Gateway Disposition |
|---|---|---|
| `x-amz-expiration` | Response | **Forwarded verbatim** |
| `x-amz-restore` | Response | **Forwarded verbatim** |
| `x-amz-delete-marker` | Response | **Forwarded verbatim** |

### Provider Quirks

Use the [backend test-selection matrix](SDK_COMPATIBILITY.md#backend-and-encryption-mode-coverage)
for current fixture coverage and the [option contract](S3_COMPATIBILITY.md) for
gateway mappings. For example, Garage's released fixture does not select object
tagging/versioning tests, while MinIO selects bucket lifecycle/policy tests but
not bucket/object ACL or CORS capabilities. A skipped test is not evidence of
product-wide non-support; a backend supporting storage-class/SSE/conditional
fields does not make the gateway's typed adapter forward them.
