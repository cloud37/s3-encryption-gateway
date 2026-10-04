# S3 Request and Response Compatibility

**Release baseline: v0.12.3. Reviewed October 4, 2026.**

This is the option-level companion to the [application matrix](S3_API_IMPLEMENTATION.md#application-compatibility-matrix)
and [complete operation inventory](S3_OPERATIONS.md). It describes production
request parsing and SDK mappings, not idealized AWS behavior. A supported base
operation does not imply every SDK input/output field is implemented. Unless
noted otherwise, limitations below have no committed implementation date.

## Addressing and Authentication

| Request mode | v0.12.3 behavior |
|---|---|
| Path-style `https://gateway/bucket/key` | Supported inbound addressing; bucket and key are taken from the path. Configure clients with path-style addressing. |
| Virtual-host-style `https://bucket.gateway/key` | Not implemented as inbound host-to-bucket routing. DNS alone cannot make it work; `/key` can be interpreted as a bucket path. Do not rewrite a signed path/Host in a proxy to compensate. |
| Backend path/virtual-host style | Independently controlled by backend settings. It does not enable inbound virtual-host bucket extraction. |
| Access-point/Outposts/Object Lambda ARNs, S3 Express zonal endpoints, directory buckets | No gateway endpoint/ARN/session routing contract. Ordinary bucket-name scopes and path routes do not implement these modes. |
| SigV4 header authentication | Gateway-configured access key/secret; default 5-minute clock-skew window. Signed body integrity is separate from operation-option mapping. |
| SigV4 presigned GET/PUT | Sign the gateway Host/path/query with gateway credentials. `X-Amz-Expires` must be a single 1–604800 second integer; deadline honored since v0.12.3. Permission changes still apply. |
| SigV2 | Deprecated, disabled by default; explicit `AUTH_ALLOW_LEGACY_SIGNATURE_V2=true` migration opt-in. |
| STS issuance / S3 Express CreateSession / configured session-token validation | Not implemented by this endpoint. Gateway credential records contain access key/secret/scope, not a token/expiry authority. A token appearing in a signed request is not certification of session-credential semantics. |
| Anonymous object or website reads | Not supported. Public backend ACL/policy does not bypass gateway authentication. Qualifying credential-free OPTIONS and system health endpoints are narrow exceptions. |
| Browser POST Object | Planned [GH-353](https://github.com/cloud37/s3-encryption-gateway/issues/353), not the existing multipart API. |

Preserve signed Host, path, query, and headers through frontend proxies. GH-338
outbound proxy-header filtering shipped in v0.12.2. The signed zero Content-Length
problem remains in v0.12.3; [GH-356](https://github.com/cloud37/s3-encryption-gateway/issues/356)
tracks an unreleased fix. See [deployment](DEPLOYMENT.md#reverse-proxies-and-backend-load-balancers).

## Object Reads and Responses

| Option / field | v0.12.3 behavior |
|---|---|
| GET/HEAD `versionId` | Mapped to typed backend reads. Versioning-capable backend required; no ListObjectVersions API. |
| GET `Range: bytes=start-end`, open-ended, suffix | Single plaintext byte range; 206 with projected Content-Range/length. Encrypted chunked/MPU paths translate to ciphertext ranges; legacy formats require full decrypt. Multiple comma-separated ranges are not implemented. |
| HEAD Range / GET or HEAD `partNumber` | Not mapped to typed SDK inputs or response planning. A query accepted by authorization is not part-selection support. |
| `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, `If-Range` | Not evaluated or mapped on typed GET/HEAD paths. Do not depend on conditional 304/412 or If-Range fallback semantics. Generic passthrough keeps these headers only for its own routed operations. |
| Six GET `response-*` overrides | Content type/language/encoding/disposition, cache control, and expires override projected values on authenticated GET, including ranges/cache. HEAD does not apply overrides. |
| `x-amz-checksum-mode`, checksum response fields, GetObjectAttributes | No durable plaintext checksum projection. Typed GET/HEAD do not request/map checksum mode; GetObjectAttributes is not implemented. Upload verification does not imply checksum retrieval. |
| ETag | GET/HEAD restore a recorded original ETag for encrypted single-object formats when available. Otherwise backend ETag; MPU retains multipart ETag. PUT and listings return backend ETags. Not a universal plaintext-MD5 contract. |
| Standard/user metadata | Six standard headers and non-reserved user metadata projected through the shared model. Reserved markers/aliases/blobs hidden. See [metadata model](METADATA_MODEL.md). |
| Backend version response | GET/HEAD prefer returned backend version, then requested version fallback. Typed write/delete handlers do not consistently project destination version/delete-marker response headers. |
| Other backend response headers | Not generic passthrough: only fields owned by the shared response projector survive typed object reads. Do not assume expiration, restore, delete-marker, SSE, checksum, or CORS headers survive. |
| Missing MPU manifest | Full/ranged GET and copy fail closed; HEAD/listing size resolution can retain ciphertext size under the documented advisory exception. |
| Cache | Optional plaintext body cache revalidates backend metadata and projects headers/GET overrides. Cache hits do not add conditional-request or checksum semantics. Version-specific reads are not the ordinary latest-object cache path. |

Evidence: [`object_stream.go`](../internal/api/object_stream.go),
[`object_response.go`](../internal/api/object_response.go),
[`handlers.go`](../internal/api/handlers.go), and
[`client.go`](../internal/s3/client.go). Existing range, metadata, cache, and
backend-error scenarios are linked in the [inventory evidence index](S3_OPERATIONS.md#evidence-index).

## Listings and Pagination

| Operation / option | v0.12.3 behavior |
|---|---|
| ListObjects v1 / v2 | One gateway handler uses backend ListObjectsV2 and reconstructs XML. Prefix, delimiter, positive max-keys, and continuation-token are passed to the typed backend. |
| v1 `marker` | Mapped to backend StartAfter; NextMarker is derived from the last returned object. |
| v2 `start-after` | Accepted by query authorization but ignored by the handler; it reads `marker`, not `start-after`. Use continuation-token pagination, not this option. |
| `encoding-type`, `fetch-owner` | Accepted but not forwarded/applied. Keys use ordinary XML escaping, not requested URL encoding; owner output is not included. |
| v2 XML fields | Subset: Name/Prefix/Delimiter/MaxKeys/IsTruncated/NextContinuationToken/Contents/CommonPrefixes, plus v1 NextMarker when derived. KeyCount, echoed continuation/start-after fields, owner, and EncodingType are not fully reproduced. |
| `max-keys=0`, invalid/negative max-keys | No strict AWS validation/zero-page contract. The adapter sets MaxKeys only when positive. Do not rely on a standards-compliant zero/invalid-value response. |
| Listing StorageClass | Reconstructed as `STANDARD`, not the backend's actual storage class. |
| Listing size / ETag | Configured Valkey cache and optional bounded HEAD fallback can resolve plaintext sizes; unresolved objects can retain ciphertext sizes. ETags remain backend-defined. Bypass buckets use native sizes. |
| Companion keys | Keys ending in `.mpu-manifest` are filtered as gateway-owned; this suffix is not a safe ordinary application-object namespace. Backend listing counts/pages can differ after filtering. |
| ListParts pagination | `max-parts` and `part-number-marker` are accepted but ignored. Adapter fetches one backend page and discards truncation/marker fields; gateway emits MaxParts=1000, PartNumberMarker=0, IsTruncated=false. Large uploads can therefore return an incomplete part inventory without truncation signaling. |
| ListParts sizes | Stored per-part plaintext sizes are substituted when available and positive; otherwise backend part size remains. Part ETags are backend values. |
| ListMultipartUploads | Proxy preserves allowed `prefix`, `delimiter`, `encoding-type`, `key-marker`, `upload-id-marker`, `max-uploads`; provider handles pagination. It lists backend uploads, not a complete gateway-admin state inventory. |
| ListBuckets new query options | `prefix`, `bucket-region`, `max-buckets`, and `continuation-token` are rejected by current root authorization. Success XML projects Owner and bucket Name/CreationDate, not complete pagination/region fields. |
| Analytics / inventory configuration lists | Shared GET proxy without `id` can return the backend's first page. Adding `continuation-token` is rejected; no independently verified pagination workflow. |
| ListObjectVersions | Not implemented; enabling bucket versioning does not add version/delete-marker inventory. |

See [`authorization.go`](../internal/api/authorization.go), ListObjects/ListParts/
ListBuckets handlers, `generateListObjectsXML`, and the typed backend ListOptions/
ListParts mappings. Small pagination tests do not certify every accepted query key.

## Writes, Copies, and Multipart Options

| Option / path | v0.12.3 behavior |
|---|---|
| PUT standard/user metadata | Six standard fields preserved; gateway-reserved metadata names rejected. Backend filter configuration can remove metadata. |
| PUT `If-Match` / `If-None-Match`; conditional DELETE / completion | Not mapped or enforced on typed paths. Do not use the gateway as an atomic compare-and-swap/write-if-absent boundary. Backend capability flags do not change this mapping. |
| PutObject ACL/grant fields | Parsed and mapped; backend ACL capability/permissions required. Subresource PutObjectAcl/GetObjectAcl are separate proxy routes. |
| PutObject inline tagging | Parsed, validated, mapped; gateway validation restricts count/length/characters. Tag XML subresources are proxied for backend validation. |
| CreateMultipartUpload metadata / ACL | Standard/user metadata and ACL/grant fields mapped; destination metadata is frozen at initiation. Inline tagging is not forwarded: apply `?tagging` after completion. |
| Storage class / SSE-S3 / SSE-KMS / SSE-C / DSSE request settings | Not mapped on typed PutObject/CreateMultipartUpload/copy/part paths. Backend default encryption/storage settings can apply independently. PutBucketEncryption proxy support does not imply per-request SSE header support. |
| Expected owner / requester pays / MFA fields | Generic passthrough preserves allowed `x-amz-*` headers, but typed object/MPU methods do not generally map these fields. Do not assume requester-pays or MFA-delete compatibility. |
| Content-MD5 / non-streaming checksum headers | Not a general inbound checksum-validation/persistence contract. Typed backend adapters compute their own Content-MD5 for seekable outgoing bytes; those may be ciphertext. Use the explicitly verified SigV4 body modes below for inbound integrity. |
| Copy source header / version / range | Source identity decoded exactly once; optional source `versionId` supported. UploadPartCopy range is plaintext and translated for encrypted source formats. Do not backend-copy location-bound ciphertext to another key/bucket. |
| Copy source conditional headers | `x-amz-copy-source-if-*` are not mapped by typed source reads/native part-copy inputs. No source-condition guarantee. |
| Copy metadata directive | Omitted/COPY inherits source plaintext metadata and ignores request metadata; REPLACE uses request metadata. Invalid directive rejected. |
| Copy ACL / tagging directive | Re-encrypt path does not apply request ACL/grants; use `?acl` afterward. `x-amz-tagging-directive` is not implemented; request tags are not full source-tag COPY/REPLACE parity. |
| Encrypted part replacement | First-content claim immutable; identical retries supported, changed content/concurrent reservation returns 409 OperationAborted. Abort/new upload required to replace content, including UploadPartCopy. |
| Completion XML | PartNumber/ETag validated, selected encrypted part set checked. Additional per-part checksum XML fields are not carried into backend completion inputs. |
| Object Lock inline PUT/initiation | PutObject parses lock headers, but the production typed PutObject adapter does not map them into SDK input. CreateMultipartUpload does not capture/initiate lock fields. Do not rely on these headers to establish retention; use backend defaults or explicit supported lock APIs. |
| Lock at completion / copy | Completion applies requested retention/hold through separate backend calls after completion, not atomically with it. Native CopyObject maps lock input; re-encrypted copy uses the typed PutObject limitation. |
| Governance bypass | Truthy `x-amz-bypass-governance-retention` refused with 403 on retention/delete paths; no admin override is enabled on the S3 data plane. |
| DeleteObject/HeadBucket response details | DELETE returns 204 without backend version/delete-marker headers. HeadBucket probes via backend ListObjects rather than forwarding the full AWS HeadBucket response-header contract. |
| DeleteObjects XML | Key and VersionId mapped; per-key successes/errors returned. Quiet is ignored; conditional ETag/size/time delete fields and complete delete-marker-version response fields are not mapped. |

These are documentation findings, not runtime fixes. The production typed SDK
adapter in [`client.go`](../internal/s3/client.go) determines whether a parsed
handler field actually reaches storage. A test's name or backend capability bit
is not proof that a request field reaches storage.

## Body Integrity and Resource Limits

Header-signed concrete lowercase SHA-256 `X-Amz-Content-Sha256` requests are
verified/spooled before dispatch. `UNSIGNED-PAYLOAD` is supported but declines that
body-integrity preflight. Exact AWS-chunked modes are:

- `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
- `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`
- `STREAMING-UNSIGNED-PAYLOAD-TRAILER`

Signed chunks/terminal signatures and declared trailer checksums are verified
before storage. Supported checksum trailers: CRC64NVME, CRC32, CRC32C, SHA-1,
SHA-256. Unknown/ambiguous framing fails closed. See [security contract](../SECURITY.md)
and [SDK streaming coverage](SDK_COMPATIBILITY.md#streaming-upload-compatibility).
This does not implement GetObjectAttributes or stored plaintext checksum retrieval.

| Limit | Default / behavior |
|---|---|
| UploadPart buffer | 64 MiB, configurable `SERVER_MAX_PART_BUFFER`; both encrypted and plaintext paths. Oversize rejected before backend write. |
| Verified-body spool | 5 GiB per request and 10 GiB aggregate process budget; configurable `SERVER_MAX_VERIFIED_SPOOL_BYTES` / `SERVER_MAX_AGGREGATE_SPOOL_BYTES`. Part requests also obey their operation cap. Excess request 413 EntityTooLarge; aggregate pressure 503 SlowDown. |
| Legacy encrypted copy source | 256 MiB configurable `SERVER_MAX_LEGACY_COPY_SOURCE_BYTES`; full decrypt required. General encrypted copy can also buffer ciphertext—support is not a zero-copy guarantee. |
| CreateBucket body | 64 KiB. |
| Configuration PUT/DELETE body | 1 MiB on body-limited proxy routes. Object Lock parser: 100 KiB. |
| CompleteMultipartUpload XML | 10 MiB parser bound and part-number/ETag/order validation; not a substitute for the S3 provider's own object/part limits. |

Do not interpret a spool bound as proof that every upload mode or provider accepts
objects up to that size. Frontend limits, disk budget, encryption overhead, backend
limits, and multipart part sizes remain relevant.

## Backend-Managed Features and Recovery

Configuration passthrough is not gateway emulation. Backend lifecycle/replication/
inventory/logging/notifications operate on ciphertext and gateway internal writes.
They do not automatically preserve companion manifests, translated sizes, or
decryption-key availability. Replication into a different gateway bucket/key can
conflict with authenticated location binding; use gateway copy or a documented
GET-through-gateway → PUT-through-gateway migration instead.

Version-specific backend reads are mapped, but historical encrypted-MPU recovery
is not certified: the companion pointer is key-based, manifest reads/cleanup do
not establish a complete parent-version-to-manifest-version history contract.
Do not assume old MPU versions remain recoverable after overwrites/deletes without
testing and retaining the matching manifest and keys. Successful primary delete
does not imply companion cleanup succeeded; cleanup is best-effort.

Object Lock protects backend ciphertext. Keep keys for the retention window and
verify actual retention via the backend/explicit lock APIs, not just accepted
inline headers. Archived-object restore is backend-owned; GET through the gateway
still needs readable ciphertext and the matching decryption material.

Backend CORS only handles forwarded preflight/passthrough responses. Typed encrypted
responses lack required allow/expose headers. Complete browser support is planned
in [GH-322](https://github.com/cloud37/s3-encryption-gateway/issues/322).

## Unsupported Request Behavior

An unsupported operation is **not guaranteed to return 501**:

1. Invalid/missing credentials fail authentication before routing.
2. Unknown selector/query shapes ordinarily fail authorization with 403 AccessDenied
   before backend access. Changing `rw`/bucket grants does not enable them.
3. `x-id` is stripped from classification, not a trusted operation discriminator.
   A request using only `x-id=ListDirectoryBuckets` can match ordinary ListBuckets;
   that is not directory-bucket support. Route/authorization matching alone is not
   a semantic compatibility test.
4. SelectObjectContent has a deliberate authenticated 501 NotImplemented handler;
   disabled MPU and disabled CreateBucket also have explicit 501 responses.
5. Registered proxy APIs can return the provider's own 4xx/5xx/NotImplemented
   responses. Backend transport and typed-object error translation are separate
   paths; see [S3 errors](S3_API_IMPLEMENTATION.md#error-handling-and-translation).

## Verification Boundaries

This document was checked against production source and existing test registrations.
It does not claim that every option was exercised against every provider. See the
[SDK/backend evidence](SDK_COMPATIBILITY.md#backend-and-encryption-mode-coverage).
Known ignored parameters, missing mappings, and unverified workflows remain
visible even where the base operation has a successful smoke scenario. If your
application depends on those semantics, test its exact requests before migration
and file a focused issue rather than assuming generic S3 parity.
