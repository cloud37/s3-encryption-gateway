# S3 Compatibility Reference

**Release baseline: v0.12.3. Reviewed October 4, 2026.**

This guide owns application compatibility, request/response options, SDK/backend
evidence, and the explicit disposition for **all 112 operations in the pinned
AWS SDK for Go v2 S3 module v1.114.0**, plus the four legacy lifecycle/notification
names in the [AWS S3 action index](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations_Amazon_Simple_Storage_Service.html),
HTML POST Object, and CORS OPTIONS. It is an inventory, not a claim of full S3
feature parity. Start with the summary below before migrating an application.

## Contents

- [Application compatibility matrix](#application-compatibility-matrix)
- [Scope, permissions, and release interpretation](#scope-and-interpretation)
- [Object and multipart operations](#object-and-multipart-operations)
- [Bucket operations](#bucket-operations)
- [Unsupported SDK operations](#unsupported-sdk-operations)
- [Legacy names and browser extensions](#legacy-names-and-browser-extensions)
- [Addressing and authentication](#addressing-and-authentication)
- [Object reads and responses](#object-reads-and-responses)
- [Listings and pagination](#listings-and-pagination)
- [Writes, copies, and multipart options](#writes-copies-and-multipart-options)
- [Body integrity and resource limits](#body-integrity-and-resource-limits)
- [SDK/tool coverage](#sdk--tool-compatibility)
- [Backend and encryption-mode coverage](#backend-and-encryption-mode-coverage)
- [Evidence index](#evidence-index)

## Application Compatibility Matrix

**Supported** means an implemented subset with the notes below, not every AWS
option or every client workflow. **Planned** is unreleased accepted work without
a promised date. **Not supported** explicitly marks absent behavior. Backend
configuration passthrough cannot implement a missing provider feature.

| Feature | Status | Requirements / limitations / tracking |
|---|---|---|
| Put/Get/Head/DeleteObject and DeleteObjects | Supported | Gateway auth/scope, policy-selected encryption or explicit bypass. Typed input/output subset; see option tables. |
| Range GET | Supported | Single plaintext range; optimized chunk/MPU paths and full-decrypt legacy fallback. No multiple-range or HEAD Range parity. |
| CopyObject / UploadPartCopy | Supported | Source read and destination write scope; mediated encrypted copy. Encoded-source identity fixed in v0.12.3 ([#346](https://github.com/cloud37/s3-encryption-gateway/issues/346)). |
| Encrypted multipart upload | Supported | Configured Valkey/key manager; 64 MiB default UploadPart cap. Immutable first-content claims; changed part replacement returns 409 OperationAborted. |
| ListObjects v1/v2 | Supported | Basic listing/token pagination; plaintext-size cache advisory, listing ETags backend-defined. Some pagination/response fields ignored—see below. |
| ListParts | Supported | First backend page only; ignores pagination and emits IsTruncated=false. Not complete large-upload part inventory. |
| SigV4 header/presigned GET/PUT | Supported | Gateway credentials. Signed expiry honored in v0.12.3 ([#345](https://github.com/cloud37/s3-encryption-gateway/issues/345)); 1–604800 seconds. |
| SigV2 | Supported | Deprecated, disabled by default; explicit `AUTH_ALLOW_LEGACY_SIGNATURE_V2=true` temporary migration opt-in. |
| POST Object form policies | Planned | Separate from MPU; [#353](https://github.com/cloud37/s3-encryption-gateway/issues/353). |
| Complete browser CORS | Planned | Forwarded preflight does not add headers on typed encrypted responses; backend CORS alone is insufficient. [#322](https://github.com/cloud37/s3-encryption-gateway/issues/322), related [#318](https://github.com/cloud37/s3-encryption-gateway/issues/318). |
| Bucket configuration / ACL / tagging / lifecycle | Supported | Registered backend-dependent subsets. Independent manage grant for bucket config mutation; object tagging does not imply bucket tagging. |
| Create/DeleteBucket | Supported | Explicit create/delete grants; create also requires ALLOW_BUCKET_CREATION=true. |
| Version-specific reads/deletes/copy sources | Supported | Backend versioning required; no ListObjectVersions or exhaustive historical MPU recovery guarantee. |
| Explicit Object Lock / retention / hold APIs | Supported | Provider setup required. Inline PUT/initiation lock fields are not persisted; verify retention via explicit APIs/backend defaults. Bypass refused. |
| Reverse proxies | Supported | Preserve signed Host/path/query/headers. Outbound filtering fixed in v0.12.2 ([#338](https://github.com/cloud37/s3-encryption-gateway/issues/338)); signed zero Content-Length exception remains ([#356](https://github.com/cloud37/s3-encryption-gateway/issues/356), unreleased fix). |
| Inbound virtual-host addressing / STS / S3 Express | Not supported | Use path-style gateway URLs; DNS/backend addressing flags do not add inbound host routing. |
| Typed conditional object requests | Not supported | If-Match/If-None-Match and related conditions not enforced; not an atomic write-if-absent boundary. |
| Per-upload backend SSE/storage-class fields | Not supported | Typed input mapping absent; backend defaults are independent of gateway encryption. |
| GetObjectAttributes / plaintext checksum retrieval | Not supported | Upload integrity verification is not durable checksum-mode retrieval. |
| SelectObjectContent / WriteGetObjectResponse | Not supported | SQL on gateway ciphertext/Object Lambda integration not implemented; explicit Select returns 501. |

Choose [deployment and bucket policy](DEPLOYMENT.md) for setup,
[key management](KMS_COMPATIBILITY.md) for key selection, and
[migration](MIGRATION.md) for upgrades/recovery. This is the single compatibility
reference; other guides link here rather than maintain parallel support matrices.

## Scope and Interpretation

- **Supported** means a production handler or deliberate dispatch implements the
  operation, subject to the listed subset and backend requirements. **Not supported**
  means no semantic implementation, even if its URL can match another operation's
  route. **Planned** means unavailable but accepted work has a tracking issue.
- Every supported row is available in the **v0.12.3 baseline**. This is not a claim
  that v0.12.3 introduced it. Earliest introduction was not audited for every row;
  use the [changelog](../CHANGELOG.md) for release history. GH-338 proxy filtering
  requires v0.12.2; GH-345 presigned lifetime and GH-346 copy-source fixes require
  v0.12.3. Branch implementations are not released support.
- Paths below use inbound **path-style** addressing. `B` is `/{bucket}` and `O`
  is `/{bucket}/{key}`. The backend's addressing mode is a separate setting.
  Selectors such as `?cors` must have an empty value. The optional SDK `x-id`
  parameter is not an operation selector; required value parameters are shown.
- **R**: bucket in credential scope, object permission `ro` or `rw`.
  **W**: bucket in scope and object permission `rw`. **M**: bucket in scope and
  independent `bucket_permissions: [manage]`. **C/D**: explicit `create`/`delete`
  grants; C also requires `ALLOW_BUCKET_CREATION=true`. **L**: authenticated
  `ro`/`rw`, with the result filtered to effective scope. `PROXIED_BUCKET` narrows
  all applicable scopes. Copy requires source read and destination write scope.
- All supported operations require a usable backend and backend IAM permissions.
  **Typed** operations construct a restricted SDK request and transform bodies or
  metadata; they do not forward every S3 option. **Proxy** operations re-sign and
  forward permitted headers and query fields. Neither implements missing provider
  capabilities. Encrypted MPU requires Valkey state and a key manager; plaintext
  MPU requires an explicit policy opt-out. See [setup](../README.md#encrypted-multipart-uploads).
- S3 Control (access-point administration, account-level public access settings,
  Batch Operations, Multi-Region Access Points), S3 Tables, S3 Vectors, STS/IAM,
  and native non-S3 cloud APIs are **out of scope** and are not implemented by this
  S3 endpoint. No support or tracking commitment is implied for these families.

## Object and Multipart Operations

All rows here depend on backend object/multipart support. Encryption follows the
bucket policy; object subresources operate on the stored ciphertext object's
backend metadata or configuration rather than decrypting their XML bodies.

| Official operation | HTTP | Status | Grant | Handling, limitations, evidence |
|---|---|---|---|---|
| `AbortMultipartUpload` | DELETE O `?uploadId=...` | Supported | W | Typed abort plus guarded encrypted-state cleanup; 204 on success. Disabled MPU returns 501. [MPU evidence](#evidence-index). |
| `CompleteMultipartUpload` | POST O `?uploadId=...` | Supported | W | Typed part-number/ETag list; encrypted committed-state validation and companion manifest. Additional checksum fields and conditional completion are not implemented. [MPU evidence](#evidence-index). |
| `CopyObject` | PUT O, `x-amz-copy-source` | Supported | W + source R | Mediated decrypt/re-encrypt; COPY/REPLACE standard/user metadata. Request ACLs, tagging-directive parity, conditions, and backend SSE options are not fully implemented. [Copy evidence](#evidence-index). |
| `CreateMultipartUpload` | POST O `?uploads` | Supported | W | Typed initiation; standard/user metadata and ACL fields. Inline tagging, storage class, SSE, and Object Lock initiation settings are not mapped. [MPU evidence](#evidence-index). |
| `DeleteObject` | DELETE O, optional `versionId` | Supported | W | Typed delete; best-effort MPU companion cleanup. 204; backend delete-marker/version response headers are not projected. Governance bypass refused. [Object evidence](#evidence-index). |
| `DeleteObjects` | POST B `?delete` | Supported | W | Typed XML Key/VersionId batch with per-key results and cleanup. `Quiet` is parsed but not honored; newer conditional XML fields are not mapped. [Object evidence](#evidence-index). |
| `DeleteObjectTagging` | DELETE O `?tagging`, optional `versionId` | Supported | W | Proxy; requires backend tagging support. [Configuration evidence](#evidence-index). |
| `GetObject` | GET O, optional `versionId` | Supported | R | Typed plaintext body/range and response-header projection; conditional headers, part selection, and checksum-mode responses are not implemented. [Object evidence](#evidence-index). |
| `GetObjectAcl` | GET O `?acl`, optional `versionId` | Supported | R | Proxy; backend object ACL support required. [Configuration evidence](#evidence-index). |
| `GetObjectLegalHold` | GET O `?legal-hold`, optional `versionId` | Supported | R | Typed Object Lock API; returns XML. [Lock evidence](#evidence-index). |
| `GetObjectRetention` | GET O `?retention`, optional `versionId` | Supported | R | Typed Object Lock API; returns XML. [Lock evidence](#evidence-index). |
| `GetObjectTagging` | GET O `?tagging`, optional `versionId` | Supported | R | Proxy; backend tagging support required. [Configuration evidence](#evidence-index). |
| `HeadObject` | HEAD O, optional `versionId` | Supported | R | Typed metadata/size projection; missing MPU manifest can leave ciphertext length. No conditional, HEAD Range, or part-number semantics. [Object evidence](#evidence-index). |
| `ListMultipartUploads` | GET B `?uploads` | Supported | R | Proxy, including accepted pagination parameters; provider owns result semantics. [MPU evidence](#evidence-index). |
| `ListObjects` | GET B | Supported | R | Typed backend ListObjectsV2 adapted to listing XML; v1 marker supported, other field/size/ETag caveats apply. [Listing evidence](#evidence-index). |
| `ListObjectsV2` | GET B `?list-type=2` | Supported | R | Shared typed listing handler; continuation-token supported, `start-after`, `fetch-owner`, and `encoding-type` ignored. XML is a subset. [Listing evidence](#evidence-index). |
| `ListParts` | GET O `?uploadId=...` | Supported | R | Typed first backend page; `max-parts`/`part-number-marker` ignored and `IsTruncated=false` emitted. State can translate part sizes. [MPU evidence](#evidence-index). |
| `PutObject` | PUT O | Supported | W | Typed encrypted/bypass body; standard/user metadata, tags, ACL fields. Conditions, inline Object Lock persistence, storage class, SSE, and durable checksum projection are not implemented by this adapter. [Object evidence](#evidence-index). |
| `PutObjectAcl` | PUT O `?acl`, optional `versionId` | Supported | W | Proxy; backend object ACL support required. [Configuration evidence](#evidence-index). |
| `PutObjectLegalHold` | PUT O `?legal-hold`, optional `versionId` | Supported | W | Typed validated ON/OFF XML, 100 KiB parser limit. [Lock evidence](#evidence-index). |
| `PutObjectLockConfiguration` | PUT B `?object-lock` | Supported | M | Typed validated bucket lock XML, 100 KiB parser limit. Backend must support Object Lock. [Lock evidence](#evidence-index). |
| `GetObjectLockConfiguration` | GET B `?object-lock` | Supported | R | Typed bucket lock configuration XML. [Lock evidence](#evidence-index). |
| `PutObjectRetention` | PUT O `?retention`, optional `versionId` | Supported | W | Typed validated future retention date/mode; 100 KiB parser limit, governance bypass refused. [Lock evidence](#evidence-index). |
| `PutObjectTagging` | PUT O `?tagging`, optional `versionId` | Supported | W | Proxy XML; backend validates the tag document. Inline PutObject tagging has separate gateway validation. [Configuration evidence](#evidence-index). |
| `RestoreObject` | POST O `?restore` | Supported | W | Proxy restore of backend ciphertext. No archive retrieval orchestration; adding `versionId` to this POST is rejected by current authorization. Route verified; provider restore workflow not independently covered. |
| `UploadPart` | PUT O `?partNumber=...&uploadId=...` | Supported | W | Typed part body, default 64 MiB buffer cap; encrypted immutable content claims and identical retries. [MPU evidence](#evidence-index). |
| `UploadPartCopy` | PUT O `?partNumber=...&uploadId=...`, `x-amz-copy-source` | Supported | W + source R | Native copy only for compatible plaintext path; otherwise mediated plaintext-range copy. Source versions and immutable encrypted claims supported; copy conditions not mapped. [Copy evidence](#evidence-index). |

## Bucket Operations

These depend on provider support for the specified bucket API. Proxy configuration
documents do not grant gateway authorization or change its encryption policy.
For example, PutBucketPolicy changes backend IAM policy, not gateway credential
scope; PutBucketEncryption changes backend defaults, not gateway key selection.
Most configuration PUT/DELETE bodies are capped at 1 MiB.

| Official operation | HTTP | Status | Grant | Handling, limitations, evidence |
|---|---|---|---|---|
| `CreateBucket` | PUT B | Supported | C | Proxy raw LocationConstraint XML, 64 KiB body cap and bucket-name validation. Backend handles Object Lock creation options. [Bucket evidence](#evidence-index). |
| `DeleteBucket` | DELETE B | Supported | D | Guarded proxy; backend must permit deleting the bucket. [Bucket evidence](#evidence-index). |
| `DeleteBucketCors` | DELETE B `?cors` | Supported | M | Proxy; no gateway-side CORS store in this release. [Configuration evidence](#evidence-index). |
| `DeleteBucketEncryption` | DELETE B `?encryption` | Supported | M | Proxy backend encryption defaults. [Configuration evidence](#evidence-index). |
| `DeleteBucketInventoryConfiguration` | DELETE B `?inventory&id=...` | Supported | M | Proxy named configuration; route parity covered, provider workflow not independently covered. |
| `DeleteBucketLifecycle` | DELETE B `?lifecycle` | Supported | M | Proxy. Lifecycle acts on ciphertext and does not coordinate key/companion retention. [Configuration evidence](#evidence-index). |
| `DeleteBucketPolicy` | DELETE B `?policy` | Supported | M | Proxy backend policy, not gateway credential policy. [Configuration evidence](#evidence-index). |
| `DeleteBucketReplication` | DELETE B `?replication` | Supported | M | Proxy; route parity covered, replication workflow not independently covered. |
| `DeleteBucketWebsite` | DELETE B `?website` | Supported | M | Proxy; route parity covered, website workflow not independently covered. |
| `GetBucketAcl` | GET B `?acl` | Supported | R | Proxy. [Configuration evidence](#evidence-index). |
| `GetBucketAnalyticsConfiguration` | GET B `?analytics&id=...` | Supported | R | Proxy named configuration; route parity covered, provider workflow not independently covered. |
| `GetBucketCors` | GET B `?cors` | Supported | R | Proxy; does not make gateway-generated responses CORS-readable. [Configuration evidence](#evidence-index). |
| `GetBucketEncryption` | GET B `?encryption` | Supported | R | Proxy backend defaults. [Configuration evidence](#evidence-index). |
| `GetBucketInventoryConfiguration` | GET B `?inventory&id=...` | Supported | R | Proxy named configuration; route parity covered, provider workflow not independently covered. |
| `GetBucketLifecycleConfiguration` | GET B `?lifecycle` | Supported | R | Proxy. [Configuration evidence](#evidence-index). |
| `GetBucketLocation` | GET B `?location` | Supported | R | Proxy backend region document. [Bucket evidence](#evidence-index). |
| `GetBucketLogging` | GET B `?logging` | Supported | R | Proxy; route parity covered, provider logging workflow not independently covered. |
| `GetBucketNotificationConfiguration` | GET B `?notification` | Supported | R | Proxy backend events; route parity covered, event delivery not independently covered. |
| `GetBucketPolicy` | GET B `?policy` | Supported | R | Proxy backend IAM policy. [Configuration evidence](#evidence-index). |
| `GetBucketReplication` | GET B `?replication` | Supported | R | Proxy; ciphertext replication, manifest/key portability not certified. Route parity covered. |
| `GetBucketRequestPayment` | GET B `?requestPayment` | Supported | R | Proxy; route parity covered, requester-pays workflow not independently covered. |
| `GetBucketVersioning` | GET B `?versioning` | Supported | R | Proxy; does not imply ListObjectVersions support or historical MPU-manifest recovery. [Configuration evidence](#evidence-index). |
| `GetBucketWebsite` | GET B `?website` | Supported | R | Proxy configuration, not an anonymous website-serving endpoint. Route parity covered. |
| `HeadBucket` | HEAD B | Supported | R | Typed existence/access probe using backend ListObjects; not a complete backend HeadBucket header contract. [Bucket evidence](#evidence-index). |
| `ListBucketAnalyticsConfigurations` | GET B `?analytics` | Supported | R | Shared proxy route without `id`; first-page backend passthrough only. `continuation-token` is rejected. No independent list/pagination test. |
| `ListBucketInventoryConfigurations` | GET B `?inventory` | Supported | R | Shared proxy route without `id`; first-page backend passthrough only. `continuation-token` is rejected. No independent list/pagination test. |
| `ListBuckets` | GET `/` | Supported | L | Proxy request then filtered/rebuilt XML; new pagination/filter queries rejected and successful-response continuation/region fields not projected. [Bucket evidence](#evidence-index). |
| `PutBucketAcl` | PUT B `?acl` | Supported | M | Proxy; independent manage grant required. [Configuration evidence](#evidence-index). |
| `PutBucketCors` | PUT B `?cors` | Supported | M | Proxy only. Gateway-managed evaluation remains [GH-322](https://github.com/cloud37/s3-encryption-gateway/issues/322). [Configuration evidence](#evidence-index). |
| `PutBucketEncryption` | PUT B `?encryption` | Supported | M | Proxy backend defaults, not gateway encryption policy. [Configuration evidence](#evidence-index). |
| `PutBucketIntelligentTieringConfiguration` | PUT B `?intelligent-tiering&id=...` | Supported | M | Proxy named configuration; GET/list/delete counterpart operations are not implemented. Route parity covered, provider workflow not independently covered. |
| `PutBucketInventoryConfiguration` | PUT B `?inventory&id=...` | Supported | M | Proxy named configuration; report contents are backend ciphertext metadata, not translated plaintext metadata. Route parity covered. |
| `PutBucketLifecycleConfiguration` | PUT B `?lifecycle` | Supported | M | Proxy; backend owns transition/expiry. [Configuration evidence](#evidence-index). |
| `PutBucketLogging` | PUT B `?logging` | Supported | M | Proxy; logs are backend-side requests, not a substitute for gateway audit. Route parity covered. |
| `PutBucketNotificationConfiguration` | PUT B `?notification` | Supported | M | Proxy; events describe backend writes, including gateway internal writes. Event delivery not independently covered. |
| `PutBucketPolicy` | PUT B `?policy` | Supported | M | Proxy; does not grant gateway access. [Configuration evidence](#evidence-index). |
| `PutBucketReplication` | PUT B `?replication` | Supported | M | Proxy configuration; backend copies are not automatically re-bound for another gateway bucket/key. Route parity covered, recovery not certified. |
| `PutBucketRequestPayment` | PUT B `?requestPayment` | Supported | M | Proxy configuration; typed object requests do not map requester-pays headers. Route parity covered. |
| `PutBucketVersioning` | PUT B `?versioning` | Supported | M | Proxy configuration; provider capability required. [Configuration evidence](#evidence-index). |
| `PutBucketWebsite` | PUT B `?website` | Supported | M | Proxy configuration; gateway still authenticates S3 reads. Route parity covered, website serving not implemented. |

## Unsupported SDK Operations

Each operation below is explicitly **not supported in v0.12.3**. Except where a
reason/tracker is specified, there is no committed implementation plan or release
date. Do not assume backend support makes it accessible through the gateway.
Grant `—` means there is no supported gateway authorization contract for that
operation; changing credential grants cannot enable it. Evidence is source
inspection of routes, authorization, and SDK bindings, not individual runtime
tests of all these requests. See [unsupported request behavior](#unsupported-request-behavior).

| Official operation | AWS HTTP shape (path-style shorthand) | Status | Grant | Reason / tracking |
|---|---|---|---|---|
| `CreateBucketMetadataConfiguration` | POST B `?metadataConfiguration` | Not supported | — | No metadata-table control API. |
| `CreateBucketMetadataTableConfiguration` | POST B `?metadataTable` | Not supported | — | No metadata-table control API. |
| `CreateSession` | GET B `?session` | Not supported | — | S3 Express session authentication is not implemented. |
| `DeleteBucketAnalyticsConfiguration` | DELETE B `?analytics&id=...` | Not supported | — | No delete route; GET-only analytics subset. |
| `DeleteBucketIntelligentTieringConfiguration` | DELETE B `?intelligent-tiering&id=...` | Not supported | — | Only PUT configuration is routed. |
| `DeleteBucketMetadataConfiguration` | DELETE B `?metadataConfiguration` | Not supported | — | No metadata-table control API. |
| `DeleteBucketMetadataTableConfiguration` | DELETE B `?metadataTable` | Not supported | — | No metadata-table control API. |
| `DeleteBucketMetricsConfiguration` | DELETE B `?metrics&id=...` | Not supported | — | Backend S3 metrics configuration is distinct from gateway Prometheus metrics. |
| `DeleteBucketOwnershipControls` | DELETE B `?ownershipControls` | Not supported | — | No ownership-controls route. |
| `DeleteBucketTagging` | DELETE B `?tagging` | Not supported | — | Object tagging support does not include bucket tagging. |
| `DeleteObjectAnnotation` | DELETE O `?annotation` | Not supported | — | No object-annotation API. |
| `DeletePublicAccessBlock` | DELETE B `?publicAccessBlock` | Not supported | — | No bucket public-access-block route. |
| `GetBucketAbac` | GET B `?abac` | Not supported | — | Backend ABAC configuration is distinct from gateway credential scopes. |
| `GetBucketAccelerateConfiguration` | GET B `?accelerate` | Not supported | — | No acceleration configuration or accelerated gateway endpoint. |
| `GetBucketIntelligentTieringConfiguration` | GET B `?intelligent-tiering&id=...` | Not supported | — | Only PUT configuration is routed. |
| `GetBucketMetadataConfiguration` | GET B `?metadataConfiguration` | Not supported | — | No metadata-table control API. |
| `GetBucketMetadataTableConfiguration` | GET B `?metadataTable` | Not supported | — | No metadata-table control API. |
| `GetBucketMetricsConfiguration` | GET B `?metrics&id=...` | Not supported | — | Not the gateway `/metrics` endpoint. |
| `GetBucketOwnershipControls` | GET B `?ownershipControls` | Not supported | — | No ownership-controls route. |
| `GetBucketPolicyStatus` | GET B `?policyStatus` | Not supported | — | GetBucketPolicy support does not include policy-status evaluation. |
| `GetBucketTagging` | GET B `?tagging` | Not supported | — | No bucket tagging route. |
| `GetObjectAnnotation` | GET O `?annotation` | Not supported | — | No object-annotation API. |
| `GetObjectAttributes` | GET O `?attributes`, `x-amz-object-attributes` | Not supported | — | No plaintext size/checksum/part attribute API. |
| `GetObjectTorrent` | GET O `?torrent` | Not supported | — | No torrent operation for encrypted objects. |
| `GetPublicAccessBlock` | GET B `?publicAccessBlock` | Not supported | — | No bucket public-access-block route. |
| `ListBucketIntelligentTieringConfigurations` | GET B `?intelligent-tiering` | Not supported | — | No list route. |
| `ListBucketMetricsConfigurations` | GET B `?metrics` | Not supported | — | No list route. |
| `ListDirectoryBuckets` | GET `/`, SDK `x-id=ListDirectoryBuckets` | Not supported | — | No directory-bucket inventory; `x-id` alone can match ordinary ListBuckets, not this semantic operation. |
| `ListObjectAnnotations` | GET O `?annotation` | Not supported | — | No annotation listing. |
| `ListObjectVersions` | GET B `?versions` | Not supported | — | Version-specific object access does not include version inventory or delete-marker listing. |
| `PutBucketAbac` | PUT B `?abac` | Not supported | — | No backend ABAC route. |
| `PutBucketAccelerateConfiguration` | PUT B `?accelerate` | Not supported | — | No acceleration configuration route. |
| `PutBucketAnalyticsConfiguration` | PUT B `?analytics&id=...` | Not supported | — | Only analytics GET/list first-page proxying is routed. |
| `PutBucketMetricsConfiguration` | PUT B `?metrics&id=...` | Not supported | — | No backend metrics configuration route. |
| `PutBucketOwnershipControls` | PUT B `?ownershipControls` | Not supported | — | No ownership-controls route. |
| `PutBucketTagging` | PUT B `?tagging` | Not supported | — | No bucket tagging route. |
| `PutObjectAnnotation` | PUT O `?annotation` | Not supported | — | No object-annotation API. |
| `PutPublicAccessBlock` | PUT B `?publicAccessBlock` | Not supported | — | No bucket public-access-block route. |
| `RenameObject` | PUT O `?renameObject`, rename-source header | Not supported | — | S3 Express rename is not gateway CopyObject plus DeleteObject. |
| `SelectObjectContent` | POST O `?select&select-type=2` | Not supported | R to reach refusal | Explicit `501 NotImplemented` after auth; backend SQL cannot evaluate gateway ciphertext. By design; [Configuration evidence](#evidence-index). |
| `UpdateBucketMetadataAnnotationTableConfiguration` | PUT B `?metadataAnnotationTable` | Not supported | — | No metadata-table control API. |
| `UpdateBucketMetadataInventoryTableConfiguration` | PUT B `?metadataInventoryTable` | Not supported | — | No metadata-table control API. |
| `UpdateBucketMetadataJournalTableConfiguration` | PUT B `?metadataJournalTable` | Not supported | — | No metadata-table control API. |
| `UpdateObjectEncryption` | PUT O `?encryption` | Not supported | — | Backend SSE changes are not gateway key rotation/re-encryption. |
| `WriteGetObjectResponse` | POST `/WriteGetObjectResponse` | Not supported | — | No S3 Object Lambda response integration; by design. |

## Legacy Names and Browser Extensions

These entries are additional to the pinned SDK's 112 operations. Legacy XML
schemas are not independently certified merely because they share a route with a
modern Configuration API. Consult backend-specific compatibility for old clients.

| Operation / extension | HTTP | Status | Grant | Handling / tracking |
|---|---|---|---|---|
| `GetBucketLifecycle` | GET B `?lifecycle` | Supported | R | Same proxy route as GetBucketLifecycleConfiguration; legacy schema not independently verified. |
| `PutBucketLifecycle` | PUT B `?lifecycle` | Supported | M | Same proxy route as PutBucketLifecycleConfiguration; backend must accept the legacy document. |
| `GetBucketNotification` | GET B `?notification` | Supported | R | Same proxy route as GetBucketNotificationConfiguration; legacy schema not independently verified. |
| `PutBucketNotification` | PUT B `?notification` | Supported | M | Same proxy route as PutBucketNotificationConfiguration; backend must accept the legacy document. |
| POST Object (presigned HTML form) | POST B, `multipart/form-data` | Planned | — currently; intended W | Not implemented. [GH-353](https://github.com/cloud37/s3-encryption-gateway/issues/353); browser response CORS depends on GH-322. |
| CORS preflight OPTIONS | OPTIONS B or O | Supported | Credential-free qualifying preflight, otherwise R | Narrow authentication exception; backend passthrough only. Complete gateway-owned browser CORS is planned in [GH-322](https://github.com/cloud37/s3-encryption-gateway/issues/322). |

## Evidence Index

Test references identify **existing source scenarios**, not a fresh pass report or
certification of all options. Provider gates and fixtures can skip scenarios; see
[SDK/backend coverage](#backend-and-encryption-mode-coverage).

- **Route evidence for all routed rows:** [`RegisterRoutes`](../internal/api/handlers.go),
  [`authorization.go`](../internal/api/authorization.go), and
  [`TestRouteClassificationParity`](../internal/api/route_parity_test.go).
  Shared analytics/inventory list shapes use the existing GET route; they lack
  independently asserted list/pagination conformance.
- **Object:** [`put_get_test.go`](../test/conformance/put_get_test.go),
  [`ranged_test.go`](../test/conformance/ranged_test.go),
  [`metadata_matrix_test.go`](../test/conformance/metadata_matrix_test.go),
  [`object_response_test.go`](../internal/api/object_response_test.go),
  and [`object_read_backend_test.go`](../test/conformance/object_read_backend_test.go).
- **Listing:** [`listobjects_size_test.go`](../test/conformance/listobjects_size_test.go)
  and ListObjects prefix/delimiter/marker/token unit tests in
  [`handlers_test.go`](../internal/api/handlers_test.go). These do not certify
  `start-after`, `fetch-owner`, `encoding-type`, or complete XML parity.
- **MPU:** Multipart_Basic / Multipart_Abort / Multipart_ListParts registrations
  in [`suite_test.go`](../test/conformance/suite_test.go),
  [`encrypted_mpu_test.go`](../test/conformance/encrypted_mpu_test.go), and
  [`sec38_complete_handler_test.go`](../internal/api/sec38_complete_handler_test.go).
  Small ListParts scenarios do not certify pagination.
- **Copy:** [`copy_source_test.go`](../test/conformance/copy_source_test.go),
  [`upload_part_copy_test.go`](../test/conformance/upload_part_copy_test.go), and
  [`sec38_copy_http_test.go`](../internal/api/sec38_copy_http_test.go).
- **Bucket:** [`bucket_management_test.go`](../test/conformance/bucket_management_test.go),
  [`bucket_management_test.go`](../internal/api/bucket_management_test.go),
  and ListBuckets/GetBucketLocation cases in the configuration suite below.
- **Configuration:** [`s3_compat_test.go`](../test/conformance/s3_compat_test.go),
  [`bucket_configuration_authorization_test.go`](../test/conformance/bucket_configuration_authorization_test.go),
  and [`passthrough_headers_test.go`](../test/conformance/passthrough_headers_test.go).
  Round trips exist for selected ACL, tagging, CORS, lifecycle, policy, versioning,
  and encryption operations. Notification, replication, logging, website, restore,
  inventory, analytics, and intelligent-tiering workflows are not independently
  certified by a route-parity assertion.
- **Lock:** [`object_lock_test.go`](../internal/api/object_lock_test.go),
  [`object_lock_test.go`](../test/conformance/object_lock_test.go), and typed SDK
  mapping in [`client.go`](../internal/s3/client.go). Inline-lock intent in tests
  must not be read as proof that typed PutObject persists those settings.

## Keeping the Inventory Complete

On an SDK or release update, compare this inventory with `api_op_*.go` in the
pinned `github.com/aws/aws-sdk-go-v2/service/s3` module and the AWS action index.
Review `RegisterRoutes`, header-based copy dispatch, query authorization, typed
SDK input/output mappings, and provider gates before changing a status. Record
options separately; do not promote an operation to full parity because its base
route or a small smoke test passes. Keep unknown/untested combinations explicit
and add tracking links only when a real issue exists.

## Addressing and Authentication

| Mode | Released behavior |
|---|---|
| Path style | Supported: `https://gateway/bucket/key`; bucket/key come from the path. |
| Virtual host | No `bucket.gateway` host-to-bucket mapping. DNS alone cannot enable it; do not rewrite a signed Host/path to compensate. Backend addressing settings are independent. |
| Access-point/Outposts/Object Lambda ARNs, S3 Express/directory buckets | No endpoint/ARN/session routing contract. Ordinary scopes/routes do not implement these modes. |
| SigV4 header | Gateway access key/secret, default 5-minute clock skew; operation fields and signed-body integrity are separate contracts. |
| SigV4 presigned GET/PUT | Sign gateway endpoint with gateway credentials; expiry single integer 1–604800 seconds. Permission changes still apply. |
| SigV2 | Disabled by default; explicit deprecated migration opt-in. |
| STS/session credentials | No token issuance/expiry authority or configured session-token validation; a token present in a signed request is not session-credential certification. |
| Anonymous/website reads | Backend public policy does not bypass gateway auth. System probes/qualifying credential-free OPTIONS are narrow exceptions. |
| Browser forms/CORS | Unreleased #353/#322 work; ordinary presigned PUT support does not imply complete browser uploads. |

### SigV4 Request Time and Presigned Expiration

Header timestamps must fall within `auth.clock_skew_tolerance` (default `5m`).
Presigned timestamps cannot exceed that tolerance into the future; past age is
bounded by `X-Amz-Date + X-Amz-Expires`, with no grace past the signed deadline.
Expiry is checked when authentication starts, not by interrupting an accepted
download. Scope date follows the signing date; crossing midnight is valid.
Malformed/duplicate/zero/negative/overflowing expiry is rejected before backend
access; altering expiry without re-signing fails HMAC verification.

| Failure | HTTP | S3 code / fixed message |
|---|---|---|
| Authenticated expired URL | 403 | AccessDenied: `Request has expired.` |
| Excessive timestamp skew | 403 | RequestTimeTooSkewed: `The difference between the request time and the server's time is too large.` |
| Authenticated invalid/missing expiry | 400 | InvalidArgument: `X-Amz-Expires must be a single integer between 1 and 604800 seconds.` |
| Incorrect HMAC | 403 | SignatureDoesNotMatch; no internal signing diagnostics |

## Object Reads and Responses

| Field / option | Released behavior |
|---|---|
| GET/HEAD `versionId` | Typed backend mapping; provider versioning required. |
| GET Range | Single closed/open/suffix plaintext range, 206 with projected length/range. Encrypted chunks/MPU translated; legacy/full fallback may read entire object. Multiple ranges absent. |
| HEAD Range / GET/HEAD `partNumber` | Not mapped/applied even when query authorization accepts it. |
| Conditional headers | If-Match/If-None-Match/If-Modified-Since/If-Unmodified-Since/If-Range not mapped/evaluated on typed GET/HEAD. No guaranteed conditional 304/412 or If-Range behavior. |
| Six GET response overrides | Content type/language/encoding/disposition, cache control, expires override projected values on authenticated GET/range/cache; not HEAD. |
| Checksum mode / attributes | No durable plaintext checksum response contract; typed reads do not map checksum-mode. GetObjectAttributes absent. |
| ETag | Original recorded encrypted single-object ETag if available; otherwise backend. MPU uses backend multipart ETag; PUT/listing backend ETag, not universal plaintext MD5. |
| Metadata | Six standard fields and filtered user metadata through shared projector; internal markers/aliases/blobs hidden. See [encryption metadata model](ENCRYPTION_DESIGN.md#encrypted-object-metadata-model). |
| Version/delete-marker output | GET/HEAD backend version wins requested fallback. Typed write/delete responses do not consistently project destination version/delete-marker fields. |
| Other backend headers | Typed reads are not generic passthrough: do not assume lifecycle/restore/SSE/checksum/CORS headers survive. |
| Manifest/cache | Missing MPU manifests fail GET/copy; HEAD/list size may retain ciphertext. Cache revalidates metadata/ETag and projects overrides but adds no conditional/checksum semantics. |

## Listings and Pagination

| Option | Released behavior |
|---|---|
| ListObjects v1/v2 | Shared backend ListObjectsV2 adapter; prefix/delimiter/positive max-keys/continuation-token mapped. |
| v1 marker | Maps to backend StartAfter; NextMarker derived from last returned object. |
| v2 start-after | Accepted but ignored; handler reads marker instead. Use token pagination. |
| encoding-type/fetch-owner | Accepted but not applied; ordinary XML escaping, no requested URL encoding/owner output. |
| XML parity | Name/Prefix/Delimiter/MaxKeys/IsTruncated/NextContinuationToken/Contents/CommonPrefixes and derived NextMarker; KeyCount/echoed continuation/start-after/EncodingType fields incomplete. |
| zero/invalid max-keys | No strict AWS validation/zero-page contract; adapter sets only positive MaxKeys. |
| StorageClass / size / ETag | StorageClass reconstructed as STANDARD; advisory Valkey/HEAD size translation, unresolved ciphertext sizes possible; ETag backend-defined. |
| Manifest suffix | `.mpu-manifest` filtered as internal namespace; not safe for ordinary app keys. Counts/pages can differ after filtering. |
| ListParts pagination | One backend page, requested max-parts/marker ignored; emits MaxParts=1000/marker=0/IsTruncated=false. Large uploads can have incomplete unsignaled inventory. |
| ListParts size | Positive stored plaintext size substituted when available; otherwise backend encrypted size. |
| ListMultipartUploads | Proxy preserves accepted prefix/delimiter/encoding/key-marker/upload-id-marker/max-uploads; provider owns pagination. Not the admin state inventory. |
| ListBuckets | New prefix/region/max-buckets/token queries rejected; success XML only Owner and Name/CreationDate, incomplete pagination/region output. |
| Analytics/inventory list | Shared first-page GET proxy without id; continuation-token rejected, not independently verified pagination. |
| ListObjectVersions | Not implemented; version-specific access is not version inventory. |

## Writes, Copies, and Multipart Options

### Copy-source Encoding and Identity (GH-346)

Copy-source headers accept `bucket/key` or `/bucket/key`, optionally followed by
`?versionId=...`. Split the raw version suffix **before** one path-percent decode;
literal `+` stays `+`, `%20` becomes space, `%252F` is literal `%2F`, encoded `?`
or `#` remain key data. Do not normalize repeated slashes/dot segments. Decode
opaque version separately; source authorization and backend reads use that same
identity. Backend copy builds a separately escaped header, never mutating signed
inbound source fields. Malformed escapes/empty components return 400 InvalidArgument;
valid out-of-scope identity returns 403. v0.12.3 fixes old wrong-sibling selection;
audit prior escaped-key copies/moves using [migration](MIGRATION.md).

| Option | Released behavior |
|---|---|
| Standard/user metadata | Shared six-field parser/persistence; reserved names rejected, backend filters apply. Initiation freezes destination fields. |
| PUT/DELETE/completion conditions | Typed If-Match/If-None-Match and newer delete conditions absent; not an atomic compare-and-swap boundary. |
| PUT ACL/grants | Parsed/mapped; provider permissions required. Copy re-encrypt does not set request ACL; use object ACL afterward. |
| PUT tags | Validated/mapped inline; XML subresources proxy provider validation. Initiation tags not forwarded; set after completion. |
| Backend SSE/storage class | SSE-S3/SSE-KMS/SSE-C/DSSE and storage-class input mapping absent on typed writes/parts/copy; backend defaults independent. |
| Owner/requester-pays/MFA | Proxy permitted x-amz fields preserved; typed methods do not generally map them. No full requester-pays/MFA-delete contract. |
| Content-MD5/checksum headers | Not a general inbound validation/persistence contract. Adapter computes outgoing MD5 for seekable bytes, possibly ciphertext. Signed-body modes below verify inbound integrity. |
| Copy identity/version/range | Decode source once; source version and plaintext part range supported. Location-bound ciphertext must not be backend-relocated. |
| Copy source conditions | x-amz-copy-source-if-* not mapped by typed source/native part inputs. |
| Metadata/tagging directive | COPY inherits source fields, REPLACE request fields; invalid metadata directive rejected. Tagging-directive not full source-tag COPY/REPLACE parity. |
| Part retry/replacement | Immutable first-content claims: identical retry supported; changed content/reservation conflict 409 OperationAborted. Abort/new upload to change part. |
| Completion XML | Selected ordered PartNumber/ETag set validated; additional per-part checksum XML not carried into backend input. |
| Inline Object Lock | PUT parses/validates but typed adapter does not persist; initiation fields not captured. Native copy maps lock; re-encrypted copy has PUT limitation. Completion retention/hold uses separate post-completion calls, not atomic. |
| Governance bypass | Truthy bypass refused with 403 on retention/delete paths; no S3 admin override. |
| DeleteObjects | Key/VersionId mapped, per-key results; Quiet ignored, conditional fields and full marker-version output absent. |

### Passthrough Request Header Contract

Registered proxy APIs construct independent backend headers before signing:
allowed `x-amz-*` operation fields (not incoming authentication), six standard
content fields plus Content-MD5, conditional/range headers, and CORS inputs.
Client Authorization/X-Amz-Date/X-Amz-Content-Sha256/security token and query
authentication are replaced/removed. Signed inbound headers are not mutated.
Proxy identity/cookies/tracing/arbitrary fields and fixed/Connection-nominated
hop-by-hop fields are excluded. Proxy responses keep end-to-end fields except
hop-by-hop nominations; redirects are returned, not followed. This is **not** the
typed object adapter's option mapping. See [proxy deployment](DEPLOYMENT.md#frontend-header-preservation).

## Body Integrity and Resource Limits

Concrete lowercase SHA-256 signed bodies are verified/spooled before dispatch;
UNSIGNED-PAYLOAD declines that preflight. Exact streaming modes accepted:
STREAMING-AWS4-HMAC-SHA256-PAYLOAD, STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER,
STREAMING-UNSIGNED-PAYLOAD-TRAILER. Signed chunks/terminal and declared trailers
are verified before storage. Trailer algorithms: CRC64NVME, CRC32, CRC32C,
SHA-1, SHA-256. Unknown/ambiguous modes fail closed; no stored-checksum retrieval implied.

| Limit | Default / behavior |
|---|---|
| UploadPart | 64 MiB `SERVER_MAX_PART_BUFFER`, plaintext/encrypted; reject before write |
| Verified spools | 5 GiB request / 10 GiB aggregate process budget; request 413 EntityTooLarge, aggregate 503 SlowDown; operation caps also apply |
| Legacy encrypted copy | 256 MiB configurable source cap; full decrypt; general copy may buffer ciphertext |
| CreateBucket XML | 64 KiB |
| Config PUT/DELETE | 1 MiB body-limited proxy; Object Lock parser 100 KiB |
| Complete XML | 10 MiB plus part/order validation; provider object limits independent |

See [deployment](DEPLOYMENT.md) for spool/timeout config and [security contract](../SECURITY.md).
Bounds do not certify every upload mode/provider accepts that size.

## Backend-Managed Features and Recovery

Lifecycle/replication/inventory/logging/events operate on ciphertext and gateway
internal writes; they do not coordinate manifest/key retention or translated sizes.
Cross-location backend replication can conflict with authenticated binding.
Historical MPU parent/manifest versions are not a fully certified recovery mapping.
Companion cleanup is best-effort. Explicit lock APIs/backend defaults must be
verified; accepted inline headers alone do not establish retention. Archived restore
still needs readable ciphertext and keys. See [migration](MIGRATION.md) and [runbook](RUNBOOK.md).

## Unsupported Request Behavior

Missing/invalid credentials fail first. Unknown query shapes normally return
403 AccessDenied before backend access; a new grant cannot enable an absent API.
`x-id` is not a trusted operation discriminator—ordinary ListBuckets can match
a directory-list-shaped request without implementing directory semantics.
SelectObjectContent and disabled MPU/CreateBucket have explicit 501 handlers;
registered proxies can return provider failures. Not every unsupported request
returns 501, and every unimplemented wire shape is not independently tested.

### Error Handling and Translation

Typed backend errors use fixed S3 XML messages: NoSuchBucket/NoSuchKey → 404,
AccessDenied → 403, InvalidArgument/InvalidBucketName → 400,
SlowDown/ServiceUnavailable → 503, unclassified failures → 500 InternalError.
GET planning preserves backend error provenance, not false crypto/tamper attribution.
Key-manager failures remain crypto failures; missing companion manifests keep their
documented integrity/advisory policy. HEAD has no response body; late streaming
errors cannot replace written headers. Proxy APIs retain upstream response semantics
and use their own forwarding-error path. Do not infer universal error codes from
this typed mapping.

## SDK / Tool Compatibility

The following is **source scenario coverage**, not fresh certification of all
operations/tool versions. Pins reflect v0.12.3. ✓ means directly exercised; — means
not independently exercised by that runner, not unsupported by the tool.

| Tool | Pin | Basic PUT/GET/LIST/DELETE | HEAD | MPU | Copy | Caveat |
|---|---|---|---|---|---|---|
| Go SDK v2 | S3 v1.114.0 | ✓ | ✓ | ✓ | ✓ | Seven-operation in-process runner |
| boto3 | 1.43.107 | ✓ | ✓ | ✓ | — | Separate HTTPS trailer MPU scenario |
| AWS CLI | 2.37.8 | ✓ | ✓ | ✓ | ✓ | HEAD via s3api, separate MPU/copy-metadata scenarios |
| s5cmd | 2.3.0 | ✓ | — | — | — | Listing command, not plaintext ETag, tested |
| rclone | 1.75 | ✓ | — | — | — | Size-cache/fallback sync tests separate; basic copy-cutoff flag not proof of S3-to-S3 copy |
| minio-py | 7.2.20 | ✓ | ✓ | — | — | Runner strips endpoint scheme and sets secure for HTTP fixture |

Runner images: amazon/aws-cli:2.37.8, peakcom/s5cmd:v2.3.0,
rclone/rclone:1.75, python:3.14-slim (package pins above), restic/restic:0.19.1.
See [runner source](../test/conformance/compat_runners.go) and [go.mod](../go.mod).
Image pins are Renovate-managed; an updated version is not a passed test report.

Restic has bypass-policy init/backup/restore/hybrid scenarios and encrypts its own
repository, not gateway-encrypted-MPU certification. minio-go has a separate MPU
scenario, not full tool coverage. Java/JS/PHP/.NET/rust-s3 and other clients have no
exhaustive tool matrix. PHP-informed copy fixes and the unreleased rust-s3 proxy fix
do not certify every operation. Dedicated presigned/KMS scenarios are not complete
per-tool combinations. CI runs on Linux; Windows/macOS workflows not certified.

```bash
make test-conformance-compat
GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 \
GATEWAY_TEST_SKIP_SEAWEEDFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
  go test -count=1 -tags=conformance -race -v -timeout 15m \
  -run 'TestConformance/minio/Compat_Boto3' ./test/conformance/...
```

## Backend and Encryption-Mode Coverage

S = fixture capability selects gated scenarios, — = not selected. Selection is
not a fresh pass report, product-wide support assertion, or complete field mapping.
Ungated tests still run and some have their own skips/upstream fixtures. Source
owners: [providers](../test/provider/) and [suite](../test/conformance/suite_test.go).

| Fixture | MPU/copy | Object tags / inline | Versions | Lock | Encrypted MPU | Size cache |
|---|---|---|---|---|---|---|
| MinIO | S/S | S/S | — | — | S | S |
| Garage | S/S | —/S | — | — | S | S |
| RustFS | S/S | S/S | — | — | S | S |
| SeaweedFS | S/S | S/S | S | — | S | S |
| AWS external | S/S | S/S | S | S | S | S |
| B2 external | S/S | —/— | — | — | S | S |
| Hetzner / Wasabi external | S/S | S/S | — | — | S | — |
| GCS / Azure configured endpoints | S/— | S/— | — | — | — | — |

Bucket management/policy/lifecycle bits selected for MinIO; bucket CORS/ACL/object
ACL/encryption bits absent across these current fixtures. AWS supports many such
APIs but the fixture does not select their gated tests. Conditional PUT bits:
MinIO/AWS/GCS/Azure; native SSE bit: AWS. **These bits do not implement missing
gateway typed conditions/SSE.** Batch-delete/presigned bits selected for all above;
load-test bits for four locals; backend TLS bit conditional on MinIO setup.

All seven tool bits selected for four locals and AWS; B2 selects boto3/CLI/s5cmd
only; Hetzner/Wasabi/GCS/Azure select no tool bits. Ceph/R2/Spaces/Swift lack
registered fixture-wide certification. GCS/Azure configured endpoints are not a
native non-S3 API or turnkey cloud-support promise.

| Mode | Existing evidence | Boundary |
|---|---|---|
| Password single-object | Basic/tool/KDF/chunked cases | Not every option/KDF/tool/size |
| Bypass | Metadata/body and restic workflows | No gateway confidentiality; not encrypted MPU |
| Encrypted MPU | EncryptedMPU/SEC38/SEC46/metadata with Valkey | Explicit wiring; generic tool MPU not proof |
| Local AES/RSA envelope | SelfContained/metadata cases | Not every tool × key type × backend |
| Cosmian | Capability on four locals/AWS/B2 | Dedicated KMS tests, not all tools/failures |
| OpenBao/Vault | Capability on four locals | Dedicated rotation/failure tests, not cloud/tool product |
| FIPS | Unit/race/vet build jobs | No separate full SDK/backend matrix |
| Streaming | Signed integrity/HTTPS CLI/boto3 | No durable plaintext checksum API |
| Legacy | Golden read fixtures | Not arbitrary relocation or historical MPU recovery |

No complete scenario matrix covers every unsupported wire error, pagination option,
conditions, SSE/owner/requester-pays/MFA field, replication/event delivery, archive
restore, anonymous website, historical MPU recovery, or every SDK/proxy/KMS/backend.
Known missing mappings above are limitations, not just absent tests. Inspect real
[CI logs/workflow](../.github/workflows/conformance.yml) and fixture policy/state/key
wiring before asserting coverage; external jobs require credentials and can skip.
