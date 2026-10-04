# S3 Operation Inventory

**Release baseline: v0.12.3. Reviewed October 4, 2026.**

This appendix gives an explicit disposition for **all 112 operations in the pinned
AWS SDK for Go v2 S3 module v1.114.0**, plus the four legacy lifecycle/notification
names in the [AWS S3 action index](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations_Amazon_Simple_Storage_Service.html),
HTML POST Object, and CORS OPTIONS. It is an inventory, not a claim of full S3
feature parity. Start with the shorter [application matrix](S3_API_IMPLEMENTATION.md#application-compatibility-matrix)
and read the [option-level contract](S3_COMPATIBILITY.md) before migrating.

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
tests of all these requests. See [unsupported request behavior](S3_COMPATIBILITY.md#unsupported-request-behavior).

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
[SDK/backend coverage](SDK_COMPATIBILITY.md#backend-and-encryption-mode-coverage).

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
