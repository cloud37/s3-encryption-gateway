# ADR 0018: Centralized object metadata

## Status

Accepted

## Decision

Use a leaf `internal/objectmeta` package for the six standard S3 object
headers, and a registry in `internal/crypto` for gateway-owned metadata keys,
aliases, and reserved-key classification. Object format classification and
chunked size derivation are pure shared functions. API read and write paths
should consume these owners rather than reproduce key lists or marker tests.

CopyObject follows S3 COPY/REPLACE semantics: COPY uses the source's client
metadata and ignores request metadata; REPLACE uses request metadata and
defaults Content-Type as documented. Same-key copy remains permitted because
the gateway uses it for re-encryption and migration.

### CopyObject directive decision table

| Request directive | Destination user metadata | Destination standard headers | Request metadata | Invalid directive |
|---|---|---|---|---|
| Absent or `COPY` | Source's decrypted client-visible metadata | Source's decrypted/native values | Ignored; request `Content-Length` and `ETag` are never copied | — |
| `REPLACE` | Request user metadata only | Request values only; absent Content-Type defaults to `application/octet-stream` | Authoritative, except transport fields are excluded | — |
| Any other value | — | — | — | Reject with `400 InvalidArgument` before backend reads |

### Field ownership decision table

| Field group | Plaintext / bypass | Encrypted single-PUT | Encrypted MPU | Projection owner |
|---|---|---|---|---|
| Six standard headers | Backend native values; authenticated GET override wins | GET override > decrypted fallback metadata > protected canonical > compact > legacy > backend-native legacy fallback | GET override > backend native values from CreateMultipartUpload | `objectmeta` model and object response projector |
| User `x-amz-meta-*` | Backend values excluding reserved keys | Decrypted body metadata ∪ expanded protected metadata, excluding reserved keys | Backend values excluding reserved keys | Metadata registry and object response projector |
| ETag | Backend ETag | Quoted original ETag when present, otherwise backend ETag | Backend multipart ETag | Object response projector |
| Content-Length / Content-Range | Backend full length / requested range length | Resolved plaintext size / requested range length and total | Authenticated manifest total / requested range length and total | Plaintext-size resolver and object response projector |
| Accept-Ranges, Last-Modified, lock/storage/parts headers | Backend | Backend | Backend | Object response projector allowlist |
| Version ID | Backend value before request `versionId` fallback | Backend value before request `versionId` fallback | Backend value before request `versionId` fallback | Object response projector |

For all encrypted objects, reserved gateway metadata is never client-visible.
Response overrides apply to GET only; HEAD continues to describe stored object
metadata. These tables are normative and paired with the implementation's
table-driven metadata and response tests.

### Read-plan ownership decision table

| Decision/data | Owner | Executor responsibility |
|---|---|---|
| Object format, size, backend range, MPU manifest and integrity preflight | `planObjectRead` and its shared resolvers | Acquire the selected backend stream and perform the selected decrypt operation |
| Success status, plaintext response range, version fallback, GET overrides, and response source | Complete `objectReadPlan` | Supply authenticated decrypted metadata and the resulting body through the plan's execution-data helper |
| Header projection, first-body preflight, success status/header writes, and complete body stream | Single `serveObjectBody` consumer | No mode-specific response reconstruction; MPU chunk execution reuses the same prepared plan for its first plaintext chunk |

## Consequences

The registry prevents aliases and internal markers from drifting between
compaction, expansion, classification, and response filtering. Unknown MPU
markers and redirecting manifest pointers fail closed. Existing wire formats,
AEAD/AAD construction, and legacy read compatibility remain unchanged.

The `planObjectRead` owner makes classification, size, range, status, and
response-shape decisions before a response can succeed. Execution supplies the
selected body and authenticated decrypted metadata to that same complete plan;
the sole `serveObjectBody` consumer applies the projector, owns successful
response headers and body writing, and performs shared preflight, with
`streamObjectBody` owning stream integrity accounting. GET/MPU executors do not
reconstruct response policy. Handlers consume these shared owners while preserving
wire formats, SEC37/SEC42 integrity ordering, bodyless HEAD semantics,
passthrough behavior, and operation instrumentation. AST guards constrain inline object-error pairs, header
ownership, reserved metadata literals, MPU markers, and manifest suffix
construction. Route parity uses an independent permission oracle against the
real router, request authorization classifier, and instrumentation classifier.

The router deliberately names CopyObject as PutObject and UploadPartCopy as
UploadPart because these are method/query route families. Instrumentation and
authorization assign semantic CopyObject and UploadPartCopy names after
examining the copy-source header. The tested naming divergence is intentional.

## Response and size precedence

The projector emits only the documented object-response allowlist and never
emits gateway-reserved metadata. Encrypted standard fields resolve in this
order: authenticated GET override, decrypted protected metadata, canonical
protected metadata, compact alias, legacy alias, then backend-native fallback.
Backend version IDs take precedence over the request's `versionId`. Plaintext
size follows the object-format policy: authenticated chunked-v2 terminal before
the version-aware ciphertext formula; chunked-v1 formula before original-size
metadata; buffered original-size before supported AEAD overhead; fallback
original-size only; and MPU manifest total with a documented fail-soft HEAD/
ListObjects exception.

Range projection derives inclusive Content-Range and Content-Length from
plaintext offsets; MPU ranged responses apply the same authenticated GET
response overrides as other GET paths. Cache entries are replayed only after a
backend HEAD validates the stored non-empty ETag and the captured body length
matches the exact plaintext size. The trade-off is that cache validation and
authenticated MPU metadata resolution require backend HEAD/manifest reads to
avoid stale or incomplete client responses.
