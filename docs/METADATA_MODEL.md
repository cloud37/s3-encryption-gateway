# Encrypted object metadata model

This document is the inventory and compatibility contract for object metadata.
The gateway treats the six standard headers below as one typed model, while
gateway-owned encryption markers remain reserved and are never client-visible.

## Standard fields

`Content-Type`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`,
`Content-Language`, and `Expires` are parsed case-insensitively, persisted as
protected metadata for encrypted objects, and restored in that order. For
passthrough objects they are native backend headers. `x-amz-meta-*` user keys
are preserved except for reserved gateway keys.

## Write paths

PUT, CreateMultipartUpload, CopyObject, UploadPartCopy, and streaming size
backfill share the same intended ownership: request parsing separates standard
and user metadata; encryption stamps protected values; the persistence layer
splits standard values into native backend fields. CopyObject uses source
metadata for absent/COPY directives and request metadata for REPLACE.

## Read paths and precedence

HEAD, full and ranged GET, MPU GET, and cache hits project headers from one
object view. `planObjectRead` owns GET classification, plaintext-size and range
decisions, integrity preflight, and response-source selection for cache, full,
passthrough, optimized, buffered, and MPU range reads; handler branches do not
repeat those decisions. It returns the complete response plan, including final
status, range shape, response overrides/version fallback, response source and
the selected body. One `serveObjectBody` consumes that plan, projects headers,
performs the shared preflight, and streams the selected reader; GET and MPU
executors do not reconstruct response policy. For encrypted single objects,
precedence is response override (GET only), decrypted protected metadata,
canonical protected metadata, compact/legacy aliases, then backend native values. MPU responses use native
headers and manifest sizes. ETags are quoted from the original encrypted
metadata when available; plaintext sizes are derived from the object format.

Unknown backend headers and all gateway-reserved metadata are dropped.

## Format compatibility

The reader continues to recognize buffered legacy/v2, fallback v1/v2/v3,
chunked v1/v2, compacted metadata, encrypted metadata blobs, MPU v1/v2, and
plaintext objects. Unknown format markers and MPU manifest pointers that do
not equal `<object-key>.mpu-manifest` fail closed.

The committed A7 fixture corpus contains deterministic backend metadata and
ciphertext for buffered legacy/v2, fallback v1/v2/v3, chunked v1/v2, compacted,
metadata-blob buffered/chunked, MPU v1/v2, and plaintext objects. The test-only
generator and production-handler golden harness pin HEAD, full GET, and ranged
GET plaintext and response headers. First-chunk tamper regressions cover every
decryptable fixture format. MPU ranged handler behavior has focused success and
failure writer tests, including error/metric ownership and override projection.

## Inventory

The write/read transformations covered by this model include standard-header
capture, encryption metadata stamping, compaction/expansion, backend key
normalization, plaintext-size derivation, MPU manifest lookup, ETag quoting,
range headers, cache fills/hits, and CopyObject directive handling. The matrix
below records the gateway-owned transformation for each path and field; the
implementation plan (`docs/plans/V1.0-S3-6-plan.md`) remains the detailed
phase checklist.

## Path-by-field inventory

| Path | Six standard fields | User metadata | ETag / size / version |
|---|---|---|---|
| PUT | Parsed by `parseWriteMetadata`; encrypted values are protected, bypass values are native | Parsed and rejected if gateway-reserved | Original size stamped; backend ETag returned |
| CreateMultipartUpload | Parsed and persisted as native multipart initiation headers | Parsed with reserved-key rejection | MPU marker and binding are added by gateway |
| CopyObject COPY | Inherits source plaintext values | Inherits source user keys; request metadata ignored | Destination is re-encrypted; source size resolved |
| CopyObject REPLACE | Request values replace source; missing Content-Type defaults | Request keys only; reserved keys rejected | Request Content-Length and ETag are excluded |
| CopyObject source-size/cap planning | Not copied from raw source metadata | N/A | Source is classified and its plaintext size is resolved before copy strategy/cap decisions |
| UploadPartCopy | Uses destination metadata frozen by CreateMultipartUpload; only source bytes/range are read | Same | Part range is resolved through source format/manifest |
| Streaming-size backfill | `buildPersistPlan` preserves native fields | Gateway metadata retained | Resolved size replaces metadata using backend COPY/REPLACE |
| Engine buffered/chunked/fallback encrypt | `stampProtectedStandard` stores protected values | Caller user fields retained | Original ETag and exact plaintext size remain format metadata |
| Backend adapters | `objectmeta.Split` sets native fields; returned keys are normalized | `x-amz-meta-*` names normalized | ETag/length/version are normalized at adapter boundary |
| HEAD | Projector applies canonical > compact > legacy > backend precedence | Non-reserved keys only | Resolved size; backend version wins request version |
| Full GET | Projector applies decrypted > canonical > compact > legacy > backend; GET overrides win | Non-reserved keys only | Original ETag quoted; resolved size; backend version wins |
| Optimized/buffered/passthrough range GET | Same projector and GET overrides | Non-reserved keys only | Plaintext Content-Range/length; ETag and version projected |
| MPU full/range GET | Native initiation values, then GET overrides | Non-reserved keys only | Manifest plaintext size; backend multipart ETag/version |
| Cache fill/hit | Serialized source metadata is re-projected; current GET overrides apply | Non-reserved keys only | Full successful plaintext only; exact captured size and backend ETag are stored atomically; HEAD ETag mismatch invalidates the entry and fetches fresh bytes |
| ListObjects | Not a response-header path | Not projected | Size translation uses shared resolver; ETag remains backend-defined |

## Path/field ownership and precedence

| Input/source | PUT | CreateMultipartUpload | CopyObject COPY | CopyObject REPLACE | UploadPartCopy | HEAD | GET / range / cache |
|---|---|---|---|---|---|---|---|
| Six standard headers | Request headers parsed case-insensitively; encrypted fields stamped as protected metadata; bypass fields persisted natively | Parsed once and placed in native MPU initiation headers; Content-Type defaults only when absent | Source decrypted standard values win; request standard values ignored | Request values win; omitted values remain absent except default Content-Type | Destination values frozen by MPU initiation; source is decrypted only for copied part bytes | Resolved protected canonical > compact > legacy > native fallback | GET override > decrypted protected > canonical > compact > legacy > native fallback |
| User metadata | Lowercase request `x-amz-meta-*`; reserved registry names rejected | Same parser and reserved rejection | Source user metadata inherited | Request user metadata replaces source; reserved rejected | Destination metadata frozen from CreateMPU | Backend/decrypted metadata excluding reserved names | Decrypted/source metadata excluding reserved names; cache stores the projected source metadata |
| Content-Length | Plaintext size passed as engine input; ciphertext length sent to backend; excluded from user metadata persistence | Not client metadata; backend multipart size is completion-dependent | Never copied from request; destination derived from decrypted source | Request Content-Length ignored; destination size derived from bytes | Source size resolved by shared resolver; part range determines copied plaintext | Shared resolver; only MPU manifest failure may return backend ciphertext size | Shared resolver for full/range body projection; range length is selected plaintext bytes |
| ETag | Backend returns ciphertext ETag; engine records original ETag | Backend multipart ETag is assigned on completion | Original source ETag is not request metadata; encrypted destination receives a new backend ETag | Request ETag ignored | Part ETag describes copied/encrypted part per MPU protocol | Original encrypted ETag quoted when present, otherwise backend ETag | Same projection on full/range/cache; MPU uses multipart ETag |
| Version ID | Backend response value | Backend response value | Backend destination version | Backend destination version | Backend destination version | Backend value > request versionId fallback | Backend value > request versionId fallback |
| Gateway markers / compact aliases | Engine stamps and registry compacts; reserved client keys rejected before side effects | MPU control markers are generated after parse; all client reserved aliases rejected | Source internal metadata is retained only for encryption processing | Client cannot override gateway-owned keys | Source format classifier selects byte transformation; destination's frozen metadata remains authoritative | Classifier validates markers/pointers before projection; reserved names omitted | Classifier and manifest loader validate before streaming; reserved names omitted from all response shapes |

## Ownership rules

The version-ID inventory describes possible backend values, not a guarantee that
every write handler returns a destination `x-amz-version-id`. Typed write/delete
response shapes do not consistently project backend version/delete-marker fields.
The six-field model is not a complete conditional-request, checksum-mode, or
arbitrary backend-header contract; see [request/response compatibility](S3_COMPATIBILITY.md).

- `objectmeta.Names` is the one ordered list of standard headers and is used by request parsing, persistence splitting, and response projection.
- `crypto.MetaKeys()` owns gateway canonical keys, compact aliases, legacy aliases, reserved classification, and the frozen historical encryption-predicate bit.
- `crypto.ClassifyObject` owns plaintext/buffered/fallback/chunked/MPU format decisions and rejects unknown marker values or manifest-pointer mismatches.
- `Handler.resolvePlaintextSize` owns API size decisions. Chunked v2 terminal authentication is first; a size formula is only the defined fallback. Fallback formats never use a guessed AEAD-size subtraction.
- Completed-object `ListObjects` size translation for bounded stat-style pages uses `loadObjectView` plus `resolvePlaintextSize`; in-progress MPU sizes use the state-store plaintext counters. If bounded HEAD resolution is disabled, larger/general listings rely on size-cache entries and otherwise retain backend sizes.
- `projectObjectHeaders` owns all client-visible object headers; the handler streams bytes only after classification, required integrity checks, and size/manifest resolution.
- CreateMultipartUpload uses `parseWriteMetadata` and `buildPersistPlan` like other writers. Gateway-generated MPU markers are merged after the caller's reserved-key validation.
- ListObjects uses the shared resolver for bounded stat-style size translation; broader listing pages rely on the exact size cache and configured fallback HEADs to avoid N+1 metadata reads.

## Precedence decision (ADR 0018)

For encrypted standard fields, canonical protected metadata wins over compact
aliases, which win over legacy aliases; decrypted response metadata is the
authoritative source when available. Backend-native values are compatibility
fallbacks for older objects. `response-*` overrides win only on authenticated
GET responses. Backend version IDs take precedence over the request's
`versionId`. Gateway-reserved metadata is never exposed, including clear
encryption markers and encrypted metadata blobs.

For plaintext/bypass objects, native backend standard fields are authoritative
unless an authenticated GET carries a `response-*` override. For encrypted
single-object reads, decrypted metadata (when body decryption supplies it) wins
over registry canonical, compact, and legacy forms, which win over native
backend compatibility values. MPU standard fields come from CreateMPU's native
headers and range/full sizes come from the validated manifest. ETag comes from
the quoted original ETag for encrypted single objects when available; MPU uses
the backend multipart ETag. A known backend version ID wins over the request
fallback. HEAD never applies response overrides.

The fallback golden fixtures assert the exact plaintext `Content-Length` on
full GET and HEAD, plus the selected plaintext range length on ranged GET.
`TestGetObject_FallbackGoldenContentLengthBehavior` pins these values.

## Additional Compatibility Boundaries

Historical MPU reads require matching companion manifests and decryption keys.
A key-based companion pointer is not a certified mapping from every parent
version to its matching manifest version. Backend overwrites/deletes/replication
need recovery validation. See the [operation inventory](S3_OPERATIONS.md) and
[recovery caveats](S3_COMPATIBILITY.md#backend-managed-features-and-recovery).
