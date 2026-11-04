# GH-353 — Browser form uploads with signed POST policies — Implementation Plan

Status: Verified complete — approved scope (2026-11-04)
Owner: API / Auth / Backend / Config / QA
Priority: P1
Labels: `area:api`, `area:auth`, `area:s3`, `area:config`
Depends on: GH-322 (`docs/plans/GH-322-plan.md`)

> Scope clarified relative to the tracker entry at `docs/issues/GH-353.md:19`.
> The user approved broader POST support: redirects, tagging, storage class,
> plaintext checksums, configured session credentials and backend SSE-S3/KMS/C.
> The user selected GH-322 as the CORS dependency and trusted-proxy HTTPS for
> SSE-C. This is implementation-ready specification, not an authorization to
> start implementation. Implement GH-322 first; preserve its existing files.

> 🧠 **From Hindsight memory (Conventions and patterns)** — Shared ownership,
> fixed S3 error messages, real HTTP regression assertions and preservation of
> unrelated work are repository conventions. Current source/ADRs cited below
> were checked before adopting those constraints in this plan.

---

## 1. Context & Current State

Discovery baseline: commit `1bd5e14`, version 0.12.3. GitHub #353 reports the
same version [1]. `ExtractCredentials` checks query fields and Authorization
only (`internal/api/credentials.go:26-87`); `AuthMiddleware` rejects failed
extraction before routing (`internal/api/auth_middleware.go:192-199`). The
fixed missing-credentials response is exactly the reported 403 AccessDenied
(`internal/api/handlers.go:511-516`). Bare bucket POST is authorizationUnknown
(`internal/api/authorization.go:269-281`) and a test explicitly pins that
result (`internal/api/authorization_test.go:261`). The router only registers
bucket POST for `?delete` (`internal/api/handlers.go:445-446`). Browser POST is
a distinct operation from multipart-upload initiation/completion, despite the
current documentation heading (`docs/S3_API_IMPLEMENTATION.md:36-40`) [2–4].

The existing PUT handler already selects per-bucket encryption, constructs
ObjectContext, parses reserved/user/standard metadata, persists ciphertext,
invalidates cache and records plaintext size (`internal/api/handlers.go:815-1242`,
`internal/api/object_write.go:18-31,81-123`). Unknown-length PUT writes directly
and later may copy-to-self to persist size (`internal/api/handlers.go:1131-1229`);
that is unsuitable for a POST whose minimum size and complete MIME framing
must be checked before a destination write. Quota reservations and 0600
temporary-file cleanup already exist (`internal/api/spool_manager.go:21-71,121-178`,
`internal/api/verified_aws_body.go:47-75,117-170`). Reuse that accounting, not the
SigV4 canonical-request/payload verifier: POST signs the literal base64 policy
instead (`internal/api/auth.go:682-717`) [3,4].

Credentials currently have no session token or deadline
(`internal/config/config.go:778-793`, `internal/api/credential_store.go:26-31`);
configuration resolves env secrets and replaces immutable snapshots
(`internal/config/config.go:53-66`, `cmd/server/main.go:136-150`,
`internal/api/credential_store.go:94-125`). Backend PutObject exposes only an
ETag and has no storage-class/SSE options; GET/HEAD cannot receive customer
keys (`internal/s3/client.go:36-63,506-551,598-615,735-745`). GCS/Azure are
wrappers, not native Google/Azure SDKs (`internal/s3/gcs_client.go:15-52`,
`internal/s3/azure_client.go:14-54`). Response projection has one owner and
returns original encrypted ETag when available
(`internal/api/object_response.go:55-139`); chunked encryption consumes an
internal ETag input (`internal/crypto/engine.go:1197-1218`). Cache eligibility
currently depends only on range/version (`internal/api/object_stream.go:298-314`).
SSE-C must therefore include read-side and cache constraints, not merely POST
serialization. These changes preserve ADR 0012's gateway/backend credential
separation and ADR 0016/0018's authorization and metadata ownership [5–7].

Browser preflight currently forwards to the backend
(`internal/api/handlers.go:4969-4972`); PUT synthesizes its own success response
(`internal/api/handlers.go:1237-1242`). GH-322 specifies an outer
`CORSMiddleware` and authoritative shared Valkey CORS store
(`docs/plans/GH-322-plan.md:325-347,551-555`). GH-353 consumes that dependency,
not a duplicate CORS engine [8]. Current trusted-proxy CIDRs already have a
shared owner (`internal/util/ip.go:10-35,88-101`), but ForceHTTPS only adds
HSTS (`internal/middleware/security.go:23-37`): it is not proof of secure
transport. TLS termination must be accepted only from a trusted immediate
peer with an unambiguous HTTPS indication [9].

## 2. Design Goals & Non-Goals

### Goals

1. **SDK compatibility:** authenticated path-style POST works with boto3
   generate_presigned_post and AWS JS createPresignedPost; exactly one file/text
   part, filename expansion and all specified policy conditions are supported.
2. **Fail-closed policy/authorization:** signature, session token/deadline,
   policy deadline, full field coverage, bucket/key and existing rw/scope/global
   restriction checks pass before file spooling/backend activity.
3. **No invalid-write side effects:** complete file size, MIME termination and
   requested plaintext checksums are verified before encryption, cache
   invalidation, backend reads/writes or auxiliary mutations. A rejected POST
   preserves an existing destination and its metadata/version/cache.
4. **One write owner:** PUT and POST reuse encryption, persisted metadata,
   exact ciphertext length, retry decisions, audit and plaintext-size logic;
   existing PUT wire behavior and unknown-length behavior remain unchanged.
5. **Broader form semantics:** metadata/ACL/tagging/storage/SSE options and
   200/201/204/303 responses are explicit, with safe XML/URL serialization and
   backend-version/SSE/checksum response projection.
6. **SSE-C end-to-end safety:** customer keys are request-scoped, require trusted
   HTTPS plus verified backend HTTPS, reach every primary-object GET/HEAD
   preflight/range read, never enter persistent metadata or plaintext cache,
   and are mandatory on subsequent reads.
7. **Credential isolation and rollout:** static or configured session credentials
   share existing atomic snapshots and Helm/env/file loading; backend identity
   remains independent; no new STS service or credential forwarding mode.
8. **Real browser acceptance:** GH-322 CORS governs success/errors and exposed
   headers; browser fetch succeeds from allowed origins and cannot read
   responses from disallowed origins. Mandatory Tier 1 and Tier 2 proof passes.

### Non-Goals

1. Anonymous/public-bucket POST, SigV2 POST and DevPay: mandatory gateway auth
   remains the boundary; ordinary configured legacy SigV2 remains unchanged
   for static credentials, but cannot use session credentials.
2. Virtual-host addressing, directory buckets/S3 Express, DSSE-KMS, multi-file
   forms, Object Lock form extensions and arbitrary provider-specific fields:
   outside the approved interoperable single-object contract; reject rather
   than silently degrade. DSSE-KMS is not SSE-KMS.
3. STS issuance/refresh or live IAM policy evaluation: session tokens are
   operator-configured gateway credentials with expiration, not dynamically
   accepted AWS identities. Existing bucket scopes plus POST policy govern access.
4. SSE-C CopyObject/UploadPartCopy/MPU/rotation extensions: this plan supports
   POST/PUT write and GET/HEAD/range lifecycle; copy/MPU SSE-C headers return
   501 before source/destination work. Never auto-rotate an SSE-C object.
5. A second CORS authority, Valkey rule import/reset or checksum database:
   GH-322 owns CORS; plaintext checksum validation/POST acknowledgment is in
   scope, durable GetObjectAttributes/checksum-mode APIs are not.

## 3. Target Interface / Semantics / Behaviour

All declarations below are normative. Helper bodies are implementation tasks;
do not add guessed exported APIs. New interfaces use private implementations,
context propagation, sentinel errors and fixed client messages. Existing
`s3.Client` remains source-compatible; extensions use an additive interface.

### 3.1 Routing, authentication and execution order

Add the named `PostObject` bucket route **after** `DeleteObjects`. The route
matches POST `/{bucket}` with Content-Type parsed by mime.ParseMediaType as
`multipart/form-data` and nonempty valid boundary. Accept `/{bucket}/` through
existing trailing-slash normalization; the pre-router predicate accepts exactly
one optional trailing slash too. Require `r.URL.RawQuery == ""` (not Query(),
which can drop malformed parameters, or signature-filtered operationQuery).
Object-level POST, extra query parameters,
`?delete`, `?uploads`, `?uploadId`, malformed media types and boundary-less
forms must never be interpreted as PostObject. Unknown shapes retain existing
denials/routes. Do not normalize or URL-decode form keys: they are literal UTF-8
S3 keys, at most 1024 bytes, nonempty after expansion; leading/repeated slashes,
`+`, `%`, dots and Unicode remain data. No virtual-host inference [2,3].

```go
// postUpload is owned by one request; fields become immutable after auth.
// No nil request/context accepted; no backend calls; Close is idempotent.
type postUpload struct {
    bucket, key, filename string
    fields map[string]string
    reader *multipart.Reader
    file *multipart.Part
    wire *postWireReader
    policy postPolicy
    options s3.ObjectPutOptions
    checksum postChecksum
    deadline time.Time
    successStatus int
    redirect *url.URL
    body verifiedAWSBody
}
func isPostObjectRequest(r *http.Request) bool
func parsePostUpload(r *http.Request, globalLimit int64) (*postUpload, error)
func (u *postUpload) Close() error
func postUploadFromContext(r *http.Request) (*postUpload, bool)
func validatePostPolicyAt(u *postUpload, c Credential, skew time.Duration, now time.Time) error
func (h *Handler) handlePostObject(w http.ResponseWriter, r *http.Request)
```

Use the exact predicate in auth, authorization fallback classifier, mux matcher
and operation instrumentation. Add PostObject→authorizationWrite to the
permission map and independent test oracle. Authenticate only this narrow
candidate before ordinary ExtractCredentials; reject any simultaneous header
or query authentication with 400 InvalidRequest (no fallback between modes).
Require form `policy`, `x-amz-algorithm`, `x-amz-credential`, `x-amz-date`,
`x-amz-signature`, `key`, and file; resolve secret only from CredentialStore.
The auth branch parses only bounded preceding fields/file headers, validates
signature and non-size conditions, attaches the **same** credential/label
context keys and upload context, defers Close, then calls ordinary authorization.
Authorization checks effective bucket and rw before the handler spools file.
The multipart reader may buffer a bounded lookahead but must not deliberately
drain/spool file contents before authorization. Emit existing auth.failure /
authorization.denied events using fixed reasons, never policy/secret values.

The handler verifies frame/file/checksum, rechecks policy/session expiration
immediately before write, constructs the typed write input, invokes the common
writer and only then serializes success. No backend acquisition, KMS call,
cache invalidation or write before validation. No request.Method/URL rewriting
or synthetic Authorization fields to reuse the PUT HTTP handler.

Rationale: MIME credentials are transport data for a distinct signing scheme;
preserving the authenticated-principal/authorization chain prevents a route
exception from becoming an auth bypass [3,5,6].

### 3.2 Strict MIME and policy contract

Limits are fixed wire constraints plus existing configurable payload budgets:
non-file data **including all MIME boundaries/headers** ≤20*1024 bytes;
≤128 scalar fields; boundary ≤70 bytes; policy conditions ≤256; JSON nesting
≤32. File ≤min(server.max_verified_spool_bytes, 5 GiB, all signed upper bounds).
All signed lower bounds must pass. No content-length-range condition is legal
and uses the server/5 GiB maximum with zero minimum. Limits are captured once
at request entry from live SpoolLimitSource. No new upload-limit config [3].

```go
type postCondition struct { op, field, value string; min, max int64 }
type postPolicy struct { expiration time.Time; conditions []postCondition }
func parsePostPolicy(encoded string) (postPolicy, error)
func matchPostConditions(p postPolicy, fields map[string]string, bucket string) (int64, int64, error)
func expandPostFilename(fields map[string]string, rawFilename string) (map[string]string, string, error)
// postWireReader counts raw bytes; zero-length Read never consumes input.
type postWireReader struct {
    r io.Reader
    read, limit int64
    boundary string
    scan []byte // boundary-length + 8 rolling delimiter lookbehind
    preambleBytes int64
    opened, closed, invalidEpilogue bool
}
func (r *postWireReader) Read(p []byte) (int, error)
func (r *postWireReader) Finish() error
```

Use MultipartReader/NextRawPart, not ParseMultipartForm/ReadForm (uncontrolled
disk/memory use) or NextPart (which can decode quoted-printable content).
Reject Content-Transfer-Encoding, nested multipart, non-form-data disposition,
missing names, duplicate names after ASCII case-folding, scalar filename
parameters, duplicate MIME critical headers, invalid UTF-8, NUL and CR/LF in
scalar values. File bytes are arbitrary. Accept `file` with or without filename
(text content is valid), exactly once and last. Reject ANY later part,
including `submit`; this explicitly follows the file-last contract despite
older AWS examples. Require closing boundary, then boundedly consume the
underlying wire reader to HTTP EOF and validate its streaming delimiter
observer, including prefetched MIME bytes. Observe initial opening delimiter
after whitespace-only preamble and the **first** syntactically complete closing
delimiter line `\r\n--<boundary>--` (optional space/tab then CRLF or EOF);
once closed, require every following byte be whitespace. Later closing-looking
bytes cannot reset this state or hide an invalid epilogue. Keep rolling
lookbehind at most boundary length + 8 and integer whitespace counters, no
whole-body copy. Handle delimiter split across reads and exact EOF using
Finish. Require CRLF framing and reject LF-only delimiter lines consistently
before accepting storage; MIME may be more permissive than this contract.
multipart.Reader can hide prefetched epilogue, so NextRawPart EOF alone is not
proof of HTTP EOF. Reject truncated
forms or unread trailing data; Content-Length, if present, describes the
entire form, never the file. Streaming/chunked transfer is allowed [2,3,14].

Track raw consumed bytes using postWireReader below MIME buffering. Before the
file, cumulative raw bytes are bounded by form allowance plus parser lookahead
(32 KiB): initialize its read cap to 20 KiB +32 KiB and clamp each underlying
Read to remaining cap+one sentinel byte; do not merely notice a huge header
after MIME finishes parsing. On recognition of the file header, raise the cap
to request file bound+20 KiB (already counted bytes remain charged). After full
EOF verify `rawBytes - fileBytes <= 20*1024`. Bound total
wire bytes to global/5 GiB cap +20 KiB + one byte sentinel, fail on overflow.
Limit scalar reads to remaining field allowance+1; MIME overhead that is only
knowable after streaming is validated **before** write. Go's MIME header
limits remain additional defense, not a substitute for the 20 KiB contract.
Account for lookahead when checking early limits; do not miscount prefetched
file data as overhead. Test oversized headers/boundaries/epilogues explicitly.

Parse JSON tokens recursively with duplicate-key rejection and json.Number;
allow only one object with `expiration` and `conditions`, no trailing JSON,
unknown root keys, duplicate nested keys or non-string equality values. Strict
standard padded base64, valid UTF-8, GMT RFC3339/RFC3339Nano expiration.
Conditions are objects (one or more field:string exact matches),
`["eq","$field","value"]`, `["starts-with","$field","prefix"]`, or
`["content-length-range",min,max]`. Ranges use nonnegative base-10 integer JSON
tokens, no floats/exponents/signs; min≤max within int64. All conditions AND.
Malformed operators/arity/types/unknown condition fields fail closed.

Field lookup uses ASCII case-insensitive canonical names and duplicate rejection.
Bucket is validated with crypto.ObjectContext.Validate before authentication
continues; production destination bucket stays the parsed URL component.
Object key/value bytes remain case-sensitive; form values are never trimmed
for matching. Compute filename basename using both slash and backslash, using
raw Content-Disposition filename (not OS filepath.Base); absent filename→empty.
Expand `${filename}` in scalar values before matching and option conversion,
except policy/signature which are never rewritten. Authentication fields must
not contain interpolation. Require exact bucket binding against destination;
an optional submitted bucket must equal the URL bucket. Require conditions
covering bucket, key and all auth fields. Other submitted fields must be covered
except policy/file/signature/x-ignore-*. Missing referenced fields fail even for
empty prefix. Ignore fields cannot influence storage/auth/responses and cannot
be condition targets. Unknown submitted fields fail 501 even if signed.

| Field class | Legal condition types |
|---|---|
| bucket, x-amz-algorithm/credential/date/security-token, success_action_status, SSE/checksum/storage/tagging fields | Exact only |
| key, six standard headers, x-amz-meta-*, success_action_redirect, redirect | Exact or starts-with |
| content-length-range | Integer range only |

Closed accepted form-name list (ASCII case-insensitive): `key`, optional
`bucket`, `file`, `policy`, `x-amz-algorithm`, `x-amz-credential`, `x-amz-date`,
`x-amz-signature`, optional `x-amz-security-token`, `acl`, all six names in
objectmeta.Names, `success_action_status`, `success_action_redirect`, `redirect`,
`tagging`, `x-amz-storage-class`, `x-amz-website-redirect-location`,
`Content-MD5`, `x-amz-checksum-algorithm`, `x-amz-checksum-crc32`,
`x-amz-checksum-crc32c`, `x-amz-checksum-sha1`, `x-amz-checksum-sha256`,
`x-amz-server-side-encryption`, `x-amz-server-side-encryption-aws-kms-key-id`,
`x-amz-server-side-encryption-context`,
`x-amz-server-side-encryption-bucket-key-enabled`,
`x-amz-server-side-encryption-customer-algorithm`,
`x-amz-server-side-encryption-customer-key`,
`x-amz-server-side-encryption-customer-key-MD5`, and nonempty suffixes under
`x-amz-meta-`/`x-ignore-`. Reserved user metadata is rejected through existing
parseWriteMetadata before spooling; x-ignore fields are discarded, never stored.
`ETag`, Content-Length, grant/copy/ObjectLock fields and unknown x-amz names
are not accepted form fields; do not infer a wildcard allowlist from x-amz-*.

For starts-with Content-Type, split only that value at commas and require each
item to match; other fields treat commas literally. Do not require both exact
and prefix key conditions; either (or several compatible conditions) suffices.
Fields exempt from coverage cannot be used to widen storage behavior [4].

SigV4 formula: `hex(HMAC-SHA256(kSigning, originalBase64Policy))`, where
`kSigning=HMAC(HMAC(HMAC(HMAC("AWS4"+secret,date),region),"s3"),"aws4_request")`.
Reuse deriveSignatureKey; zeroize it and decoded signature/HMAC buffers.
Require exactly five nonempty credential components, date YYYYMMDD matching
x-amz-date YYYYMMDDTHHMMSSZ, service s3, terminator aws4_request, algorithm
AWS4-HMAC-SHA256 and a 64-hex-character signature decoded to 32 bytes. Compare
with hmac.Equal; don't re-encode JSON before verifying. Region is nonempty
signed scope, not automatically forced to backend region (different backend
region is valid). Reject future signing timestamps beyond clock skew; an older
signature remains valid until policy deadline, without the header-auth age
window or X-Amz-Expires rules. At now≥deadline reject, with no expiry grace;
session expiry may shorten deadline. Signature/policy is reusable until expiry,
not a one-time upload token [3,4,15].

Rationale: strict coverage and one canonical interpretation prevent a valid
policy signature from authorizing unsigned fields or parser differentials;
preserving literal policy bytes ensures SDK interoperability [3,4].

### 3.3 Configured session credentials

```go
// Add to config.GatewayCredential, retaining all existing fields.
SessionToken    string     `yaml:"session_token"`
SessionTokenEnv string     `yaml:"session_token_env"`
ExpiresAt       *time.Time `yaml:"expires_at"`
// Add to api.Credential; snapshot-owned immutable data, cloned deadline.
SessionToken string
ExpiresAt    *time.Time
func validateSessionCredentialAt(c Credential, supplied string, now time.Time) error
func sessionTokenFromRequest(r *http.Request) (string, error)
```

```yaml
auth:
  credentials:
    - access_key: BROWSERSESSION
      secret_key_env: GATEWAY_SESSION_SECRET
      session_token_env: GATEWAY_SESSION_TOKEN
      expires_at: "2026-12-01T12:00:00Z"
      buckets: [attachments]
      permissions: rw
backend:
  session_token: ""  # optional BACKEND_SESSION_TOKEN; independent identity
```

Token/env omitted→static credential; static entry must not have expires_at.
Nonempty token or token env requires expires_at; require GMT valid deadline,
token 1..16 KiB, no NUL/CR/LF, env source resolves nonempty or configuration
fails (no fallback to inline on a specified missing env). Reject both inline
and env token sources. Clone time pointer during ResolvedCredentials/snapshot
construction/Lookup. Permit valid but already expired entries in config so
rotation/restart is possible; runtime always rejects expired entries.
Session token equality is constant-time (compare SHA256 digests and lengths),
deadline is exclusive, missing/wrong/extra static-token→403 InvalidToken,
expired configured session→403 ExpiredToken. No raw token in logs/errors.

Apply token/deadline validation on POST **and ordinary SigV4 header/presigned
requests**, not just POST. Exactly one token in selected transport; reject
duplicate/query+header token, require header token be in SignedHeaders,
presigned token in signed canonical query and POST token in exact condition.
Session credentials presented with SigV2→403 InvalidToken; no session bypass.
Credential replacement retains existing atomic snapshot behavior [5,6,10].

Env/Helm: `GW_CRED_<i>_SESSION_TOKEN` (LookupEnv supports clearing),
`GW_CRED_<i>_EXPIRES_AT` (strict timestamp); honor existing indexed access-key
matching and credentials-file/YAML behavior. Add Helm credential `sessionToken`
configValue with valueFrom and optional `expiresAt` string; existing mounted
credentials secret accepts YAML fields above without another mount. Backend
adds `SessionToken string yaml:"session_token" env:"BACKEND_SESSION_TOKEN"`,
Helm config.backend.sessionToken configValue, empty by default. GetClient uses
backend token; preserve GetClientWithCredentials(accessKey,secretKey) as a
tokenless compatibility wrapper and add:

```go
func (f *ClientFactory) GetClientWithSessionCredentials(accessKey, secretKey, token string) (Client, error)
```

Never send gateway token to backend. Backend credentials/token, trusted proxy
CIDRs, backend TLS/endpoints are construction-time; reject changes in both
validateReloadSafety and ApplyConfigChanges before any live mutation. Gateway
session credential rotation remains hot-reloadable. Clear temporary token
references alongside secret references, but do not claim Go immutable string
memory is reliably zeroized. No logging of config credential structs [5,10].

Rationale: configured session identity extends the existing snapshot boundary
without turning AWS STS responses or arbitrary request tokens into authority.

### 3.4 Bounded file validation and plaintext checksums

```go
type postChecksum struct { algorithm, value, md5 string }
type postValidatedFile struct {
    body verifiedAWSBody
    length int64
    md5Hex string
    responseChecksums map[string]string
}
func parsePostChecksum(fields map[string]string) (postChecksum, error)
func spoolPostFile(ctx context.Context, u *postUpload, manager SpoolManager, limit int64) (postValidatedFile, error)
```

Acquire reservation for zero bytes after authz; Grow actual file bytes **before**
each 32 KiB disk write. Use the configured shared spool directory, 0600 file,
cleanup-on-all-errors, context cancellation and existing idempotent
verifiedAWSFile lifecycle. Spool only plaintext file bytes; no unconstrained
io.ReadAll. Max bound errors use an explicit sentinel, never LimitReader's
fake EOF. After EOF validate complete MIME/overhead and every lower bound,
then rewind. Reject incomplete HTTP body. Recheck deadline before write and
do not report success until backend completion. Cleanup disk/quota even on
backend failure or response-write failure.

Support Content-MD5 and one additional checksum: CRC32 (IEEE), CRC32C
(Castagnoli), SHA1, SHA256. `x-amz-checksum-algorithm` must match exactly one
checksum field; checksum without algorithm infers its algorithm; multiple
additional algorithms or mismatched/absent selected field→400 InvalidRequest.
Strict padded base64 and decoded digest sizes (4/4/20/32; MD5=16) before
reading. CRC digest is big-endian bytes then base64. Verify plaintext while
spooling, constant-time compare; failure→400 BadDigest. Unsupported CRC64NVME
or unknown algorithm→501, not a silent checksum omission. Compute MD5 for
client ETag interoperability, **not authorization or AEAD integrity** [2,11].

POST encrypted non-SSE-C response ETag is quoted computed plaintext MD5;
pass unquoted md5Hex as internal engine metadata `ETag` so existing original
ETag stamping works, never accept form `ETag`. Plaintext/bypass POST preserves
backend ETag. SSE-C response ETag remains backend opaque ETag (no MD5 promise);
do not set original ETag input on that path. Buffered crypto computes its own
original MD5 (`internal/crypto/engine.go:598-599`); do not remove/mutate sealed
metadata after Encrypt. Instead the shared response projector selects backend
ETag whenever backend SSE-C headers declare a customer algorithm, ahead of any
original-ETag metadata. Apply this on POST and subsequent GET/HEAD/range, so
buffered and chunked formats agree. Additional plaintext checksum
response headers acknowledge validated uploaded bytes. Never forward those
plaintext digests as ciphertext backend checksums/Content-MD5; backend SDK
computes its own ciphertext MD5 where applicable. No new persisted checksum
metadata or GetObject checksum guarantee.

For POST only, bound memory for engines that buffer whole input. Introduce an
additive write-profile interface, not a change to EncryptionEngine:

```go
type EncryptionWriteProfile struct { StreamsPlaintext bool }
// Invariants: immutable/thread-safe; no I/O, metadata or secret retention;
// no ctx needed; value copied to caller; API treats missing profiler as buffered.
type EncryptionWriteProfiler interface { WriteProfile() EncryptionWriteProfile }
func (e *engine) WriteProfile() EncryptionWriteProfile
func (PassthroughEngine) WriteProfile() EncryptionWriteProfile
```

Implement in `internal/crypto/write_profile.go`: engine profile reports its
immutable chunkedMode; PassthroughEngine reports true; an unknown engine
without the optional interface is conservatively buffered. When false reject
POST plaintext length over effectiveMaxPartBuffer **before** Encrypt; return
413 EntityTooLarge. Chunked metadata-overflow fallback is streaming, not
buffered (`internal/crypto/engine.go:1477-1561`), and remains supported up to
file limits. No crypto format change or new cap on ordinary PUT. Assert profile
accuracy and branch gating in tests; no concrete engine assertions in API.

After encryption, POST spools its ciphertext into a second 0600 seekable file
using the same aggregate quota, before any backend write. The plaintext
reservation remains held until cleanup. This gives exact ciphertext length and
rewindability even for streaming metadata-prefix fallback. Bound ciphertext to
5 GiB (backend single-PUT limit), charge every ciphertext byte and reject cap/
aggregate failure before cache invalidation/backend writes. This intentionally
uses roughly plaintext+ciphertext temporary disk; document it. Do not infer
fallback ciphertext length from the plain chunk formula. Ordinary PUT keeps its
existing bounded-memory buffering/streaming choice; POST uses disk, not an
additional NewSeekableBody memory copy.

```go
func spoolPostCiphertext(ctx context.Context, reader io.Reader, manager SpoolManager) (verifiedAWSBody, error)
```

Do not advertise unlimited memory merely because plaintext was disk-spooled.

Rationale: final plaintext size/checksum/framing is knowable before write only
after complete file ingestion; bounded disk storage makes that ordering safe.

### 3.5 Shared writes and additive backend options

```go
// Invariants: caller owns Body; synchronous methods never retain readers,
// metadata, SSE keys or options; nil ctx/body invalid; no key logging.
type ObjectPutOptions struct {
    StorageClass string
    WebsiteRedirectLocation string
    SSE *SSEOptions
}
type SSEOptions struct {
    Algorithm, KMSKeyID, KMSContext string
    BucketKeyEnabled *bool
    Customer *SSECustomerKey
}
type SSECustomerKey struct { Key []byte; MD5 string }
func (k *SSECustomerKey) Close() // zeroizes Key; idempotent after I/O ends
type ObjectReadOptions struct { Customer *SSECustomerKey }
type PutObjectResult struct {
    ETag, VersionID string
    Headers map[string]string // closed non-secret response allowlist
}
// Additive; legacy Client and all existing constructors/signatures unchanged.
type AdvancedObjectClient interface {
    Client
    PutObjectWithOptions(ctx context.Context, bucket, key string, body io.Reader,
        metadata map[string]string, length *int64, tags string, lock *ObjectLockInput,
        acl, grantFullControl, grantRead, grantReadACP, grantWriteACP string,
        options ObjectPutOptions) (PutObjectResult, error)
    GetObjectWithOptions(ctx context.Context, bucket, key string, versionID, rangeHeader *string,
        options ObjectReadOptions) (io.ReadCloser, map[string]string, error)
    HeadObjectWithOptions(ctx context.Context, bucket, key string, versionID *string,
        options ObjectReadOptions) (map[string]string, error)
}
```

Implement on SDK s3Client; legacy PutObject delegates with zero options and
returns result.ETag; legacy Get/Head delegate with zero read options. SDK
mapping: StorageClass, WebsiteRedirectLocation, ServerSideEncryption,
SSEKMSKeyId, SSEKMSEncryptionContext, BucketKeyEnabled, SSECustomerAlgorithm
AES256/SSECustomerKey(base64 of raw32)/SSECustomerKeyMD5. Return only ETag,
VersionId, Expiration, StorageClass if returned, ServerSideEncryption,
SSEKMSKeyId, BucketKeyEnabled, SSECustomerAlgorithm/MD5. No key in result/meta.
Preserve existing TLS transport, retryer, metadata normalization and
ciphertext seek-length/MD5 serialization. SDK read options supply SSE-C to
every read; normalize non-secret SSE result headers into metadata.

GCS/Azure advanced methods preserve their current metadata normalization and
validation, delegate no-SSE/default-or-STANDARD storage requests through inner
AdvancedObjectClient, and explicitly return s3.ErrNotImplemented before
body consumption for nonempty SSE, non-STANDARD storage or website redirect.
No pretending AWS KMS/SSE-C semantics map to native Google/Azure. ProxyClient
gets advanced stub methods returning wrapped ErrNotImplemented; never forward
the browser form or gateway credentials. Legacy mocks need not implement the
new interface. Common write helper falls back to legacy Client only for zero
options (including ordinary PUT); never fall back for unsupported options.

```go
type objectWriteInput struct {
    Bucket, Key, Operation string
    Body io.Reader
    PlainLength int64
    HaveLength bool
    Metadata writeMetadata
    PlainETag string
    Tags, ACL, GrantFullControl, GrantRead, GrantReadACP, GrantWriteACP string
    Lock *s3.ObjectLockInput
    Options s3.ObjectPutOptions
    Deadline time.Time // zero for ordinary PUT; exclusive for POST
}
type objectWriteResult struct { Backend s3.PutObjectResult; ClientETag string; PlainSize int64 }
func (h *Handler) putObjectData(ctx context.Context, client s3.Client, in objectWriteInput) (objectWriteResult, error)
func parsePutObjectOptions(r *http.Request) (s3.ObjectPutOptions, error)
func projectObjectWriteHeaders(result objectWriteResult, checksums map[string]string) http.Header
func (h *Handler) writePostSuccess(w http.ResponseWriter, r *http.Request, u *postUpload, result objectWriteResult, checksums map[string]string) error
```

Extract data-write logic from handlePutObject into putObjectData. Typed
metadata input uses parseWriteMetadata/buildPersistPlan; copy dispatch remains
in PUT handler. Keep ordinary streaming verification before data helper, fixed
S3 error writer at HTTP boundary, exact encrypted length, same cache/size/audit
semantics and existing single-attempt unknown-length/backfill behavior.
No response writes inside helper. Ciphertext spool is helper-owned: immediately
defer its Close after creation and hold it until backend finishes; do not store
it in postUpload or return it through objectWriteResult. A zero-length POST still
gets an exact length and complete ciphertext (including authenticated terminal).
Operation distinguishes PostObject metrics,
not backend SDK verb (still PutObject). POST supplies known plaintext length,
spools exact ciphertext (§3.4), skips memory buffering and cannot run unknown-size
copy-to-self. Use typed backend/crypto error
classification instead of returning already-written HTTP errors. For POST
validate all options before encryption/cache invalidation/backend acquisition.
Capture encryption engine/write profile once after complete file validation;
ciphertext cap/quota/EOF/seek errors leave cache/destination unchanged. Recheck
in.Deadline after ciphertext preparation, immediately before cache invalidation/
backend PutObject (not just before Encrypt). No rollback is promised if deadline
passes during an already-authorized backend write.
New response headers (including version) are projected in object_response.go
and written via writeObjectHeaders; retain production drift guards [7].

Tagging: strict bounded XML `<Tagging><TagSet><Tag><Key>…</Key><Value>…</Value></Tag></TagSet></Tagging>`
with optional S3 namespace; no DTD/directives/unknown nodes/duplicate key/value
nodes or trailing content. 0..10 unique keys, key 1..128/value 0..256 Unicode
codepoints, valid UTF-8, reject aws: key prefix; AWS tag charset letters/digits,
whitespace and `+ - = . _ : / @`. Convert to url.Values.Encode and pass inline
tags; do not use the narrower legacy validateTags function to reject otherwise
valid POST Unicode tags. No post-write PutObjectTagging fallback (can leave a
partially applied upload); backend errors remain errors [12].

```go
func parsePostTagging(value string) (string, error)
func parsePostOptions(fields map[string]string) (s3.ObjectPutOptions, string, string, error)
```

parsePostOptions returns options/tags/ACL; accept canned ACL values private,
public-read, public-read-write, authenticated-read, aws-exec-read,
bucket-owner-read, bucket-owner-full-control. Empty acl uses backend default
private; signed unsupported acl is 400 InvalidArgument. No grant form fields.
Storage classes: STANDARD (default absent), REDUCED_REDUNDANCY, STANDARD_IA,
ONEZONE_IA, INTELLIGENT_TIERING, GLACIER, DEEP_ARCHIVE, GLACIER_IR; unknown
class→400 InvalidArgument, EXPRESS_ONEZONE→501. Provider acceptance/billing
remains backend responsibility, not silent STANDARD fallback.
Website redirect accepts leading `/` or absolute http(s), max2KiB; validate
no userinfo/control chars; forward typed property and project on reads.

`parsePutObjectOptions` is implemented in sse.go: ordinary non-copy PutObject
maps signed header storage/website/SSE options through the same validation,
with no interpolation or POST policy. Preserve existing inline tags/grants/
Object Lock handling. Require SigV4-signed SSE-C triplet, trusted ingress and
verified HTTPS backend; unknown optional advanced mode never falls back.
Ordinary PUT success keeps legacy ETag unless SSE-C uses backend opaque ETag;
no unconditional plaintext checksum/ETag change. Mixed copy+SSE-C is the explicit
501 non-goal. This gives SSE-C uploads an ordinary PUT lifecycle without
duplicating another option parser.

Unknown/empty explicit SSE values must be distinguished from absent fields;
SSEOptions is nil only when no SSE form/header fields were submitted. Empty
KMS/customer/context option fields are invalid, not silently absent. Explicit
STANDARD storage can normalize to zero option after validation.

Rationale: a typed additive interface avoids breaking all backend/test clients
while ensuring nonzero options cannot be silently lost. Shared write ownership
avoids divergent crypto/metadata contracts across PUT and POST [5,7].

### 3.6 SSE semantics, reads, caching and transport

| Submitted mode | Validation / backend effect |
|---|---|
| No SSE fields | Existing gateway encryption and backend defaults unchanged |
| AES256 | SSE-S3; no KMS/customer/bucket-key fields |
| aws:kms | SSE-KMS; optional nonempty KMS key ID, strict base64 UTF-8 JSON string:string context (duplicate keys rejected), optional `true`/`false` BucketKeyEnabled |
| SSE-C customer triplet | All required, algorithm AES256, strict base64 raw32 key and base64 raw16 MD5 matching key; no SSE-S3/KMS fields |
| Mixed/incomplete/invalid values | 400 InvalidArgument before encryption or backend |
| aws:kms:dsse / unknown SSE scheme | 501 NotImplemented before encryption or backend |

SSE is **additional backend encryption of gateway ciphertext**. Never replace
per-bucket gateway encryption with the submitted SSE mode; KMS keys are
backend keys, not gateway KeyManager key IDs. Backend must authorize KMS usage
and return its actual errors/headers. Existing backend SSE defaults may apply
with no fields [2,13].

```go
func parseSSEOptions(fields map[string]string) (*s3.SSEOptions, error)
func parseSSECustomerHeaders(h http.Header) (*s3.SSECustomerKey, error)
func (e *IPExtractor) IsTrustedPeer(r *http.Request) bool
func (e *IPExtractor) IsHTTPSRequest(r *http.Request) bool
// WithSSECustomerReadClient targets exactly bucket/key and never global state.
func WithSSECustomerReadClient(client Client, bucket, key string, customer *SSECustomerKey) (Client, error)
func (h *Handler) objectReadClient(r *http.Request, client s3.Client, bucket, key string) (s3.Client, func(), error)
```

SSE-C ingress is secure only for r.TLS != nil OR trusted **immediate** RemoteAddr
peer plus exactly one X-Forwarded-Proto value `https` (case-insensitive), no
commas/control chars; ignore Forwarded/X-Forwarded-SSL/ForceHTTPS. Default CIDR
list empty→no forwarded trust. IsTrustedPeer uses existing private CIDR matcher,
not client IP from XFF. Reject unsupported/conflicting forwarding chain. Proxy
must overwrite XFP and gateway port must not be directly reachable. Underlying
proxy→gateway hop must be protected by the operator (TLS recommended); plan
accepts operator-trusted termination, not encryption of a plaintext hop.
Use per-handler immutable extractor from construction config, not global mutable
test extractor for this security decision. Require backend ResolveEndpoint
scheme https and TLS.InsecureSkipVerify=false; TLS trust failures must surface.
Use the same rule for SSE-C POST/PUT/GET/HEAD and reject before key backend I/O.
Use r.Host plus the same trusted scheme logic for response Location; do not
trust arbitrary X-Forwarded-Host [9,13].

GET/HEAD customer headers must be exactly one each and signed in ordinary
SigV4 SignedHeaders; for presigned GET/HEAD allow exact SSE-C triplet in signed
query instead, reject header+query ambiguity and scrub secrets in telemetry.
For a primary object GET/HEAD, after acquiring base backend client, parse
customer input once, make a request-local Client decorator embedding base,
override GetObject/HeadObject to call advanced methods only for identical
bucket/key; delegate unrelated manifest/object accesses without customer key.
The same wrapped client must go to planning, terminal preflight, optimized
range, buffered/full reads and HEAD size resolution. No context key that could
leak SSE key into arbitrary backend operations; no mutation of shared client.
Cleanup zeroizes mutable raw key after synchronous serving completes. Keep
SDK base64/string references only during request; no reliable string-zeroization
claim. Missing/wrong key errors come from backend and cannot fall through to
legacy decrypt/cache. Reject SSE-C copy/MPU headers at handler entry 501.
Cover destination triplet and source
`x-amz-copy-source-server-side-encryption-customer-*`; GET/HEAD accept only
customer triplet, not SSE-S3/KMS write fields. No key material is sourced from
object metadata or carried to unrelated operations.

Cache policy: incoming SSE-C material disables cache lookup/capture; backend
metadata declaring SSECustomerAlgorithm disables capture even with absent
request keys. Existing cached hits still require backend HEAD and reject on
key-required denial; if HEAD detects SSE-C discard/skip cache rather than replay.
Set `Cache-Control: no-store` on all SSE-C GET/HEAD/POST/PUT responses as the
last projection step, overriding stored standard headers and GET overrides. Ensure
ordinary plaintext/encrypted cache behavior is unchanged. Skip automatic
gateway key-rotation/re-encryption for SSE-C object; no write-back without
explicit supplied key/options. Do not persist customer key, key-derived
fingerprint, token or POST policy into objectmeta/crypto envelopes/Valkey [13].

GET/HEAD use existing projector extended with non-secret SSE allowlist,
website redirect and storage fields. Never emit customer key or KMS context.
Preserve ETag/version/range/AEAD tag verification and authenticated terminal
checks. SSE-C cannot turn backend failure into a crypto fallback/success [7].

Rationale: the backend's customer-key requirement is a second access boundary;
a plaintext cache or unkeyed preflight must not bypass it. Request-local
decoration covers nested reads without rewriting every legacy Client method.

### 3.7 Success responses, CORS, errors and telemetry

```go
type postResponse struct {
    XMLName xml.Name `xml:"PostResponse"`
    XMLNS string `xml:"xmlns,attr"`
    Location, Bucket, Key, ETag string
}
func postObjectLocation(r *http.Request, bucket, key string, secure bool) (string, error)
func parsePostSuccess(fields map[string]string) (int, *url.URL, error)
func postRedirectLocation(target *url.URL, bucket, key, etag string) string
```

| Fields | Success contract |
|---|---|
| absent/invalid success_action_status | 204 empty body (after signed condition validation) |
| status 200 or 204 | exact status, empty body |
| status 201 | XML UTF-8 PostResponse namespace `http://s3.amazonaws.com/doc/2006-03-01/`, Location/Bucket/Key/quoted ETag; correct XML escaping |
| valid success_action_redirect or legacy redirect | 303 empty body; Location target plus URL-encoded bucket/key/etag query values; preserve unrelated existing query/fragment, replace those three selectors |

Both redirect aliases present→400 InvalidArgument, never ambiguous precedence.
Only absolute http(s), nonempty host, no userinfo/control chars, max2048 bytes;
invalid redirect is treated absent as AWS specifies, while policy must still
cover/match the submitted literal value. Validate/clone target before write;
gateway never fetches target, resolves DNS or forwards authentication/keys.
Empty/invalid URL→status path; valid redirect outranks status. URL must be
covered by exact/prefix policy; recommend exact redirects. Object Location is
external request host and path-style bucket/key encoded as separate components,
preserving key slashes/dots; use url.URL escaping, not path.Join/Clean. Host
must parse as a valid authority with no controls/userinfo; absent invalid host
returns 400 before write. Auth-bearing URL components are never appended [2].

Project ETag, x-amz-version-id, x-amz-expiration and actual non-secret SSE
headers from typed backend result, plus computed additional checksum headers.
Do not emit object Content-Length as response length; XML length vs file
length are different. Response header owner stays object_response.go.

CORS: after GH-322, preserve Recovery→CORSMiddleware→Auth→Authorization→other
middleware→router order and its single CORSStore. Use `cors.mode: gateway` in
browser fixtures, shared Valkey and allowed POST rule; explicitly expose ETag,
x-amz-version-id and checksum/SSE headers needed by test. Allowed Origin gets
CORS on 200/201/204/303 and 4xx/5xx; unmatched origin does **not** reject a
valid signed non-browser upload, only suppresses browser-readable response.
Preflights remain narrow unauthenticated OPTIONS; no public POST exception.
Store unavailable actual-response behavior remains GH-322's suppress-CORS
contract; do not silently fall back or introduce another backend CORS lookup.
Document default passthrough does not guarantee local POST response CORS [8].

| Failure | HTTP / S3 XML code (fixed message) |
|---|---|
| missing policy/auth fields | 403 AccessDenied, `Missing or invalid credentials in request.` |
| unknown access key | 403 InvalidAccessKeyId, existing fixed message |
| invalid algorithm/scope/signature/date binding | 403 SignatureDoesNotMatch, existing fixed message |
| future date beyond skew | 403 RequestTimeTooSkewed, existing fixed message |
| expired policy / expired session | 403 AccessDenied `Request has expired.` / 403 ExpiredToken `The provided token has expired.` |
| missing/wrong/unexpected session token | 403 InvalidToken `The provided token is invalid.` |
| unmet/absent coverage/bucket/key condition | 403 AccessDenied `The request does not satisfy the POST policy.` |
| malformed policy/base64/JSON/operator/range | 400 InvalidArgument `Invalid POST policy.` |
| duplicate/malformed MIME/mixed auth | 400 InvalidRequest `Invalid POST form.` |
| truncated HTTP/MIME body | 400 IncompleteBody `The request body is incomplete.` |
| over signed/server/file/form limit | 413 EntityTooLarge `The request exceeds the permitted payload size.` |
| below signed file minimum | 400 EntityTooSmall `The uploaded object is smaller than the permitted size.` |
| malformed/invalid options/checksum encoding | 400 InvalidArgument or InvalidRequest as specified above; no submitted value echo |
| malformed tagging XML / duplicate/invalid tags | 400 MalformedXML / InvalidTag, fixed messages |
| plaintext checksum mismatch | 400 BadDigest `The provided checksum does not match the uploaded object.` |
| insecure SSE-C transport | 400 InvalidRequest `SSE-C requires a secure transport.` |
| unsupported form field/mode/backend capability | 501 NotImplemented `The requested POST option is not supported.` |
| spool aggregate exhausted / disk error | 503 SlowDown existing message / 500 InternalError fixed message |
| gateway scope/rw denial, backend failure | existing authorization/TranslateError meanings; no rewrite as crypto error |

Define errors.Is-compatible sentinel errors in post_errors.go and map centrally
through classifyPostError; use existing spool/auth errors where semantics match.
Also define ErrPostIncompleteBody, ErrPostEntityTooLarge, ErrPostInvalidOption,
ErrPostMalformedXML, ErrPostInvalidTag and ErrSSEInsecureTransport in that file
with fixed strings for their classes. parsers return typed classes, not raw
XML/JSON/field errors. For ordinary PUT SSE validation use the same fixed
option-error mapping; session sentinels may live in session_auth.go so Phase A
compiles without post_errors.go.
Client cancellation cleans resources; if writer still usable use fixed
IncompleteBody/RequestTimeout (408) for deadline exceeded; never backend write.

```go
var (
    ErrPostPolicyMalformed = errors.New("malformed POST policy")
    ErrPostPolicyDenied = errors.New("POST policy denied")
    ErrPostFormMalformed = errors.New("malformed POST form")
    ErrPostEntityTooSmall = errors.New("POST file below policy minimum")
    ErrPostBadDigest = errors.New("POST checksum mismatch")
    ErrPostUnsupported = errors.New("unsupported POST option")
    ErrInvalidToken = errors.New("invalid session token")
    ErrExpiredToken = errors.New("expired session token")
)
func classifyPostError(err error, resource string) *S3Error
```

Metrics: PostObject semantic request/status and S3 operation count, plaintext
file bytes exactly once (exclude MIME overhead and double-counted spool reads),
existing spool gauges/rejections, encryption/audit once; backend retries still
PutObject. Auth parsing errors use existing auth audit; no policy/token/key
values in metric labels or logs. SSE-C key + key MD5, authorization, token,
signature and policy query/body values get mandatory telemetry redaction even
when operator disables ordinary redaction; never log form bodies/maps. Extend
logging/tracing/query-redaction for session/SSE-C headers/queries; make existing
ordinary non-secret redaction configuration continue to work. Error strings
must not interpolate fields/options. Avoid backend SDK debug body/header logging.

Rationale: HTTP response serialization is independent of data writing, and CORS
is a browser read policy, not upload authorization. Explicit errors preserve
SDK diagnostics without exposing signature/key material [2,8,9].

## 4. Work Breakdown

Each item is one file edit/new file unless explicitly identified as a generated
fixture manifest. Work in phase order; no production implementation during
planning. After GH-322 lands, retain these normative contracts and relocate
insertion points to its current files without changing scope.

### Phase A — Dependency, configuration and session identity

- **A1. `docs/adr/0020-browser-post-policy-uploads.md` (new):** record §§3.1–3.7,
  GH-322/ADR0019 prerequisite, gateway/backend encryption distinction, trusted
  proxy assumption, reusable policies, temporary plaintext and exclusions.
  ADR0019 is reserved by GH-322; do not collide with it.
- **A2. `internal/config/config.go` (edit):** add GatewayCredential token/env/
  deadline and BackendConfig token fields as §3.3; resolve/env/index loading,
  deadline cloning, validation and construction-time reload rejection.
- **A3. `internal/config/session_config_test.go` (new):** table tests for YAML,
  credentials file/env/indexed precedence, missing env, invalid pair/deadline,
  expired-but-valid config and cloned deadline; exact test names in §6.
- **A4. `internal/api/credential_store.go` (edit):** copy session token/deadline
  into immutable snapshot and clone deadline on Lookup; preserve bucket policy.
- **A5. `internal/api/session_auth.go` (new):** validateSessionCredentialAt and
  sessionTokenFromRequest, constant-time validation, selected transport and
  required signed-token checks; never mutate signed request fields.
- **A6. `internal/api/session_auth_test.go` (new):** exact token/deadline,
  SignedHeaders/query/POST and atomic snapshot/rotation matrix.
- **A7. `internal/api/auth_middleware.go` (edit):** apply session validator to
  ordinary SigV4 branches after signature validation and before downstream;
  deny session SigV2. POST branch is added in C6, same principal keys.
- **A8. `internal/api/handlers.go` (edit):** extend classifyAuthError with
  InvalidToken/ExpiredToken fixed errors; no change to existing expiry codes.
- **A9. `cmd/server/main.go` (edit):** prevalidate restart-only backend/trust
  changes before any live mutation; clear temporary session references in
  credential handling; retain gateway credential reload and GH-322 wiring.
- **A10. `cmd/server/session_reload_test.go` (new):** successful rotation,
  invalid replacement retention and rejected construction-time change before
  credential/spool/policy mutation.

### Phase B — Backend advanced objects and secure read boundary

Phase B depends on A2. No s3.Client signature change; legacy tests keep compiling.

- **B1. `internal/s3/object_options.go` (new):** exported types and
  AdvancedObjectClient/SSECustomerKey.Close declarations exactly §3.5.
- **B2. `internal/s3/client.go` (edit):** advanced SDK Put/Get/Head, legacy
  zero-option wrappers, result allowlist, optional backend session credentials
  factory; preserve ciphertext MD5/length/retry/transport behavior.
- **B3. `internal/s3/gcs_client.go` (edit):** advanced delegation with metadata
  lowercasing; explicit unsupported-mode errors before I/O as §3.5.
- **B4. `internal/s3/azure_client.go` (edit):** advanced delegation plus existing
  metadata validation; unsupported-mode errors before body consumption.
- **B5. `internal/s3/proxy_client.go` (edit):** advanced fixed unsupported stubs;
  do not enable ForwardRequest for POST.
- **B6. `internal/s3/customer_read_client.go` (new):** request-local decorator
  `WithSSECustomerReadClient` embedding Client, exact-target Get/Head overrides,
  advanced-interface capability denial, no key retention beyond request.
- **B7. `internal/s3/object_options_test.go` (new):** real httptest SDK wire
  requests for storage/SSE/tokens, exact ciphertext body length, results/version,
  zero options, adapters and decorator target isolation/zeroization.
- **B8. `internal/util/ip.go` (edit):** IsTrustedPeer/IsHTTPSRequest using
  existing CIDRs, immediate RemoteAddr and exact single XFP; no global policy.
- **B9. `internal/util/https_test.go` (new):** TLS, trusted/untrusted IPv4/IPv6,
  duplicate/comma/empty/spoofed XFP, XFF/ForceHTTPS non-authority cases.
- **B10. `internal/api/sse.go` (new):** parseSSEOptions/customer headers and
  parsePutObjectOptions/objectReadClient; immutable per-handler transport policy and typed backend
  HTTPS validation, source transport selection and signed header/query checks.
- **B11. `internal/api/sse_test.go` (new):** mode/context/key/MD5 matrix,
  secure transport, read preflight/range isolation, bad/missing key, no rotation.
- **B12. `internal/api/handlers.go` (edit):** construct per-handler trusted
  extractor; use objectReadClient with deferred cleanup before cache lookup
  in GetObject and in HeadObject; reject unsupported SSE-C copy/MPU at entry.
- **B13. `internal/api/object_stream.go` (edit):** CacheEligible false for
  request/backend SSE-C, skip cached SSE-C replay, skip automatic re-encryption,
  reuse decorated client through all size/terminal/body reads.
- **B14. `internal/api/object_response.go` (edit):** non-secret SSE/storage/
  website headers and no-store projection; all version writes remain here.

### Phase C — POST parser, policy and authentication

Phase C depends on A/B for session/options. Auth never spools unauthorised files.

- **C1. `internal/api/post_errors.go` (new):** sentinel errors and
  classifyPostError table (§3.7); fixed resource/message handling.
- **C2. `internal/api/post_policy.go` (new):** strict JSON token parser,
  postPolicy/postCondition, original-policy HMAC and temporal/token validation,
  exact/prefix/range AND and full field coverage (§3.2).
- **C3. `internal/api/post_policy_test.go` (new):** AWS vector, SDK-style
  policies, whitespace preservation, duplicate JSON, coverage, filename,
  date/scope and boundary-time table plus FuzzPostPolicy.
- **C4. `internal/api/post_form.go` (new):** postUpload/context lifecycle,
  isPostObjectRequest, parsePostUpload, postWireReader, filename expansion,
  NextRawPart strict framing/field caps, no body-map telemetry.
- **C5. `internal/api/post_form_test.go` (new):** all parser/routing/filename/
  duplicate/UTF8/truncation/file-last/bounded-overhead cases and FuzzPostForm.
- **C6. `internal/api/auth_middleware.go` (edit):** exact form branch, reject
  mixed auth, bounded parse→lookup→policy/session→attach principal/context→next,
  defer cleanup, preserve existing signatures and options; record limit snapshot.
- **C7. `internal/api/auth_middleware_test.go` (edit):** GH353 signed form,
  rejected form doesn't call downstream, fields buffered but no file drain,
  existing SigV4/V2/preflight unaffected; use real next-handler counters.
- **C8. `internal/api/authorization.go` (edit):** PostObject write contract,
  require authenticated parsed context in production branch, exact bucket scope
  and rw/global intersection; unrelated POST/query shapes remain unknown.
- **C9. `internal/api/authorization_test.go` (edit):** replace bare POST unknown
  assumption with valid multipart predicate only; retain malformed/bare no-type
  POST denial, scope/readonly/no principal/mixed selectors regression table.
- **C10. `internal/api/s3_instrumentation.go` (edit):** PostObject name from
  exact predicate, skip raw MIME counting; count validated file bytes once on
  consumption with existing metrics (spool was before router instrumentation).
- **C11. `internal/api/route_parity_test.go` (edit):** explicit PostObject
  method/path/content-type fixture and independent write permission oracle;
  negative ?delete/uploads/uploadId/non-form shapes; route matcher same predicate.

### Phase D — File, broader options and shared object writes

Phase D depends on B/C; do not create parallel crypto metadata implementations.

- **D1. `internal/api/post_checksum.go` (new):** postChecksum/validated file,
  parsePostChecksum and streaming digest comparison per §3.4; import standard
  hash/CRC libs, mark MD5/SHA1 protocol interoperability not security.
- **D2. `internal/api/post_spool.go` (new):** spoolPostFile with shared quota,
  0600 temp lifecycle, exact size/framing/overhead/HTTP EOF, cancellation,
  rewind, checksums and early max+1 rejection before backend.
- **D3. `internal/api/post_spool_test.go` (new):** below/at/above bounds,
  overhead-vs-file, chunked body, spool disk/seek/create/quota failure injection,
  resource cleanup, cancellation and checksum known vectors.
- **D4. `internal/api/post_options.go` (new):** parsePostOptions/tagging,
  supported field table, ACL/storage/website/SSE options and strict XML/tag
  conversion; zeroize key on rejected option combination.
- **D5. `internal/api/post_options_test.go` (new):** field/ACL/storage/tag/SSE
  tables, Unicode tags, unknown field fail-closed, MD5/plaintext separation.
- **D6. `internal/api/object_put.go` (new):** objectWriteInput/result,
  putObjectData extraction with typed errors, exact encrypted length,
  zero-option legacy fallback and nonzero advanced requirement; operation
  metric/audit accounting; bounded POST buffered-engine guard, helper-owned
  ciphertext spool and post-preparation exclusive deadline recheck.
- **D7. `internal/api/handlers.go` (edit):** retain copy dispatch, parsing and
  ordinary streaming verification in PUT wrapper; call common data helper,
  serialize existing PUT 200/ETag semantics; add PostObject route after delete.
- **D8. `internal/api/object_put_test.go` (new):** PUT characterization
  chunked/buffered/metadata/pass-through/zero/unknown/retry/backfill and no
  duplicated audit/size/metrics; POST nonzero-options requires capability.
- **D9. `internal/api/spool_manager.go` (edit):** classify exact plain form
  PostObject as global-budget payload where applicable, retain conservative
  control-route cap for all other POST shapes; actual file limiter also intersects
  signed bound; no silent conversion to fake EOF.
- **D10. `internal/api/spool_limits_regression_test.go` (edit):** global/part/
  form/control selector table and once-captured live limits under reload.
- **D11. `internal/api/post_object.go` (new):** handlePostObject validates
  context/principal, converts metadata with parseWriteMetadata, spools,
  validates final/deadline, obtains client only then, calls common write and
  response owner; cleans file/key resources, fixed errors before success.
- **D12. `internal/api/post_object_test.go` (new):** real HTTP chain with
  counting backend, complete positive matrix and negative no-write/cache/KMS/
  version-preservation assertions. Include SSE and GH-322 CORS errors.
- **D13. `internal/crypto/write_profile.go` (new):** additive
  EncryptionWriteProfiler/Profile with engine chunkedMode and passthrough
  implementations; immutable read-only method, no format/KDF change.
- **D14. `internal/crypto/write_profile_test.go` (new):**
  `TestGH353EncryptionWriteProfile_StreamingAndBuffered` validates real
  engines and streaming metadata fallback; API test treats missing profile
  conservatively without concrete engine assertions.
- **D15. `internal/api/post_spool.go` (edit):** implement
  spoolPostCiphertext per §3.4; exact size/retry source, aggregate charging and
  cleanup. Wire ownership into postUpload and common writer before cache/write.

### Phase E — Response/CORS/secret observability

Phase E depends on GH-322 plus B–D. No second CORS store or matcher.

- **E1. `internal/api/post_response.go` (new):** postResponse XML,
  parsePostSuccess, Location/redirect helpers and writePostSuccess as §3.7.
  Headers come from object_response.go, not inline protected-header writes.
- **E2. `internal/api/object_response.go` (edit):** projectObjectWriteHeaders,
  backend version/SSE/lifecycle + plaintext checksums and ETag semantics;
  ensure XML/object lengths distinct and no-store for SSE-C.
- **E3. `internal/api/post_response_test.go` (new):** 200/201/204/invalid
  status/303/malformed redirect, XML escaping/unusual literal keys, non-secret
  backend fields, host/scheme spoof protection and no redirect fetch.
- **E4. `internal/middleware/logging.go` (edit):** mandatory redaction of
  authorization/token/SSE-C material regardless optional config; form body
  stays absent. Preserve benign header logs and signed request unchanged.
- **E5. `internal/middleware/tracing.go` (edit):** mandatory credential/SSE-C
  redaction even redactSensitive=false; no POST fields in span attributes.
- **E6. `internal/middleware/query_redaction.go` (edit):** add policy/SSE-C
  triplet sensitive query keys, preserving signature/query request bytes.
- **E7. `internal/middleware/post_secrets_test.go` (new):** all logging formats,
  tracing redaction on/off and query transport; inspect sentinel secrets absent.
- **E8. `internal/api/s3_instrumentation_test.go` (edit):** plaintext file bytes
  only once, separate PostObject request operation, retry still PutObject,
  validation errors not success and no double encryption/audit.
- **E9. `internal/api/drift_guard_test.go` (edit):** enforce shared write helper
  adoption, version/header owner, no direct key persistence; do not weaken
  existing metadata/response guards to accommodate new handlers.

### Phase F — Provider, SDK/browser and conformance proof

Phase F depends on all implementation phases and GH-322; Docker fixtures only,
not host-installed SDK/browser dependencies. Missing mandatory local fixture is
a failed/blocked acceptance, not a passing all-skipped SSE/browser matrix.

- **F1. `test/harness/gateway.go` (edit):** mirror production chain including
  GH-322 CORS/Recovery order, resolve gateway session config and per-handler
  trusted extractor, preserve shared spool manager; WithConfigMutator supplies
  SSE/TLS without a new feature flag. Do not bypass auth in new POST fixtures.
- **F2. `test/provider/provider.go` (edit):** add optional `ObjectSSE *SSEFixture`
  on Instance, `type SSEFixture struct { Backend TLSFixture; KMSKeyID string }`;
  provides verified backend HTTPS and disposable static-KMS name to tests.
- **F3. `test/provider/minio.go` (edit):** configure ONLY TLS fixture with
  `MINIO_KMS_SECRET_KEY=gh353-test:<base64 random32>`; validate SSE-S3,
  SSE-KMS key gh353-test and SSE-C round trips through trusted backend SDK
  before exposing ObjectSSE fixture. Keep normal provider endpoint unchanged.
  Use existing pinned MinIO image, no new production KMS provider. Failure to
  prove static-key support blocks fixture acceptance; don't advertise fake SSE.
- **F4. `test/conformance/post_object_test.go` (new):** named Go scenarios in
  §6, all base providers for core POST/negative tests, optional tags/ACL/version
  use existing exact caps; TLS ObjectSSE fixture for real SSE modes/storage.
  Use provider cleanup policies; no extra billable external storage classes.
- **F5. `test/conformance/post_sdk_runners.go` (new):** boto3PresignedPostRunner
  and awsJSPresignedPostRunner implement existing sdkToolRunner methods
  (Name/Image/Script/AssertOutput); reusable default/201, metadata/range/session
  policies generated by real SDKs, standard multipart file-last fetch.
  Reuse pythonImage/boto3Version; JS Node image `node:24-bookworm-slim`, exact
  @aws-sdk/client-s3 and @aws-sdk/s3-presigned-post `3.1146.0`.
- **F6. `test/conformance/post_browser_runner.go` (new):** runner uses
  `mcr.microsoft.com/playwright:v1.63.0-noble` and playwright `1.63.0` plus
  exact JS SDK versions; launch Chromium and browser fetch from a distinct
  loopback origin, send FormData and verify status/readable ETag/XML. Test
  rejected signed form readable error, denied origin unreadable response,
  custom-header OPTIONS and allowed preflight. No printout of forms/credentials.
- **F7. `test/conformance/compat_runner.go` (edit):** add sdkTestEnv.SessionToken
  and optional env injection AWS_SESSION_TOKEN; avoid exposing in logs;
  preserve existing runners. Runner names/method declarations match interface.
- **F8. `test/conformance/suite_test.go` (edit):** register PostObject_* and
  Compat_* scenarios from §6; core/browser require no native POST/CORS cap;
  browser starts Valkey and uses gateway-mode CORS independent of backend API.
- **F9. `test/conformance/post_sdk_runners_test.go` (new):** exact pinned
  packages/images, scripts assert request/result not merely OK, secrets env
  transport and errors; no local npm/python installs.
- **F10. `scripts/test-gh353-helm.sh` (new):** shell function
  `TestChart_GH353SessionCredentials` renders/lints inline/existing-secret/token
  env + deadlines/backend token and rejects invalid schema; set -euo pipefail.

### Phase G — Helm/config/operator documentation and final gates

- **G1. `config.yaml.example` (edit):** annotated §3.3 credential/token/deadline
  and independent backend token example, safe env sources and no real secrets.
- **G2. `helm/s3-encryption-gateway/values.yaml` (edit):** optional sessionToken
  configValue/expiresAt credential and backend sessionToken; no nonempty default
  token, no new SSE key values or CORS authority.
- **G3. `helm/s3-encryption-gateway/values.schema.json` (edit):** credential
  token configValue/deadline timestamp and pairing constraints for concrete
  inline values; backend token schema. Runtime validates secretRef contents.
- **G4. `helm/s3-encryption-gateway/templates/deployment.yaml` (edit):** indexed
  token/deadline and backend-token env using envVar helper; mounted credentials
  secret remains authoritative; omission vs explicitly empty token preserved.
- **G5. `helm/s3-encryption-gateway/README.md` (edit):** session SecretRefs,
  rotating tokens/expiration, SSE-C proxy/HTTPS and GH-322 CORS prerequisite.
- **G6. `README.md` (edit):** browser POST support/limits, boto3 example link,
  backend SSE is additional encryption, credentials and exclusions.
- **G7. `docs/S3_API_IMPLEMENTATION.md` (edit):** rename misleading MPU heading,
  separate POST Object endpoint and full field/condition/error/response matrix,
  SSE-C read lifecycle and provider-specific unsupported behavior.
- **G8. `docs/DEPLOYMENT.md` (edit):** complete boto3+curl and JS FormData examples,
  path style/filename/policy, session reload, safe exact redirects, backend KMS
  permissions/cost, 0600 ephemeral plaintext disk/quota, TLS termination and
  trusted-peer overwrite/network isolation; reference GH-322 Valkey backups.
- **G9. `docs/METADATA_MODEL.md` (edit):** POST original ETag/checksum semantics,
  backend version/SSE header projection, no customer-key persistence or SSE-C
  cache/rotation; keep registry/on-disk format unchanged.
- **G10. `docs/TESTING.md` (edit):** §6 exact command budget/logs, mandatory SSE
  and real-browser fixtures, package pins and no all-skipped acceptance.
- **G11. `CHANGELOG.md` (edit):** under existing v1.0 – Unreleased only,
  GH-353 features, compatibility exclusions, CORS dependency, session/sensitive
  transport/cache caveats and temporary plaintext disk; no published edits.
- **G12. `docs/issues/GH-353.md` (edit):** link implementation evidence and
  update status only after all §8 checkboxes and dependency proof; don't close
  GitHub issue or mark Done merely because plan was created.

`scripts/generate-config-from-helmrelease.py` is not a GH-353 deliverable:
its existing mapping has no gateway-credentials conversion, so adding backend
token alone would imply misleading support. Operators use the native example
or rendered Helm env/mounted credential file; broader generator modernization
is a separate follow-up. Do not silently rely on it for session examples.

## 5. Affected Files

### Direct edits

- `internal/config/config.go` — session sources/validation/reload invariants.
- `internal/api/credential_store.go` — immutable token/deadline principal.
- `internal/api/auth_middleware.go` — POST and ordinary session auth.
- `internal/api/authorization.go` — exact PostObject write permissions.
- `internal/api/handlers.go` — PUT wrapper, route, read client and error mapping.
- `internal/api/object_stream.go` — SSE-C preflight/cache/rotation discipline.
- `internal/api/object_response.go` — central write/SSE/version projection.
- `internal/api/spool_manager.go` — exact POST payload classification.
- `internal/api/s3_instrumentation.go` — PostObject/file-byte accounting.
- `internal/api/{auth_middleware_test.go,authorization_test.go,route_parity_test.go,spool_limits_regression_test.go,s3_instrumentation_test.go,drift_guard_test.go}` — explicit regressions, parity and structural invariants.
- `internal/s3/{client.go,gcs_client.go,azure_client.go,proxy_client.go}` — additive advanced methods, independent backend session identity.
- `internal/util/ip.go` — secure trusted-peer scheme predicates.
- `internal/middleware/{logging.go,tracing.go,query_redaction.go}` — mandatory secret redaction.
- `cmd/server/main.go` — session reload guards and construction wiring.
- `test/harness/gateway.go` — production-equivalent CORS/auth/TLS fixtures.
- `test/provider/{provider.go,minio.go}` — isolated real TLS/SSE fixture.
- `test/conformance/{compat_runner.go,suite_test.go}` — session runner env and scenario registration.
- `config.yaml.example` — annotated credential/backend token examples.
- `helm/s3-encryption-gateway/{values.yaml,values.schema.json,templates/deployment.yaml,README.md}` — secret-backed session/deadline config.
- `README.md`, `CHANGELOG.md`, `docs/{S3_API_IMPLEMENTATION.md,DEPLOYMENT.md,METADATA_MODEL.md,TESTING.md}` — wire/operator/test contracts.
- `docs/issues/GH-353.md` — implementation status/evidence.

### New files

- `internal/config/session_config_test.go`, `cmd/server/session_reload_test.go` — configuration/rotation proof.
- `internal/api/session_auth.go`, `internal/api/session_auth_test.go` — common session authentication.
- `internal/s3/{object_options.go,customer_read_client.go,object_options_test.go}` — advanced object API and request-local key decorator.
- `internal/util/https_test.go` — exact trusted HTTPS tests.
- `internal/api/{sse.go,sse_test.go}` — SSE validation and read boundaries.
- `internal/api/{post_errors.go,post_policy.go,post_policy_test.go,post_form.go,post_form_test.go}` — strict auth/parser contract.
- `internal/api/{post_checksum.go,post_spool.go,post_spool_test.go,post_options.go,post_options_test.go}` — verified file/options.
- `internal/api/{object_put.go,object_put_test.go,post_object.go,post_object_test.go}` — shared writes and live POST handler.
- `internal/api/{post_response.go,post_response_test.go}` — XML/status/redirect serialization.
- `internal/crypto/{write_profile.go,write_profile_test.go}` — additive immutable streaming capability for POST memory bounds.
- `internal/middleware/post_secrets_test.go` — no-secret telemetry proof.
- `test/conformance/{post_object_test.go,post_sdk_runners.go,post_browser_runner.go,post_sdk_runners_test.go}` — provider/SDK/browser acceptance.
- `scripts/test-gh353-helm.sh` — repeatable chart validation.
- `docs/adr/0020-browser-post-policy-uploads.md` — architectural decision.

No crypto format/metadata registry changes, new production libraries, new KMS
provider or HSM changes are required. GH-322 files remain dependency-owned.

## 6. Test Strategy

Names below are exact. Tier 1 tests use no build tag unless marked fips;
Tier 2 files run through TestConformance with `conformance`. Lowercase scenario
functions are deliberate existing harness convention; PascalCase full subtest
names are listed, not invented standalone Test functions that never run.

| Layer | Tests |
|---|---|
| Unit — config (no tag) | `TestGH353SessionConfig_SourcesAndPrecedence`, `TestGH353SessionConfig_PairingExpiryAndClone`, `TestGH353SessionConfig_RestartOnlyTransport` — all YAML/file/env/index/secret/deadline cases and no aliasing. |
| Unit — session (no tag) | `TestGH353SessionAuth_TokenAndDeadline`, `TestGH353SessionAuth_SignedTransports`, `TestGH353CredentialStore_SessionSnapshotIsolation`, `TestGH353SessionReload_RotationAndInvalidSnapshot`, `TestGH353SessionReload_RestartChangeHasNoSideEffects` — missing/wrong/duplicate/expired tokens, signed headers/query/POST, old snapshot in flight/new request uses new snapshot. |
| Unit — backend wire (no tag) | `TestGH353AdvancedPut_SDKWireOptionsAndResult`, `TestGH353AdvancedRead_CustomerKeyWire`, `TestGH353BackendSessionToken_IsIndependent`, `TestGH353AdvancedAdapters_FailBeforeBodyRead`, `TestGH353CustomerReadClient_TargetIsolationAndClose` — real HTTP serialization, SDK credentials/result, normalized adapters, key not sent to companion. |
| Unit — secure read/cache (no tag) | `TestGH353HTTPS_TrustedImmediatePeer`, `TestGH353SSE_ValidationAndTransport`, `TestGH353SSEC_ReadPreflightRangeAndHEAD`, `TestGH353SSEC_NoCacheReplayOrCapture`, `TestGH353SSEC_NoAutomaticRotation`, `TestGH353SSEC_CopyAndMPURejected` — TLS/proxy spoofing, raw key/MD5, every primary read gets key, wrong/absent key yields no plaintext. |
| Unit — policy (no tag) | `TestGH353PostPolicy_AWSSignatureVector`, `TestGH353PostPolicy_StrictJSONAndScope`, `TestGH353PostPolicy_AllConditionsAndFieldCoverage`, `TestGH353PostPolicy_ContentTypeCommaSemantics`, `TestGH353PostPolicy_ExpirationAndFutureSkew` — exact original policy signing, token coverage, dates, eq/prefix/range and no expiry grace; AWS fixed vector checks crypto only with frozen clock. |
| Unit — MIME (no tag) | `TestGH353PostForm_RoutePredicate`, `TestGH353PostForm_FieldAndFilenameSemantics`, `TestGH353PostForm_DuplicatesFramingAndUTF8`, `TestGH353PostForm_OverheadAndLookaheadBound`, `TestGH353PostAuth_DeniedBeforeFileSpool` — file/text last, Windows/Unix basename, literal key semantics, fake EOF/oversize headers/epilogue and no unauthorized disk/backend activity. |
| Unit — spool/checksums (no tag) | `TestGH353PostSpool_ExactInclusiveBounds`, `TestGH353PostSpool_FileNotWholeFormLength`, `TestGH353PostSpool_ChecksumVectors`, `TestGH353PostSpool_CleanupOnAllFailures`, `TestGH353PostSpool_LiveLimitSnapshot`, `TestGH353PostSpool_BufferedEngineBound` — zero/min/max/+1, all four hashes+MD5, HTTP chunking, quota/cancel/create/write/seek/remove failures and bounded memory. |
| Unit — streaming profile/ciphertext (no tag) | `TestGH353EncryptionWriteProfile_StreamingAndBuffered`, `TestGH353PostSpool_CiphertextQuotaLengthAndRetry` — immutable engine profile, streaming fallback preserved, exact ciphertext prefix length, full plaintext+ciphertext aggregate quota, disk seekable retries, no second memory buffer. |
| Unit — options (no tag) | `TestGH353PostOptions_ClosedFieldMatrix`, `TestGH353PostTagging_StrictXMLAndUnicode`, `TestGH353PostOptions_StorageACLAndWebsite`, `TestGH353PostOptions_SSEAndNoKeyPersistence` — known options converted, unknown denied, tags Unicode/duplicates, key excluded from metadata. |
| Unit — shared write/live chain (no tag) | `TestGH353Put_CharacterizationPreserved`, `TestGH353PostObject_RoundTripFormatsAndMetadata`, `TestGH353PostObject_RejectionPreservesDestination`, `TestGH353PostObject_ScopeReadOnlyAndMixedRoutes`, `TestGH353PostObject_ExpiryBeforeCommit`, `TestGH353PostObject_AdvancedCapabilityRequired`, `TestGH353PostObject_GatewayCORS` — full chain, all-six metadata+two user keys, bad checksum/range/framing/expired policy has zero backend calls and unchanged object/version/cache; bypass/chunked/buffered policies; allowed/disallowed/error CORS. |
| Unit — response/telemetry (no tag) | `TestGH353PostResponse_StatusXMLAndRedirect`, `TestGH353PostResponse_EscapingVersionSSEAndChecksums`, `TestGH353PostResponse_NoRedirectFetchOrHostSpoof`, `TestGH353PostSecrets_LogsAndTracingNeverLeak`, `TestGH353PostInstrumentation_FileBytesOnce`, `TestGH353DriftGuard_SharedWriteAndSecretOwnership` — status defaults, correctly escaped URLs/XML, response allowlist, no key/token/policy/signature or double metrics. |
| Existing regression (no tag) | `TestRouteClassificationParity`, `TestHandlePutObject_UnknownLength_StreamsSingleAttempt`, `TestHandlePutObject_UnknownLength_RecordsPlaintextSize`, `TestHandlePutObject_MetadataEncryptionLengthMatchesBackendWireBody`, `TestAuthenticatedMiddlewareChain_CORSPreflightRoutesAndReflectsBackendHeaders` — existing route/PUT/retry/default passthrough contracts remain directly asserted. |
| Fuzz (seed corpus in Tier 1, no tag) | `FuzzPostPolicy`, `FuzzPostForm`, `FuzzPostTagging`, `FuzzPostRedirect` — bounded parsing, no panics, duplicate/invalid inputs never produce an accepted write, file-byte accounting invariant; add fuzz functions to respective policy/form/options/response test files. |
| FIPS distinct feedback (`fips`, GOFIPS140=v1.0.0) | `TestGH353PostPolicy_AWSSignatureVector`, `TestGH353PostSpool_ChecksumVectors`, `TestGH353PostObject_RoundTripFormatsAndMetadata`, `TestGH353SSE_ValidationAndTransport` — protocol hashes/signatures and encrypted writes compile/work under project's supported FIPS mode; no HSM. |
| Conformance — core (`conformance`) | `testPostObjectRoundTrip`, `testPostObjectRejectPreservesExisting`, `testPostObjectSessionAndExpiry`, `testPostObjectResponses`, registered as `TestConformance/<provider>/PostObject_RoundTrip`, `PostObject_RejectPreservesExisting`, `PostObject_SessionAndExpiry`, `PostObject_Responses` — real encrypted backend, read/HEAD/range, ETag/metadata, no invalid overwrite, 204/201/303 and no forwarded gateway credentials. |
| Conformance — optional storage (`conformance`) | `testPostObjectTaggingACLVersion`, subtest `PostObject_TaggingACLVersion` uses existing CapInlinePutTagging/CapObjectACL/CapVersioning for individual subcases; `testPostObjectSSE`, subtest `PostObject_SSE` uses validated ObjectSSE TLS fixture and proves SSE-S3/KMS/C POST→GET/HEAD/range, missing/wrong-key cache denial, backend SSE headers and STANDARD_IA storage on disposable local fixture only. |
| SDK and browser (`conformance`) | `testCompatBoto3PresignedPost`, `testCompatAWSJSPresignedPost`, `testCompatBrowserPost`, registered as `Compat_Boto3PresignedPost`, `Compat_AWSJSPresignedPost`, `Compat_BrowserPost` — real SDK-generated defaults/session/range/201 and Chromium cross-origin FormData, allowed/denied response access, preflight/errors. These are mandatory on at least one local provider, not all-skipped. |
| Runner/chart (runner: no tag; chart: shell) | `TestGH353PostSDKRunner_ScriptsAndPins`, shell `TestChart_GH353SessionCredentials` — real scripts contain assertions, exact package/image pins, secret env injection and Helm valueFrom/deadline/backend-token rendering/negative schema. |

AWS immutable vector for `TestGH353PostPolicy_AWSSignatureVector` [16]:
access key `AKIAIOSFODNN7EXAMPLE`, secret
`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` (fictitious public example), scope
`20151229/us-east-1/s3/aws4_request`, x-amz-date `20151229T000000Z`, frozen now
`2015-12-29T00:00:00Z`, expected signature
`8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e`.
Use this exact base64 string, not reserialized JSON:

```text
eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29uZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0KICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRDb250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJzdGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0KICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9
```

Fields are bucket sigv4examplebucket, key user/user1/test.jpg, acl public-read,
Content-Type image/jpeg, x-amz-meta-uuid 14365123651274, x-amz-meta-tag empty,
x-amz-server-side-encryption AES256 and success_action_redirect
http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html, plus auth
fields above. This is cryptographic/policy validation only, not a network write
with expired/public example credentials. Mutating decoded CRLF then base64
must invalidate the signature, proving exact policy-byte signing.

Test fixtures use supported minimum PBKDF2 work factor; production defaults
are unchanged. Use 32–128 KiB multi-chunk files except boundary fake readers;
no multi-GiB allocation to prove limits. Bounded-buffer tests use configured
tiny caps and instrumented readers/allocations.

### Validation Matrix

This is a command budget. Coordinator means the single executing agent when
not orchestrated; implementation worker owns focused feedback only. Final
verifier consumes recorded successful gate evidence unless relevant edits
occurred later. Run broad gates sequentially once after final relevant edit;
use timestamp-unique paths, pipefail+tee, suppress stdout from agent context.
Failed/missing Docker or mandatory SSE/browser fixtures means BLOCKED/FAIL,
not a successful partial result. No duplicate full-suite coverage/race run.

| Command | Purpose | Tier | Owner | Run when |
|---|---|---|---|---|
| `go test -count=1 ./internal/api ./internal/s3 ./internal/crypto ./internal/config ./internal/util ./internal/middleware ./cmd/server -run '^(TestGH353.*|TestRouteClassificationParity)$'` | Fast named implementation feedback; not second acceptance gate | 1 | implementation worker | After affected phase edits |
| `GOFIPS140=v1.0.0 go test -tags=fips -count=1 ./internal/api -run '^TestGH353(PostPolicy_AWSSignatureVector|PostSpool_ChecksumVectors|PostObject_RoundTripFormatsAndMetadata|SSE_ValidationAndTransport)$'` | Distinct FIPS protocol/encryption proof | 1F | coordinator | Once after last crypto-facing edit |
| `bash scripts/test-gh353-helm.sh` | Schema/lint/render/secret env proof outside Go suite | Chart | coordinator | Once after final chart edit |
| `set -o pipefail; make test 2>&1 \| tee /tmp/opencode/GH-353-make-test-$(date -u +%Y%m%dT%H%M%S).log >/dev/null` | Single full Tier 1 race/coverage gate | 1 | coordinator | Once after final relevant edit and dependency integration |
| `set -o pipefail; make test-conformance 2>&1 \| tee /tmp/opencode/GH-353-conformance-$(date -u +%Y%m%dT%H%M%S).log >/dev/null` | Real-provider, SDK, SSE and browser gate | 2 | coordinator | Once after successful make test; same final tree |
| `go tool cover -func=coverage.out` | Inspect existing Tier 1 profile only; each new production file ≥85% statement coverage, aggregate by statement counts | Evidence | coordinator | After successful make test; no second coverage suite |
| `git diff --check` | Whitespace/patch hygiene | Static | coordinator | After final edits |

For per-file coverage aggregate profile covered/total statement counts (not
unweighted average function percentages) and record calculations in evidence.
Do not add full test-fips/vet/HSM/load/soak gates; this issue needs focused FIPS
proof, not another broad suite. Fuzz seeds run in make test; extended fuzzing
is debugging-only on a discovered parser failure, not another default gate.

### Commands to verify locally

```bash
go test -count=1 ./internal/api ./internal/s3 ./internal/crypto ./internal/config ./internal/util ./internal/middleware ./cmd/server -run '^(TestGH353.*|TestRouteClassificationParity)$'
GOFIPS140=v1.0.0 go test -tags=fips -count=1 ./internal/api -run '^TestGH353(PostPolicy_AWSSignatureVector|PostSpool_ChecksumVectors|PostObject_RoundTripFormatsAndMetadata|SSE_ValidationAndTransport)$'
bash scripts/test-gh353-helm.sh
set -o pipefail; make test 2>&1 | tee /tmp/opencode/GH-353-make-test-$(date -u +%Y%m%dT%H%M%S).log >/dev/null
set -o pipefail; make test-conformance 2>&1 | tee /tmp/opencode/GH-353-conformance-$(date -u +%Y%m%dT%H%M%S).log >/dev/null
go tool cover -func=coverage.out
git diff --check
```

Record actual log paths, exit status, tested commit/diff identity, mandatory
scenario execution and skip counts. Logs under /tmp/opencode are execution
evidence, not repository files. No broad gates are run just to validate a plan.

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Valid signature permits uncovered/duplicate/conflicting fields | Strict JSON/MIME duplicate rejection, required bucket/auth coverage, exact shared predicate, all-condition AND; no transport fallback. |
| Bad min-size/framing/checksum discovered after destination overwrite | Entire file+MIME EOF+digest validation before encryption/cache/backend; negative tests with preexisting object/version/cache and zero call counters. |
| Disk quota or buffered engine consumes unbounded resources | Shared Grow-before-write plaintext+ciphertext reservations, separate 20KiB form cap, streaming raw-wire observer, 32KiB copy buffer, profile-based buffered-engine cap and cleanup failure/cancel tests. |
| SSE-C request reads cached plaintext or loses key on terminal range read | Request-local exact-target decorator, zero SSE-C lookup/capture, key-required backend failures retained and no-store; full/range/HEAD/preflight tests. |
| Proxy header spoof or TLS bypass exposes customer key | Immediate-peer CIDRs, exactly one XFP=https, direct TLS alternative, verified HTTPS backend, restart-only trust; no ForceHTTPS inference. |
| Key/token/policy reaches logs, spans, metadata, Valkey or redirects | Mandatory redaction on/off, no body-map logging, allowlisted options/results, no key persistence, zeroized raw buffers and no auth URL parameters. |
| Session expiration/rotation bypasses ordinary SigV4 access | One validator across POST/header/query, required signed token, exclusive deadlines, snapshot cloning and failed-reload retention. |
| Provider adapter accepts SSE option it cannot implement | Advanced interface with explicit 501 for unsupported options before body consumption; no legacy nonzero fallback; real TLS MinIO fixture proves supported modes. |
| Refactor changes PUT metadata, lengths, retries or metrics | Characterization tests and shared helper adoption guard; maintain ordinary known/unknown length semantics and independent response wrappers. |
| Plaintext checksum is forwarded as ciphertext checksum | Validate while spooling, separate response map; SDK computes ciphertext MD5; wire tests assert plaintext digest never used on backend encrypted body. |
| Redirect or XML injures clients or leaks credentials | Prevalidated absolute HTTP(S), no fetch/userinfo/control chars, query replacement via URL encoder, XML encoder, signed URL coverage. |
| CORS duplicates GH-322 or browser acceptance passes only curl | Explicit dependency, single shared store/outer middleware, mandatory Chromium cross-origin assertions; preserve durability/fallback rules. |
| All SSE/browser tests skip while broad suite exits zero | Local TLS/KMS+browser scenario execution is a release-blocking DoD item; record executed/skipped subtests, never mark Done on all-skipped gates. |

All security-critical rows are promoted to §8; provider unsupported behavior
is intentional compatibility signaling, not an implementation omission.

## 8. Definition of Done

Per `docs/issues/GH-353.md:19`, all checkboxes below are binary and required:

> **Verification: 2026-11-04 — PASS for the approved scope.** Independent
> `litellm/azure-gpt-6-1-sol` session `ses_e59826f2cffegFn0A0Yi7uRErl` reviewed
> the complete plan, source, assertions and validation ledger without repository
> edits. Report: `/tmp/opencode/GH-353-sol-final-verify-r37-report.md`;
> reviewed content inventory: `/tmp/opencode/GH-353-final-tree-20261104-r36.json`.
> Acceptance includes strict restart-only `metadata_profile` and
> `post_inline_tagging` settings, bounded metadata fallback/HEAD restoration,
> GH-353-only RustFS/SeaweedFS exclusions, and independent MinIO/RustFS native
> rejection proofs. Metadata documentation is in `docs/ENCRYPTION_DESIGN.md`.
> r36 Tier 1 and coverage pass; r34 local runtime follows passing r33 Tier 1
> and remains applicable after only reviewed test/name/documentation edits,
> not an identical-r36-tree runtime execution. Focused FIPS and Helm evidence
> is retained and unchanged. All 17 new production files exceed 85% statement
> coverage (minimum 85.18518519%). Wasabi/B2 focused compact-profile passes do
> not attest final-tree provenance, full conformance or optional native SSE,
> ACL/versioning. Excluded/skipped scenarios are not passes. See
> [the testing contract](../TESTING.md#gh-353-post-acceptance-contract).
> Completion markers were updated only after independent PASS; implementation
> remains uncommitted and unreleased.

- [x] GH-322 is implemented; its single store/middleware covers POST success,
  auth/policy errors and browser preflight; original GH-322 files not overwritten.
- [x] Real boto3 and AWS JS forms upload through exact path-style PostObject
  route; unknown/mixed/subresource POST shapes keep correct denial/routing.
- [x] Original-policy HMAC, scope/date, deadlines and all-condition coverage
  pass; malformed JSON/base64/MIME/duplicate fields fail closed.
- [x] Filename expansion, literal UTF-8 keys, Content-Type comma matching,
  bucket binding and all integer range bounds match §3.2.
- [x] Existing principal rw/bucket/PROXIED_BUCKET checks precede file spooling
  and all backend/KMS operations; no public POST auth exception.
- [x] Entire plaintext file/framing/digests are validated before encryption,
  cache invalidation/write; rejected POST preserves object/version/metadata/cache.
- [x] Form ≤20KiB, file server/signed cap, shared aggregate quota and buffered
  engine memory bounds enforced; success/error/cancel paths remove temp files
  and release reservations; plaintext+ciphertext disk use documented, exact
  ciphertext length/rewindability proves fallback and retry paths.
- [x] Content-MD5/CRC32/CRC32C/SHA1/SHA256 prove plaintext bytes, not ciphertext;
  mismatch BadDigest has no mutation; unsupported algorithms fail explicitly.
- [x] PUT and POST call one common data-write helper; original PUT known/
  unknown-length/retry/backfill/metadata behavior and metrics remain tested.
- [x] Metadata/ACL/tagging/storage/website options, advanced capability errors,
  200/201/204/303 and backend version/SSE/ETag/checksum projection match §3.
- [x] Configured tokens/deadlines validated on all SigV4 transports, SigV2
  session attempts denied, env/Helm/file sources and atomic rotations covered.
- [x] Gateway session credentials never forwarded as backend identity;
  restart-only backend/trust changes reject before live mutation.
- [x] SSE-S3 and SSE-KMS add backend encryption without disabling gateway
  policy; provider unsupported modes produce 501, no silent downgrade.
- [x] SSE-C raw keys require direct/trusted-peer HTTPS and verified backend
  HTTPS, are never logged/persisted, and mutable key buffers zeroized on cleanup.
- [x] SSE-C GET/HEAD/full/range/terminal preflights use correct primary key;
  absent/wrong key never releases plaintext, cache never bypasses key requirement,
  no automatic rotation/write-back, no-store returned.
- [x] SSE-C copy/MPU inputs rejected before work; no customer key sent to
  companion/other objects or included in URL/XML/metadata/Valkey.
- [x] Mandatory secret redaction holds for logging/tracing settings on/off;
  no raw policy/signature/token/customer key in logs/errors/metrics.
- [x] Redirect targets signed/validated, gateway performs no target fetch,
  URI/XML escaping is correct and object Location ignores spoofed forwarded host.
- [x] PostObject client metrics count only plaintext file bytes exactly once;
  backend retry operation remains PutObject; no double audit/encryption events.
- [x] Real local SSE-S3/KMS/C fixture, SDK runners and Chromium browser
  allowed/denied/error/preflight scenarios execute and pass, not all-skipped.
- [x] `make test` then `make test-conformance` pass sequentially on final tree,
  unique retained logs and scenario/skip evidence recorded; focused FIPS passes.
- [x] Each new production file ≥85% statement coverage from final Tier 1
  coverage.out; no duplicate coverage/full-race suite used.
- [x] Helm render/lint/schema and whitespace checks pass; config example,
  chart README, project README, API/deployment/metadata/testing docs, ADR0020
  and v1.0 Unreleased entry agree with actual implementation/exclusions.
- [x] Tracker/plan checkboxes updated only after independent implementation
  verification; no implementation success claimed from planning or curl alone.

## 9. Milestones & Estimated Effort

Engineering estimates from the explicit phase/file/test scope; days are focused
developer-days, not elapsed calendar promises. GH-322 effort excluded; its
implementation is an external predecessor, not silently bundled here.

| Phase | Output | Effort |
|---|---|---|
| A | Session/config/snapshot/reload contract and tests | 1.50 d |
| B | Advanced SDK/provider API, trusted TLS and SSE-C read/cache boundary | 3.00 d |
| C | Strict bounded parser, signed policy and middleware integration | 2.50 d |
| D | Verified file/checksums/options and shared PUT/POST data writer | 2.50 d |
| E | Responses/CORS integration/secret-safe metrics and telemetry | 1.50 d |
| F | Provider SSE fixture, SDK and real-browser conformance | 2.50 d |
| G | Helm/docs and single final acceptance cycle | 1.50 d |
| **Total** | **GH-353, excluding GH-322 implementation** | **15.00 d** |

Security review findings or upstream fixture limitations change estimates;
they do not authorize weakening transport/parser/coverage acceptance criteria.

## 10. Follow-ups / Out-of-scope items surfaced during planning

- SSE-C CopyObject/UploadPartCopy/MPU plus source/destination keys — separate
  protocol/state feature; explicit rejection is safer than partial key reuse.
- Virtual-host/addressing and directory buckets/DSSE-KMS — separate endpoint/
  storage semantics, not a path-style POST insertion.
- Dynamic STS issuance/refresh and backend token auto-refresh — requires an
  external authority/credential-provider lifecycle, not static config extension.
- HelmRelease-to-native-config generator credential conversion — existing
  generator is not the authoritative chart env path; modernize separately.
- Durable plaintext checksum projection/GetObjectAttributes — would require
  authenticated persisted metadata/registry changes; POST acknowledgment only.
- Native GCS/Azure SSE mappings — shims cannot promise AWS KMS/SSE-C semantics;
  explicit unsupported behavior preserves the requested security contract.
- Broader buffering optimizations — disk-spooled POST uses explicit memory
  bounds; changing legacy crypto streaming formats is not part of GH-353.

## 11. References

1. cloud37 issue reporter, *Support browser form uploads (POST Object with a presigned POST policy)* (GitHub, 2026) — reported reproduction and missing operation.
    <https://github.com/cloud37/s3-encryption-gateway/issues/353>
2. Amazon Web Services, *POST Object* (AWS Documentation, accessed 2026) — form fields, SSE, checksums and response serialization.
    <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/RESTObjectPOST.html>
3. Amazon Web Services, *Creating an HTML Form (Using AWS Signature Version 4)* (AWS Documentation, accessed 2026) — 20KB overhead, file-last, filename expansion and session tokens.
    <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-HTTPPOSTForms.html>
4. Amazon Web Services, *POST Policy* (AWS Documentation, accessed 2026) — condition operators, field coverage, Content-Type matching and expiration.
    <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-HTTPPOSTConstructPolicy.html>
5. cloud37 Engineering, *ADR 0012 — Unified Credential Store* (s3-encryption-gateway, 2026) — mandatory gateway auth and independent backend identity.
    <https://github.com/cloud37/s3-encryption-gateway/blob/main/docs/adr/0012-unified-credential-store.md>
6. cloud37 Engineering, *ADR 0016 — Per-Credential Authorization* (s3-encryption-gateway, 2026) — scopes, permissions and atomic snapshots.
    <https://github.com/cloud37/s3-encryption-gateway/blob/main/docs/adr/0016-per-credential-authorization.md>
7. cloud37 Engineering, *ADR 0018 — Centralized Object Metadata* (s3-encryption-gateway, 2026) — shared metadata/read/projection and ETag ownership.
    <https://github.com/cloud37/s3-encryption-gateway/blob/main/docs/adr/0018-centralized-object-metadata.md>
8. cloud37 Engineering, *GH-322 — Gateway-managed bucket CORS* (local implementation plan, 2026) — explicit approved dependency, Valkey authority, outer middleware and browser errors. Authoritative local file: `docs/plans/GH-322-plan.md`; not yet committed at planning time.
    <https://github.com/cloud37/s3-encryption-gateway/issues/322>
9. MDN Contributors, *Cross-Origin Resource Sharing (CORS)* (MDN Web Docs, accessed 2026) — browser response access, preflight and credentials.
    <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS>
10. Amazon Web Services, *Temporary security credentials in IAM* (AWS Documentation, accessed 2026) — token-bearing temporary credential lifecycle, distinct from issuance by this gateway.
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html>
11. Amazon Web Services, *Checking object integrity in Amazon S3* (AWS Documentation, accessed 2026) — plaintext digest algorithms and representations.
    <https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html>
12. Amazon Web Services, *Categorizing your storage using tags* (AWS Documentation, accessed 2026) — tag count/length/charset and reserved prefix.
    <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html>
13. Amazon Web Services, *Using server-side encryption with customer-provided keys (SSE-C)* (AWS Documentation, accessed 2026) — HTTPS, customer key lifecycle, GET/HEAD key requirement and opaque ETags.
    <https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html>
14. Go Authors, *mime/multipart package* (Go standard library, accessed 2026) — streaming raw parts and MIME parsing behavior.
    <https://pkg.go.dev/mime/multipart>
15. Amazon Web Services, *Browser-Based Uploads Using POST (AWS Signature Version 4)* (AWS Documentation, accessed 2026) — policy string-to-sign derivation.
    <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-UsingHTTPPOST.html>
16. Amazon Web Services, *Example: Browser-Based Upload using HTTP POST (Using AWS Signature Version 4)* (AWS Documentation, accessed 2026) — immutable public signing vector and case-insensitive form names.
    <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-post-example.html>

External verification: AWS protocol docs [2–4,15] and SDK package versions
were checked during planning. O'Reilly MCP was unavailable; architecture
recommendations were not independently verified against O'Reilly material.
