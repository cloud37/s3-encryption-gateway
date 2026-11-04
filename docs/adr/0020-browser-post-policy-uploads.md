# ADR 0020: Browser POST-policy uploads and configured session identity

## Status

Accepted architecture for GH-353; implementation is staged by
[the implementation plan](../plans/GH-353-plan.md). This decision does not claim
that the complete POST/SSE/browser feature has shipped.

## Context

S3 browser POST Object is a signed MIME form, not multipart-upload initiation
or a canonical-request PUT signature. Supporting it requires preserving the
mandatory gateway principal, bucket authorization and encryption boundaries,
while validating the entire upload before any destination mutation.
[ADR 0012](0012-unified-credential-store.md),
[ADR 0016](0016-per-credential-authorization.md) and
[ADR 0018](0018-centralized-object-metadata.md) retain their respective credential,
authorization and metadata ownership. GH-322 and
[ADR 0019](0019-gateway-managed-cors.md) are prerequisites for browser-readable
preflight, success and error responses; they remain the single CORS authority.

## Decision

### Routing, authentication and policy

Accept only path-style bucket POST with a valid multipart/form-data boundary,
an empty raw query, and exactly one optional trailing bucket slash. Keep delete,
MPU, object-level POST and malformed shapes on their existing routes/denials.
Reject simultaneous form/header/query authentication, rather than falling back.
Use the same credential and label context and ordinary rw/bucket/global scope
authorization before spooling file bytes or doing backend/KMS work.

Verify SigV4 HMAC against the **original base64 policy**, not rewritten JSON or
PUT canonicalization. Require strict scope/date/algorithm, constant-time
signature comparison, bounded duplicate-free JSON and MIME, full field coverage,
exact bucket binding and AND evaluation of all equality/prefix/size conditions.
Only Content-Type prefixes split comma-separated values. Filename expansion uses
both slash styles; keys remain literal UTF-8, with no path cleaning or decoding.
Require exactly one last file/text part, complete CRLF framing and HTTP EOF,
whitespace-only epilogue, bounded lookahead, at most 20 KiB non-file wire overhead,
128 scalars, 256 conditions, nesting 32 and boundary length 70. The file ceiling
is the intersection of the live server limit, signed bounds and 5 GiB.

Policies are reusable until an exclusive deadline, not one-time tokens. An older
signing timestamp is legal until expiration; future signing times obey clock
skew, which never extends policy/session expiration. Recheck expiry after file
and ciphertext preparation, immediately before cache invalidation/backend write.
There is no rollback guarantee if a deadline passes during an authorized write.

### Configured sessions and independent backend identity

Operator-configured session credentials add a token and GMT expires_at to the
existing immutable atomic credential snapshot. Token env sources are exclusive
with inline sources and must resolve nonempty without fallback; static entries
cannot have deadlines. Valid already-expired entries may be configured, but
runtime rejects them. Clone deadline pointers on resolution, snapshot creation
and lookup. Compare SHA256 token digests and lengths in constant time.

Apply one token/deadline validator to ordinary header/presigned SigV4 and POST.
Require exactly one token in the selected signed transport: SignedHeaders for
header auth, canonical query for presigned auth, exact condition for POST.
Missing/wrong/unexpected token returns fixed 403 InvalidToken; expiration returns
fixed 403 ExpiredToken. Session SigV2 is denied; static legacy auth remains opt-in.
Sessions rotate through existing atomic reload; no STS issuance, refresh or live
IAM evaluation is introduced. Indexed env and mounted YAML credentials use the
same validation, including explicit clearing and strict timestamps.

Gateway credentials/tokens are never forwarded to storage. Optional backend
session_token belongs solely to the independent backend identity. Backend
identity/token, endpoints/TLS and trusted-proxy configuration are construction-time;
both reload entry points reject changes before any live mutation. Drop temporary
secret/token references without claiming immutable Go strings are zeroized.

### Complete validation, shared writes and memory/disk budgets

Spool plaintext in request-owned 0600 temporary files, charging the shared quota
before writes; validate full framing, inclusive signed size bounds and plaintext
Content-MD5 plus optional CRC32/CRC32C/SHA1/SHA256 before encryption/backend work.
Checksums are protocol interoperability, not authorization or AEAD integrity.
Never forward plaintext digests as ciphertext checksums. Clean disk/reservations
on success, failure and cancellation.

PUT and POST share one typed encryption/data-write owner, preserving existing
PUT known/unknown-length, retries, size backfill, metadata, audit and cache behavior.
POST obtains an immutable optional engine write profile; absent/buffered profiles
obey the effective part-memory bound before Encrypt. Disk spooling alone does
not make buffered encryption unbounded-memory-safe. Spool ciphertext separately
under the same aggregate quota, holding both reservations until completion, to
obtain exact length and a seekable retry source, including metadata-prefix
streaming fallback. Reject ciphertext over 5 GiB before cache/backend mutations.
Temporary disk use is roughly plaintext plus ciphertext, and contains plaintext.
No crypto format or metadata registry change is introduced.

### Additive backend options and SSE-C lifecycle

Keep legacy Client source-compatible and add AdvancedObjectClient for typed
storage class, website redirect, SSE and read options/results. Zero options may
use the legacy path; nonzero unsupported options return explicit 501 before body
consumption, never silently downgrade. S3 SDK mappings preserve ciphertext
length/MD5/retry/TLS and a closed non-secret result allowlist. GCS/Azure shims and
proxy clients do not promise native AWS KMS/customer-key mappings.

Support signed closed-list metadata, canned ACL, bounded strict Unicode tagging,
storage classes, website redirect, SSE-S3, SSE-KMS and SSE-C. Backend SSE encrypts
**gateway ciphertext in addition to**, not instead of, per-bucket gateway
encryption. Backend KMS identifiers are not gateway key-manager IDs.

SSE-C requires direct TLS or a trusted **immediate** peer with exactly one
X-Forwarded-Proto=https indication, plus verified HTTPS backend transport. Ignore
XFF-derived client trust, Forwarded, X-Forwarded-SSL, ForceHTTPS and forwarded
host as authority. Trusted proxies must overwrite XFP and isolate the gateway
port; operators protect the proxy-to-gateway hop (TLS recommended). The accepted
trusted-termination assumption is not a claim that a plaintext hop is encrypted.

Customer keys are request-scoped mutable bytes, validated with matching MD5,
and zeroized after synchronous I/O. GET/HEAD/range and terminal preflights use
an exact-target request-local decorator; companion/other reads never receive
the key. Require signed selected header/query transport and no ambiguity.
Missing/wrong-key backend failures cannot fall through to crypto/cache success.
Disable SSE-C cache lookup/capture/replay and automatic gateway re-encryption,
return no-store, and preserve backend opaque ETag ahead of original-MD5 metadata.
Never persist keys, key fingerprints, tokens or policies in metadata/Valkey.

### Response ownership, CORS and observability

Central response projection owns non-secret ETag/version/lifecycle/SSE/storage
headers and validated checksum acknowledgments. Encrypted non-SSE-C POST exposes
plaintext MD5 ETag; bypass/SSE-C preserves backend ETag. Return 200/204 empty,
201 escaped namespace-qualified XML, or 303 with validated signed redirect and
encoded bucket/key/etag selectors. Invalid status defaults to 204; invalid
redirect falls back to status, two aliases are invalid. Never fetch redirects
or append auth material. Location uses validated host and trusted scheme,
without path cleaning or arbitrary forwarded-host trust.

Reuse Recovery → GH-322 CORS → Auth → Authorization → router ordering and the
single shared store. CORS controls browser response readability, not upload
authorization; an unmatched Origin does not reject an otherwise valid upload.
Default backend passthrough cannot guarantee CORS on local POST responses.
Use fixed typed S3 errors and exactly-once auth/audit/operation metrics; count
plaintext file bytes, not MIME or spool replays. Mandatory token/signature/policy/
customer-key redaction holds even when optional redaction is disabled; never log
form maps/bodies or credential structs.

## Consequences and exclusions

The feature costs bounded temporary plaintext+ciphertext disk and cross-cutting
auth/write/read integration. Mandatory Tier 1, real-provider Tier 2, SDK-generated
forms, real Chromium CORS and verified local TLS/KMS/SSE fixtures are acceptance
proof; all-skipped browser/SSE cases do not establish completion. New production
files require 85% statement coverage from the shared final Tier 1 profile.

Excluded: anonymous/public POST, SigV2 POST, DevPay, virtual-host addressing,
directory buckets/S3 Express, DSSE-KMS, multi-file forms, Object Lock extensions,
arbitrary provider fields, dynamic STS/refresh, SSE-C copy/MPU/rotation, a second
CORS authority, native GCS/Azure SSE mappings and durable plaintext-checksum APIs.
Reject unsupported sensitive semantics explicitly rather than partially accepting
them. Ordinary static authentication and PUT behavior must remain unchanged.
