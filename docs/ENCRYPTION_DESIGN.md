# Encryption Formats, Metadata, and FIPS

This guide owns the encryption/metadata contract and FIPS build profile. For
operator key setup use [key management](KMS_COMPATIBILITY.md); for API options
use [S3 compatibility](S3_API_IMPLEMENTATION.md); for upgrades/recovery use
[migration](MIGRATION.md). **Baseline: v0.12.3.**

## Contents

- [Encryption and integrity boundaries](#encryption-and-integrity-boundaries)
- [Chunked formats and range reads](#chunked-formats-and-range-reads)
- [Encrypted multipart uploads](#encrypted-multipart-uploads)
- [Encrypted object metadata model](#encrypted-object-metadata-model)
- [Metadata encryption and compaction](#metadata-encryption-and-compaction)
- [FIPS build profile](#fips-build-profile)
- [Verification and references](#verification-and-references)

## Encryption and Integrity Boundaries

Encryption-enabled buckets store authenticated ciphertext; explicitly bypassed
buckets store the client's original bytes. AES-256-GCM is the default;
ChaCha20-Poly1305 is supported in non-FIPS builds. AES-GCM uses 32-byte keys,
12-byte nonces, and 16-byte tags. Nonce uniqueness is required—GCM is not
nonce-misuse resistant.

Password mode derives keys using configured PBKDF2-SHA256 (default 600,000
iterations) or Argon2id parameters. Per-object parameters are retained for reading,
subject to decrypt-cost limits. The legacy 100,000 iteration setting is not the
recommended current default. Envelope mode generates a random DEK and wraps it
with a local AES/RSA KEK or external provider, avoiding password derivation on
ordinary new-object requests. See [mode selection](KMS_COMPATIBILITY.md#choosing-an-encryption-mode)
and [measured performance](PERFORMANCE.md#encryption-mode-benchmarks).

Current payload authentication binds bucket/key identity independently of
KeyManager advisory metadata. Backend-native moves/copies are not safe relocation;
gateway CopyObject or an explicit gateway GET→PUT rebinds the destination.
Classification recognizes historical formats but rejects unsupported/malformed
markers. Do not strip encryption metadata or reinterpret crypto failures as plaintext.

Verification is record-based for streaming formats. Preflight can reject the first
corrupt record before headers; later integrity failure can terminate an already
started response rather than replace its status with an XML error. Clients must
verify successful stream completion, not only the initial 200/206.

Private temporary request spools and optional plaintext/DEK caches are part of the
process trust boundary. Protect the gateway host, files, and keys, and bound memory
and disk. Zeroization of owned bytes is best-effort under Go's runtime, not a
guarantee that every intermediate historical copy was overwritten.

## Chunked Formats and Range Reads

The default chunk size is 64 KiB. The authenticated format manifest distinguishes
chunked v1 and v2; new current-format writes use v2. This description is the
chunked layout, not a universal layout for buffered/fallback/MPU objects.

```text
v1: DataRecord_0 || ... || DataRecord_(N-1)
v2: DataRecord_0 || ... || DataRecord_(N-1) || TerminalRecord
DataRecord_i = ciphertext(P_i) || 16-byte authentication tag
```

For v2 the terminal is 32 bytes: its authenticated plaintext contains big-endian
`uint64(N) || uint64(total plaintext length)`. An empty object contains the terminal
encoding `(0,0)`. Data and terminal nonces/AAD use separate HKDF domains. See
[ADR 0016](adr/0016-authenticated-chunked-completeness.md) and production format
code for the exact encoding; location binding is an additional payload boundary.

For plaintext length `P`, chunk size `S`, and `N=ceil(P/S)` (`N=0` for `P=0`),
ciphertext length is `P + 16*N` for v1 and `P + 16*N + 32` for v2. V1 authenticates
individual touched chunks but not a complete trailing suffix; it remains readable
and is a migration candidate.

For a plaintext range `[start,end]`, select chunks `start/S` through `end/S`, fetch
the corresponding ciphertext records including tags, verify them, and return only
the requested plaintext slice. Final ciphertext bounds must be clamped to actual
stored length. V2 authenticates the terminal before success and at full-stream EOF.
Legacy single-AEAD/fallback paths may require a full read/decrypt rather than this
optimized range mapping. Single ranges use plaintext Content-Range/Content-Length;
an oversized end is clamped, while an unsatisfiable start fails. Multiple ranges,
HEAD Range, and GET part selection are not complete supported contracts; see
[request options](S3_API_IMPLEMENTATION.md#object-reads-and-responses).

## Encrypted Multipart Uploads

Encrypted MPU has a per-upload wrapped DEK, identity binding, authenticated chunk
records, and a companion `<key>.mpu-manifest`. In-flight Valkey state owns routing,
first-content claims, reservation leases, and guarded completion/abort phases.
Identical part retries can return the committed ETag; changing claimed plaintext
is rejected rather than reusing deterministic nonces. Completion validates the
selected ordered committed set and persists the authenticated manifest.

The companion is integrity-critical for completed MPU reads. GET/copy fail closed
if it cannot be used; HEAD/listing may retain ciphertext sizes under the advisory
size exception. Historical parent versions and companion versions do not have an
exhaustively certified recovery mapping. Keep manifests and keys and test recovery;
do not treat backend versioning as automatic preservation. See
[MPU lifecycle/operations](RUNBOOK.md#valkey-state-at-rest-encryption),
[recovery](MIGRATION.md), and [ADR 0009](adr/0009-encrypted-multipart-uploads.md).

## Encrypted Object Metadata Model

The gateway treats `Content-Type`, `Cache-Control`, `Content-Disposition`,
`Content-Encoding`, `Content-Language`, and `Expires` as one typed standard-field
model. Encrypted values are protected/restored; bypass values use native backend
fields. Non-reserved user `x-amz-meta-*` keys are preserved subject to configured
backend filters. Gateway-reserved full/compact/legacy names cannot be supplied
by clients and are never projected back as user metadata.

### Write paths

PUT, CreateMultipartUpload, CopyObject, UploadPartCopy, and size backfill share
request parsing and persistence splitting. CopyObject's omitted/COPY directive
inherits source plaintext metadata; REPLACE uses request metadata. MPU initiation
freezes destination standard/user metadata; source-copy metadata does not replace it.

### Read paths and precedence

GET planning owns format classification, size/range/integrity decisions, manifest
resolution, and response-source selection. The shared projector applies the six
standard fields, user filtering, ETag, size, and version policy across HEAD, full/
ranged GET, MPU, and cache. Encrypted single-object precedence is:

```text
authenticated GET override → decrypted protected value → canonical → compact/legacy → backend fallback
```

HEAD does not apply GET overrides. Plaintext/bypass native fields are authoritative
unless GET overrides apply; MPU uses native initiation metadata and manifest size.
GET/HEAD restore a recorded original ETag for encrypted single objects when
available; MPU uses backend multipart ETag. Backend version wins the requested
version fallback. Unknown backend headers are not a generic passthrough contract.

### Format compatibility

Readers recognize buffered legacy/v2, fallback v1/v2/v3, chunked v1/v2, compacted
metadata, encrypted metadata blobs, MPU v1/v2, and plaintext. Unsupported markers
and pointers not matching `<key>.mpu-manifest` fail closed. Golden fixtures retain
historical ciphertext/metadata and assert HEAD/full/ranged reads and first-chunk
tamper behavior. Compatibility is not permission to mutate backend envelopes.

### Path-by-field inventory

| Path | Six standard fields | User metadata | ETag / size / version |
|---|---|---|---|
| PUT | Parsed; protected for encrypted objects, native for bypass | Parsed; reserved names rejected | Original size stamped; backend ETag returned |
| CreateMultipartUpload | Parsed and persisted natively | Parsed; reserved names rejected | MPU marker/binding generated by gateway |
| CopyObject COPY | Source plaintext fields inherited | Source user keys inherited; request metadata ignored | Source size resolved; destination rebound/re-encrypted |
| CopyObject REPLACE | Request fields; default Content-Type if absent | Request user keys only | Request Content-Length/ETag ignored |
| UploadPartCopy | Destination metadata frozen at initiation | Same | Source format/manifest resolves plaintext part range |
| Size backfill | Persistence model retains native/protected fields | Internal metadata retained | Exact size replaces metadata through backend COPY/REPLACE |
| Engine buffered/chunked/fallback writes | Protected standard values stamped | Caller user fields retained | Original ETag/size retained by format |
| Backend adapters | Standard/user split and key normalization | Backend metadata keys normalized | Typed input/output subset, not all SDK fields |
| HEAD | Canonical > compact/legacy > backend | Non-reserved keys | Exact resolved size; original ETag when recorded; backend version wins |
| Full/range GET | Decrypted > canonical > aliases > backend; GET override wins | Non-reserved keys | Plaintext range/size; ETag/version projected |
| MPU GET | Native initiation fields, GET overrides | Non-reserved keys | Manifest size; backend multipart ETag/version |
| Cache | Stored source metadata re-projected with current GET overrides | Non-reserved keys | Backend validation; ETag mismatch refreshes successful full-body entry |
| ListObjects | Not an object response-header path | Not projected | Advisory size translation; backend ETag |

### Path/field ownership and precedence

| Field | PUT / initiation | COPY / REPLACE | Part copy | HEAD / GET / range / cache |
|---|---|---|---|---|
| Standard headers | Case-insensitive parsing; encryption protection or native initiation fields | Source fields for COPY; request fields for REPLACE | Destination initiation metadata | Shared precedence above; HEAD has no overrides |
| User metadata | Lowercase names; reserved aliases rejected before side effects | Source for COPY; request-only for REPLACE | Destination frozen | Filter all reserved names/blobs |
| Content-Length | Plaintext input; ciphertext backend length; never user metadata | Destination derived from bytes, never request length | Resolved source/range size | Shared resolver; plaintext range length; MPU-manifest advisory exceptions |
| ETag | Backend write/part/completion ETag | New destination backend ETag, not request metadata | Backend part ETag | Original encrypted ETag if available; backend for plaintext/MPU |
| Version ID | Backend values may exist | Destination version may exist | Backend values may exist | GET/HEAD backend > requested fallback |
| Internal markers | Engine registry / MPU control generation | Used for source processing, not user overrides | Classifier selects source; initiation owns destination | Classifier/manifest validation, then reserved filtering |

Typed write/delete response shapes do not consistently expose backend destination
version/delete-marker fields. The model is not a conditional-request, checksum-mode,
or arbitrary backend-header guarantee; those limitations live in
[S3 compatibility](S3_API_IMPLEMENTATION.md).

### Ownership rules

- `objectmeta.Names` / `objectmeta.Standard`: ordered standard fields and splitting.
- `crypto.MetaKeys()`: canonical/compact/legacy registry and reserved classification.
- `crypto.ClassifyObject`: trusted format/pointer classification, no backend I/O.
- `Handler.resolvePlaintextSize`: terminal/format/manifest size policy; no guessed
  AEAD subtraction for fallback formats.
- `projectObjectHeaders`: client-facing field projection; `serveObjectBody` owns
  the selected body path rather than handlers reimplementing header policy.
- General listings rely on exact write-through cache entries or bounded opt-in
  HEAD fallback, not unconditional N+1 metadata calls.

See [ADR 0018](adr/0018-centralized-object-metadata.md),
[object response tests](../internal/api/object_response_test.go),
[golden fixtures](../internal/api/testdata/objectformats/), and
[metadata conformance](../test/conformance/metadata_matrix_test.go).

## Metadata Encryption and Compaction

The metadata registry retains short aliases and legacy expansion rules to support
provider header budgets. Compaction changes storage representation, not ownership
or client-visible fields. Provider limits and fallback formats differ; do not use
one old byte-count table as a universal envelope-size guarantee.

When configured, a separate 32-byte metadata key seals gateway encryption metadata
into `x-amz-meta-enc-metadata` (compact alias `em`). The encryption discriminator
remains outside the blob; user metadata is not automatically confidential. The
read path expands aliases, authenticates/decrypts the blob, and filters reserved
fields before response projection. Body fallback formats are authenticated format
variants, not an invitation to synthesize a legacy salt/IV layout.

Metadata-key generation, backup, loss, and safe replacement belong to the
[runbook](RUNBOOK.md#metadata-encryption-key-management). A gateway HEAD hides
internal encryption metadata; inspect it with authorized backend/read-only audit
access, not a client-visible-header assertion. Built-in compression was removed;
see [compressed-object migration](MIGRATION.md#removing-compression-v10).

## FIPS Build Profile

The optional `fips` build tag restricts local crypto to approved algorithms and
uses Go's FIPS module. **This gateway is not itself a CMVP-certified product.**
Verify the exact module version, binary, environment, key lifecycle, and external
KMS posture against your compliance requirements. See
[Go FIPS documentation](https://go.dev/security/fips140) and the NIST CMVP database
for current upstream evidence; these build instructions do not grant accreditation.

### Approved algorithms

| Use | Build-profile behavior |
|---|---|
| Payload AEAD | AES-256-GCM; ChaCha20-Poly1305 excluded |
| Password KDF | PBKDF2-HMAC-SHA256; Argon2id rejected |
| Nonce derivation / auth | HKDF/HMAC-SHA256 |
| Local envelope | AES-GCM KEK / RSA-OAEP-SHA256; memory provider AES key-wrap |
| Randomness / TLS | Go runtime/module behavior; verify deployment/module boundary |
| MD5 | S3 interoperability/non-security use, not security integrity |

External Transit/KMIP cryptography occurs in the external service. A FIPS-tagged
gateway does not certify the KMS/HSM, and the HSM adapter remains nonfunctional.

### Building a FIPS-compliant binary

```bash
make build-fips VERSION=dev
# bin/s3-encryption-gateway-fips-dev

GOFIPS140=v1.0.0 CGO_ENABLED=0 go build -tags=fips \
  -o bin/s3-encryption-gateway-fips ./cmd/server
```

Use the pinned `go.mod` toolchain (Go 1.27.1+). `GOFIPS140` is a build setting,
not a runtime switch that can retrofit a non-FIPS binary. The runtime must report
`crypto/fips140.Enabled()` true; startup `AssertFIPS` fails closed otherwise.
The shipped Dockerfile builds static binaries with **CGO disabled** using a
Bookworm builder and distroless nonroot runtime. It does not require glibc merely
because the image uses Debian.

### Docker and Helm

```bash
docker build -f Dockerfile.fips --build-arg VERSION=dev \
  -t s3-encryption-gateway:dev-fips .

helm template gateway helm/s3-encryption-gateway \
  -f helm/s3-encryption-gateway/values.fips.yaml
```

The FIPS overlay selects the FIPS image and sets its environment. Inspect rendered
values and preserve normal credentials, key setup, Valkey, writable spool, TLS,
and coordinated-upgrade prerequisites; FIPS does not bypass them. Default builds
cannot enable the profile just by setting a runtime variable. Switching algorithm
availability can make previously written ChaCha/Argon objects unreadable under the
restricted profile; inventory/migrate them before cutover.

### Auditor evidence and monitoring

Retain the exact source revision, build/module/toolchain settings, image digest,
SBOM/provenance, selected algorithms and key ceremony, test results, startup crypto
profile, and `gateway_fips_mode` metric. Separate local module evidence from external
KMS validation. Missing runtime activation or disallowed configuration must fail
startup/construction rather than silently fall back to a nonapproved algorithm.

```bash
GOFIPS140=v1.0.0 go test -tags=fips -race -short ./internal/crypto ./internal/config
```

Full gate commands live in [testing](TESTING.md). Algorithm approval alone does
not establish secure key storage or complete system compliance.

## Verification and References

- [Crypto source](../internal/crypto/): registry, formats, KDF limits, key managers.
- [Shared metadata](../internal/objectmeta/) and [API projection](../internal/api/object_response.go).
- [ADR 0005](adr/0005-fips-crypto-profile.md), [ADR 0009](adr/0009-encrypted-multipart-uploads.md),
  [ADR 0016](adr/0016-authenticated-chunked-completeness.md), [ADR 0018](adr/0018-centralized-object-metadata.md).
- [FIPS Dockerfile](../Dockerfile.fips), [Makefile](../Makefile), [tests](TESTING.md).

Historical plans contain conceptual interfaces and old formats. They remain
evidence, not current configuration or a claim that every workflow was certified.
