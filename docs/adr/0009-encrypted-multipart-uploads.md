# ADR 0009: Encrypted Multipart Uploads with Per-Upload DEK and Finalization Manifest

## Status
Proposed

## Context

ADR 0002 (*Multipart Upload Security Validation and Interoperability*) froze
multipart upload bodies as **plaintext on the backend** because the gateway
could not solve the "multiple independent AEAD streams cannot be decrypted
after S3-side concatenation" problem with the primitives available at the
time. ADR 0002 §Alternative 1 rejects per-part AEAD precisely on this
ground, and ADR 0006 §Future Considerations names the intended successor
design — "chunked-MPU with a finalization manifest on
`CompleteMultipartUpload`" — without specifying it.

Since ADR 0002 shipped, three pieces of infrastructure have landed that
change the calculus:

1. **Chunked AEAD format with per-chunk IV derivation and a JSON
   manifest** (`internal/crypto/chunked.go`, `internal/crypto/engine.go`
   `encryptChunked` at engine.go:793+). Per-chunk IV is derived by XORing
   the last 4 bytes of a base IV with a monotonic chunk index
   (`deriveChunkIV`, chunked.go:118-132). Each chunk is a standalone
   `ciphertext || 16-byte tag` blob.
2. **Envelope encryption via a pluggable `KeyManager`** (ADR 0004,
   `internal/crypto/keymanager.go:24-50`) that cleanly separates DEK
   generation from KEK wrap/unwrap, with working memory and Cosmian
   adapters.
3. **A metadata-fallback object pattern** for manifests that exceed
   S3's 2 KiB per-header / ~2 KB total `x-amz-meta-*` budget
   (`MetaFallbackMode`/`MetaFallbackPointer`, engine.go:51-52;
   `encryptChunkedWithMetadataFallback`, engine.go:961+). This already
   exists for single-object chunked encryption with large manifests.

The current state is also explicitly flagged in the product:

- `handleUploadPart` at `internal/api/handlers.go:2211-2295` has a
  dead `if uploadID == ""` branch — the multipart router at `:107`
  guarantees `uploadID` is non-empty — so every multipart part is
  buffered with `io.ReadAll` and forwarded **verbatim** to the backend.
- `handleCreateMultipartUpload`, `handleCompleteMultipartUpload`, and
  `handleAbortMultipartUpload` never touch `engine` or `keyManager`.
- `Server.DisableMultipartUploads` (`internal/config/config.go:172-173`)
  is the fail-closed escape hatch, making every multipart handler
  return `501 NotImplemented`. It is off by default for compatibility;
  this is the security hole the roadmap commits to close
  (`README.md:700`).

This ADR records the architectural decisions for closing the gap.

## Problem Statement

1. **Plaintext at rest for any object ≥ 8 MiB under AWS SDK defaults.**
   AWS CLI, boto3, `aws-sdk-go-v2`, and `minio-go` all auto-transition
   to multipart at small thresholds (5–16 MiB). For a gateway whose
   value proposition is "transparent encryption at rest", this is the
   headline defect.
2. **`DisableMultipartUploads=true` is not a real fix.** It caps objects
   at 5 GiB (single-PUT limit) and breaks every mainstream client's
   default behaviour.
3. **Per-part AEAD alone is insecure** (ADR 0002 §Alternative 1) if the
   only integrity boundary is the part — no trailer ties the parts
   together, a malicious or buggy backend could reorder/truncate parts
   undetectably, and nonce uniqueness across parts of one logical
   upload is not structurally enforced.
4. **Ranged GET and decryption across part boundaries** must continue
   to work. The existing `engine.DecryptRange` path
   (engine.go:1263, handlers.go:834) crosses chunk boundaries within a
   single manifest; the new design must extend that across part
   boundaries.

## Decision

Introduce **per-upload envelope encryption** with a **finalization
manifest** written at `CompleteMultipartUpload`. The scheme:

1. **One DEK per multipart upload.** `CreateMultipartUpload` generates a
   fresh 256-bit DEK via `generateDataKey` (engine.go:~400) and
   immediately wraps it using the resolved bucket-policy
   `KeyManager.WrapKey`. The wrapped envelope and a 12-byte random
   `iv_prefix` are pinned to this `uploadId` for the lifetime of the
   upload. The DEK itself is kept in memory only long enough to derive
   per-part keys, then zeroised.
2. **Deterministic per-part, per-chunk IV derivation.** For part
   `N ∈ [1, 10_000]` and intra-part chunk index `k ∈ [0, chunkCount(N))`,
   the 12-byte IV is:

       IV(N, k) = HKDF-Expand-Label(DEK, "mpu-iv" || uploadIdHash,
                                    iv_prefix || be32(N) || be32(k), 12)

   HKDF (RFC 5869) binds the IV to the wrapped-DEK, the upload identity,
   the part number, and the chunk position, giving structural nonce
   uniqueness per AEAD-GCM requirements
   (*Serious Cryptography* 2nd ed. §9.3; NIST SP 800-38D §8.2) without
   requiring a counter shared across parts. Two clients that race on
   the same `uploadId` for different parts cannot reuse an IV.
3. **Chunked AEAD per part.** Each `UploadPart` body is sealed with
   the existing `encryptChunked` pipeline, substituting the derived
   IV schedule above for the default XOR-counter and writing
   `partCiphertext = plain(N) + chunkCount(N) * 16` bytes to the
   backend. The backend sees 1 opaque blob per part; concatenation of
   these blobs at `CompleteMultipartUpload` yields a stream that the
   gateway can decrypt chunk-by-chunk given the manifest.
4. **Durable upload-state in Valkey.** Persistent state for an
   in-flight upload is held in a **Valkey** (or Redis-protocol-
   compatible) key-value store. Each upload maps to a single
   hash keyed `mpu:<uploadIdHash>` holding the wrapped-DEK,
   iv_prefix, algorithm, chunk_size, bucket/key, created_at,
   and per-part entries appended as `UploadPart` calls arrive.
   Keys carry a TTL (default 7 days, extended on every
   `UploadPart` via `EXPIRE`) so orphan uploads are cleaned up
   natively by Valkey — no reaper daemon required. The wrapped
   DEK is written with AES-256-GCM-wrap (standard `KeyManager`
   envelope); the Valkey connection is TLS-required in
   production. Chosen over backend-object state because:
   (a) per-part state PUTs add 50–500 ms of S3 round-trip to
   every `UploadPart` and compete with data PUTs for the same
   connection pool and provider request-rate quotas;
   (b) object-storage providers with minimum-storage-duration
   policies (Wasabi, AWS Glacier / Standard-IA / One Zone-IA)
   treat every state-object write as 30–90 days of billed
   storage plus a Timed Deleted charge on Complete/Abort,
   making the naive design economically prohibitive on those
   backends;
   (c) Valkey provides native atomic primitives (`HSET`,
   `SETNX`, Lua scripts, `EXPIRE`) that remove the optimistic-
   lock `If-Match` complexity needed for multi-replica backend-
   object state. Chosen over in-memory state because multi-
   replica gateway deployments would lose MPU state on any
   request routed to a different replica.
5. **Finalization manifest written at `CompleteMultipartUpload`.** On
   Complete the gateway reads state, validates the part list echoed by
   the client against its recorded per-part metadata, builds the
   manifest

       {
         "version": 1,
         "algorithm": "AES256-GCM",
         "chunk_size": 65536,
         "iv_prefix": "<base64>",
         "wrapped_dek": "<base64>",
         "kms_key_id": "...",
         "kms_provider": "cosmian",
         "parts": [
           {"n": 1, "enc_len": 5242928, "chunks": 80, "plain_len": 5242880},
           {"n": 2, "enc_len": 5242928, "chunks": 80, "plain_len": 5242880},
           ...
         ],
         "original_etag": "<md5-hex or multipart-etag-of-etags>"
       }

   and stores it either (a) inline in `x-amz-meta-encryption-manifest`
   if ≤ 1.8 KiB, or (b) in a companion object via the existing
   `MetaFallbackPointer` mechanism (engine.go:51-52, 961+). The final
   object's per-object metadata carries `x-amz-meta-encryption-mpu=v1`
   to distinguish MPU-encrypted objects from single-PUT chunked
   objects on the GET path.
6. **GET decrypts across part boundaries.** `engine.DecryptRange` is
   extended to accept a multipart manifest: the chunk iterator reads
   the `parts` array to map plaintext offset → `(part_index,
   chunk_index_within_part)` and reconstructs the exact IV via the
   HKDF schedule above. No change to the existing ranged-GET callers
   in `handleGetObject`; the manifest type is polymorphic.
7. **`AbortMultipartUpload` cleans up state.** Abort issues a
   `DEL mpu:<uploadIdHash>` to Valkey and emits an audit event.
   Orphan cleanup requires no daemon — Valkey expires stale keys
   automatically via the per-key TTL set at Create time.
8. **`UploadPartCopy` into an encrypted MPU re-encrypts under the
   per-upload DEK.** The three source classes from ADR 0006
   (plaintext, chunked, legacy) are re-encrypted with the destination
   upload's DEK + IV schedule; the fast path from ADR 0006 for
   plaintext-source/plaintext-dest no longer applies when the
   destination is an encrypted MPU.
9. **`DisableMultipartUploads` remains as the fail-closed escape
   hatch** for FIPS-restricted or paranoid deployments that prefer a
   5 GiB hard ceiling over any multipart flow.
10. **Rollout is opt-in per-bucket via policy.** A new
    `PolicyConfig.EncryptMultipartUploads` (default `false` in v0.6,
    default `true` once soaked in v0.7) controls the behaviour. When
    `false`, the legacy plaintext-parts path from ADR 0002 continues
    unchanged.

## Rationale

### Why per-upload DEK rather than reusing the per-bucket DEK

A per-upload DEK keeps the IV derivation simple — the tuple
`(part_number, chunk_index)` is naturally unique within one DEK's
lifetime. Re-using a bucket-level DEK would force IV derivation to
include `(bucket, key, uploadId, part, chunk)`, which works but
conflates key scope with object scope and complicates rotation (an
object written pre-rotation would have to be decryptable
post-rotation using the same bucket DEK). A per-upload DEK is also
the AWS Encryption SDK's convention (one "data key" per encryption
context; see *AWS Security Cookbook* [4] ch. "Client-side encryption
with KMS"), which pays off in future AWS-ESDK interop.

### Why HKDF rather than counter-XOR for IV derivation

The existing single-object chunked format XORs the chunk index into
the last 4 bytes of the base IV (chunked.go:118-132). That works for
up to ~4 billion chunks within one DEK's lifetime and is fine for a
single object. For MPU we need IVs derived from
`(uploadId, part, chunk)` without the part counter and chunk counter
interfering in the lower bits. HKDF-Expand with a labelled `info`
field is the standard primitive for this keyed-IV-derivation pattern
(*Real-World Cryptography* [1] §8.4 "Deriving keys from a master
secret"; *Serious Cryptography* 2nd ed. [2] §9.5 "Nonce generation").
The IV is 96 bits, matching AES-GCM's native nonce length, avoiding
the GHASH-based derivation penalty of larger nonces.

### Why a manifest rather than a per-part trailer

ADR 0002 §Alternative 1 rejected a per-part trailer format because it
requires every downstream tool (analytics, `aws s3 cp`) to parse a
custom frame format. A manifest in object metadata preserves
backend-opaque storage: the concatenated ciphertext is a pure byte
stream, and the manifest tells the gateway how to carve it back into
chunks. This also enables ranged GET at full efficiency because the
manifest records per-part `enc_len` and `chunk_count`, so a plaintext
range translates directly to a backend byte range without any
per-part scanning (NIST SP 800-108 "Key Derivation" §4 describes the
same separation of data and structure).

### Why Valkey rather than a backend-object state store

An earlier draft of this ADR placed upload state in the S3
backend itself at `.sgw-mpu/<uploadId>.state`, rationalised as
"no new infrastructure." That draft was abandoned for three
converging reasons:

1. **Latency tax on every `UploadPart`.** A backend-object state
   design requires one S3 `PUT` per `UploadPart` to persist the
   growing part list. At typical S3 p50 latencies of 20–100 ms
   per request (higher for cross-region or non-hyperscaler
   backends), a 1 000-part upload would accrue 20–100 seconds of
   wall-clock latency purely on state I/O, competing with the
   actual data `PUT`s for the same HTTP connection pool and
   SigV4 signer. A Valkey `HSET` over a local socket or VPC
   link is sub-millisecond — a 50–500× improvement on state-op
   latency and moves the traffic off the S3 request budget
   entirely (AWS recommends ≤ 3 500 `PUT`/sec per prefix, a cap
   the state prefix would consume under high concurrency).

2. **Billing hostility on minimum-storage-duration backends.**
   **Wasabi**'s Minimum Storage Duration Policy [13] bills every
   object for at least 90 days on Pay-Go (30 days on Reserved
   Capacity) regardless of when it is deleted; **overwrites
   count as delete-plus-create**, so no coalescing strategy
   avoids the cost. AWS S3 Standard-IA / One Zone-IA / Glacier
   Instant Retrieval have 30-day minimums; Glacier Flexible
   Retrieval / Deep Archive have 90-day minimums. A 1 000-part
   upload would create 1 000 state-object generations, each
   billed for the full minimum retention period —
   ≈ 45 GB·days of phantom billed storage per upload on
   Wasabi Pay-Go. Strategy redesigns (coalesced overwrites,
   append-only logs) do not solve this because Wasabi treats
   each distinct write as a billable object. The repository
   already flags this class of issue for test cleanup in
   `test/cleanup_helper.go:18-37`.

3. **Multi-replica correctness.** Backend-object state needs
   optimistic-lock `If-Match` on `PUT` to serialise concurrent
   appends from different gateway replicas — a primitive not
   uniformly supported across S3-compatible backends
   (Wasabi, B2, Hetzner conformance varies). Valkey has native
   atomic primitives (`HSET`, `SETNX`, Lua-scripted CAS,
   `EXPIRE`) that make the multi-replica case trivial without
   sticky session routing.

**Valkey is the right choice specifically** because: (a) it is
the BSD-3 licensed, Linux-Foundation-stewarded fork of Redis
with 100 % wire-compatibility — the gateway speaks the Redis
protocol, so operators who already run Redis can point at their
existing cluster; (b) it ships official Helm charts and Docker
images, matching the existing deployment model for MinIO/Garage
in test harnesses (`test/docker-compose.yml`); (c) TTL-based
expiry replaces a custom reaper daemon; (d) operational burden
is modest for SRE teams already running Kubernetes and
negligible for Docker-Compose deployments.

**Trade-off:** one additional infrastructure dependency. For
deployments that absolutely cannot add Valkey, the fail-closed
escape hatch (`Server.DisableMultipartUploads=true`) remains
available — it caps objects at the 5 GiB single-PUT limit but
requires no state store at all. This is documented in
§Consequences.

### Why AEAD authenticity is preserved across concatenation

Each chunk is individually authenticated. The manifest is
authenticated as part of the object's `x-amz-meta-*` set under SigV4
when the client supplies integrity headers, and the manifest's
`original_etag` is verified at Complete time against the ETag-of-ETags
that S3 derives from the concatenated part list. A malicious backend
swapping parts would produce a manifest mismatch (different
`enc_len`) or fail chunk-tag verification on GET
(*Security Engineering* 3rd ed. [3] §5.3 on authenticated
multipart protocols).

### Why per-bucket opt-in rather than global switch

Deployments that pin object layout for compliance reasons (e.g.
migrations, data-gravity contracts) cannot absorb a format change
silently. Per-bucket policy lets operators enable encrypted-MPU on a
bucket after a dry run, and ADR 0007's key-rotation state machine
already has the `RotatableKeyManager` hooks needed to manage
in-flight uploads during rollout transitions.

## Consequences

### Positive

- **Plaintext-at-rest hole closed** for the default client path
  (≥ 8 MiB objects via AWS SDK auto-multipart).
- **Ranged GET works** against MPU-encrypted objects with the same
  efficiency as chunked single-PUT objects.
- **Sub-millisecond state ops.** MPU state traffic moves off S3
  onto Valkey — no per-part S3 round-trip, no contention with
  data `PUT`s, no impact on provider request-rate budgets.
- **Backend-agnostic cost profile.** No minimum-storage-
  duration surprises on Wasabi, Glacier, Standard-IA, etc.
- **Reuses every existing crypto primitive**: chunked AEAD, HKDF
  (already imported by `golang.org/x/crypto`), KeyManager envelope,
  fallback-pointer metadata. Net-new crypto surface is the HKDF IV
  derivation and the manifest schema.
- **Native TTL expiry** replaces a custom reaper daemon: set
  `EXPIRE mpu:<uploadIdHash> 604800` at Create, refresh on
  each `UploadPart`; stale uploads vanish automatically.
- **Native atomic primitives** remove the optimistic-lock
  `If-Match`-on-PUT complexity of backend-object state.
  Multi-replica deployments work without sticky routing.
- **Compatible with ADR 0007 rotation** — the wrapped-DEK is version-
  tagged; rotation of the KEK re-wraps DEKs of in-flight uploads or
  force-aborts them via the admin API.
- **FIPS-compliant** — AES-256-GCM and HKDF-SHA256 are both FIPS-140
  approved (see ADR 0005); no ChaCha20 dependency.

### Negative

- **One new infrastructure dependency: Valkey** (or any Redis-
  protocol-compatible KV). Docker-Compose users add one
  container; Kubernetes users add one Helm dependency; bare-
  metal users install one package. Users who categorically
  cannot add Valkey must use
  `Server.DisableMultipartUploads=true` instead — the fail-
  closed escape hatch is preserved.
- **Valkey becomes a hard-availability dependency for
  multipart uploads.** If Valkey is unreachable, `Create` /
  `Upload` / `Complete` / `Abort` return `503 ServiceUnavailable`.
  Single-PUT encryption and GET of already-complete objects are
  unaffected. Mitigated by: (a) Valkey Sentinel or Cluster for
  HA in production; (b) a health-gauge metric so operators
  observe Valkey health; (c) documented runbook entry for
  Valkey failover.
- **State durability is bounded by Valkey's persistence
  settings.** With default `appendonly yes` + `appendfsync
  everysec`, a Valkey crash can lose ≤ 1 s of state writes. A
  client whose `UploadPart` was acknowledged but whose state
  row was lost must retry that part number; the IV schedule is
  deterministic and the resulting ciphertext is byte-identical,
  so retries are safe. Documented behaviour; acceptable
  trade-off for the latency benefit.
- **Part-number-dependent IV schedule** means part re-upload must use
  the same part number. This matches the S3 contract (UploadPart is
  idempotent per `(uploadId, partNumber)`) and does not introduce a
  new constraint, but must be explicitly documented because the
  previous plaintext-parts design was fully part-number-agnostic.
- **Manifest grows O(parts)**. 10 000 parts × ~50 bytes JSON ≈ 500
  KiB. Must use fallback-object pointer for any upload with > ~30
  parts. No new primitive — the pointer exists.
- **UploadPartCopy fast path disappears** for encrypted-MPU
  destinations. ADR 0006's plaintext-to-plaintext backend-native copy
  is no longer viable; every copy into an encrypted MPU mediates.

### Neutral

- Single-PUT chunked and legacy single-AEAD paths are unchanged.
- Object Lock (ADR 0008) interaction is unchanged — the manifest is
  part of object metadata and is locked together with the object at
  Complete time.

## Alternatives Considered

### Alternative A — Buffer-and-seal at `CompleteMultipartUpload`

Accept parts as plaintext into a staging prefix; at Complete, run the
existing `engine.Encrypt` over the concatenated stream and PUT to the
final key. Rejected because it: (a) materialises plaintext at rest,
even if briefly, breaking the threat model; (b) doubles storage I/O;
(c) forfeits multipart's restartability; (d) re-uploads the whole
object, defeating the purpose of MPU.

### Alternative B — Per-part self-contained envelope

Each part embeds its own trailer (IV || tag || wrapped DEK). No
manifest needed. Rejected per ADR 0002 §Alternative 1: breaks all
downstream tooling that reads raw S3 objects, custom frame format,
range reads misalign with plaintext ranges.

### Alternative C — Adopt `aws/aws-encryption-sdk-go`

Adopt the AWS Encryption SDK (Go port) for the encryption pipeline
wholesale. Rejected because the SDK is still labelled developer
preview as of 2025, conflicts with the gateway's `KeyManager`
abstraction, maintains an incompatible on-disk format, and couples
the project to an external library's lifecycle. Revisit when the SDK
stabilises and exposes the underlying keyring interface for adapter
use.

### Alternative D — Make `DisableMultipartUploads` the default

Already documented in ADR 0002; rejected again here because a 5 GiB
ceiling breaks the mainstream use case. Retained as a fail-closed
escape hatch for deployments that cannot run Valkey.

### Alternative E — Backend-object state (`.sgw-mpu/<uploadId>.state`)

Store per-upload state as an encrypted side-object in the same
bucket, written through the existing single-PUT chunked path, with a
reaper daemon for orphan cleanup. Rationale was "no new
infrastructure component." Rejected because: (a) one S3 `PUT` per
`UploadPart` adds 20–500 ms of sequential latency per part and
competes with data `PUT`s for the provider's request budget;
(b) minimum-storage-duration backends (Wasabi Pay-Go: 90 days; AWS
Glacier / Standard-IA: 30–90 days) bill every distinct state-object
write — **including overwrites, because the provider bills the
superseded version for its remaining retention period** — making a
1 000-part upload produce ~45 GB·days of phantom billed storage on
Wasabi; (c) multi-replica correctness requires conditional-PUT
(`If-Match`) support, which not all S3-compatible backends implement
uniformly; (d) reaper logic for orphan cleanup replicates what a
Valkey TTL provides for free. The latency and cost issues (a–b)
are not architecturally fixable with coalescing or append-only
logs on minimum-duration backends, which forced the redesign.

### Alternative F — In-memory state on the gateway

Zero infrastructure; state lives in a `sync.Map`. Rejected because
multi-replica deployments routinely route `CreateMultipartUpload`
and `UploadPart` to different replicas via round-robin load
balancers; losing state on every non-sticky request is fatal. Even
single-replica deployments lose all in-flight uploads on any
restart. Valkey provides the same latency profile
(sub-millisecond) with cross-replica visibility and persistence.

## Implementation Details

### New and Modified Files

- **New** `internal/crypto/mpu_manifest.go` — `MultipartManifest`
  type, JSON marshalling, size budget check vs.
  `x-amz-meta-encryption-manifest` inline limit.
- **New** `internal/crypto/mpu_iv.go` — `DeriveMultipartIV(dek,
  uploadId, ivPrefix, part, chunk)` using HKDF-Expand from
  `golang.org/x/crypto/hkdf`.
- **New** `internal/mpu/state.go` — `UploadState` record,
  `StateStore` interface, `ValkeyStateStore` implementation
  using `github.com/redis/go-redis/v9` (Redis protocol, works
  against Valkey and Redis alike). `StateStore` is an interface
  in case future implementations are added but v0.6 ships
  Valkey-only; in-memory and backend-object variants are
  explicitly rejected in §Alternatives. Keys are
  `mpu:<base64url(sha256(uploadId))>`, fields are JSON-encoded
  state records, TTL set at Create and refreshed on every
  `UploadPart`.
- **Modified** `internal/api/handlers.go` —
  `handleCreateMultipartUpload` generates DEK+wraps+writes state;
  `handleUploadPart` encrypts when `UploadState` exists;
  `handleCompleteMultipartUpload` reads state, builds manifest,
  persists metadata/fallback, deletes state;
  `handleAbortMultipartUpload` deletes state.
- **Modified** `internal/api/upload_part_copy.go` — re-encrypt
  every source class into the destination's MPU DEK when the
  destination is an encrypted MPU. Plaintext fast path becomes
  conditional on destination not being an encrypted MPU.
- **Modified** `internal/crypto/engine.go` — `DecryptRange`
  accepts either a chunked manifest or a multipart manifest
  (polymorphism via a sealed-interface `Manifest`). IV
  derivation routed through `mpu_iv.go` when multipart.
- **Modified** `internal/config/policy.go` —
  `PolicyConfig.EncryptMultipartUploads bool`, default false.
- **Modified** `internal/metrics/metrics.go` —
  `gateway_mpu_encrypted_total{result}`,
  `gateway_mpu_state_store_ops_total{op,result}`,
  `gateway_mpu_orphan_state_objects_total`.
- **Modified** `internal/crypto/chunked.go` — no changes to on-wire
  format; MPU variant reuses the same chunk framing and only swaps
  the IV schedule.

### IV Derivation Pseudocode

```go
// internal/crypto/mpu_iv.go
import "golang.org/x/crypto/hkdf"

// DeriveMultipartIV produces a 96-bit AES-GCM nonce for a specific
// (uploadId, part, chunk) position. dek and ivPrefix come from the
// per-upload state. Safe to call concurrently (stateless).
func DeriveMultipartIV(
    dek []byte,
    uploadIDHash [32]byte, // sha256(uploadId) — upload IDs are opaque strings
    ivPrefix [12]byte,
    partNumber uint32,
    chunkIndex uint32,
) [12]byte {
    var info [12 + 4 + 4]byte
    copy(info[0:12], ivPrefix[:])
    binary.BigEndian.PutUint32(info[12:16], partNumber)
    binary.BigEndian.PutUint32(info[16:20], chunkIndex)

    // salt = uploadIDHash binds the derivation to the upload's identity
    // info = ivPrefix || be32(part) || be32(chunk) binds to position
    r := hkdf.Expand(sha256.New, dek, append(uploadIDHash[:], info[:]...))
    var iv [12]byte
    _, _ = io.ReadFull(r, iv[:])
    return iv
}
```

(See *Real-World Cryptography* [1] §8.4 for the HKDF-Expand-for-IV
pattern and *Serious Cryptography* 2nd ed. [2] §9.5 for why HKDF
output IVs are safe for AES-GCM despite not being uniform random —
HKDF's collision resistance under SHA-256 is > 128 bits, well above
the AES-GCM IV-collision threshold of 2^32 encryptions per key.)

### State Record Schema (Valkey hash at `mpu:<uploadIdHash>`)

Each hash field holds a JSON-encoded fragment; the upload-level
metadata is stored under field `meta` and each part under field
`part:<N>`. This layout allows `HSET` + `HGET` + `HDEL` to
address individual part records atomically without re-writing
the full state.

```
Key:   mpu:<base64url(sha256(uploadId))>
TTL:   604800 seconds (7 days), refreshed on every UploadPart
Fields:
  meta        = {
    "version": 1,
    "upload_id": "<opaque-backend-id>",
    "bucket": "<dst-bucket>",
    "key": "<dst-key>",
    "created_at": "2026-04-20T10:00:00Z",
    "wrapped_dek": "<base64>",
    "kms_key_id": "kms-root-v3",
    "kms_provider": "cosmian",
    "key_version": 3,
    "iv_prefix": "<base64 12 bytes>",
    "upload_id_hash": "<base64 32 bytes>",
    "algorithm": "AES256-GCM",
    "chunk_size": 65536,
    "policy_snapshot": {"encrypt_multipart": true}
  }
  part:1      = {"n": 1, "enc_len": 5242928, "chunks": 80,
                 "plain_len": 5242880, "etag": "\"aaaa...\""}
  part:2      = {...}
  ...
```

**Wrapped-DEK at rest in Valkey.** The DEK is wrapped by the
bucket's `KeyManager.WrapKey` before being written to Valkey.
Valkey sees only ciphertext. An attacker with full Valkey-read
access cannot recover plaintext DEKs without also compromising
the `KeyManager` (Cosmian KMIP, HSM, etc.). TLS is **required**
on the Valkey connection in production (`tls.MinVersion =
TLS1.3`); the gateway fails closed at startup if
`MultipartState.Valkey.TLS.Enabled=false` and
`MultipartState.Valkey.InsecureAllowPlaintext=false` (default).

**Atomic `Create`.** Uses `HSETNX mpu:<h> meta <json>` to prevent
two concurrent `CreateMultipartUpload` calls on the same upload
id from racing.

**Atomic `AppendPart`.** `HSET mpu:<h> part:<N> <json>` +
`EXPIRE mpu:<h> 604800` in a `MULTI`/`EXEC` pipeline (a
two-command Lua script for older Valkey versions).

**`Complete` / `Abort`.** `DEL mpu:<h>` (single command, atomic).

### Manifest Size Budget

S3's combined per-header limit for `x-amz-meta-*` is 2 KB (AWS),
~8 KB (MinIO), 2 KB (Wasabi, B2). We budget **1.8 KiB** for the
inline manifest to leave headroom for other headers. At 50 bytes
per part entry, that's ~30 parts inline. Any upload with more parts
writes the manifest to a fallback object
`<backend-key>.enc-manifest` via the existing
`MetaFallbackPointer` path (engine.go:961+) — the main object's
metadata carries only the pointer.

### Failure Modes and Recovery

| Failure | Behaviour |
|---|---|
| Valkey unreachable at CreateMultipartUpload | Return 503 ServiceUnavailable; no backend multipart created yet → no orphan. Client retries. |
| Valkey unreachable at UploadPart | Return 503 ServiceUnavailable; client retries. Backend part may or may not have been uploaded yet depending on order of operations (see note on write-order below). |
| Valkey unreachable at CompleteMultipartUpload | Return 503 ServiceUnavailable; backend multipart remains in-flight; client retries or issues Abort. Re-issuing Complete after Valkey recovers is idempotent because the state record is still present. |
| Valkey unreachable at AbortMultipartUpload | Return 503 ServiceUnavailable; backend multipart is also aborted in the same handler call, so either both succeed or neither. Orphaned Valkey state (backend aborted but Valkey delete failed) expires automatically via TTL. |
| `HSET part:<N>` fails post-backend-PUT of part | Return 500 InternalError; client retries same part number; IV schedule is deterministic so ciphertext is byte-identical on retry; no nonce reuse. |
| Valkey crash with AOF loss of ≤ 1 s of writes | State record may be missing the most recent part entries. Client's subsequent Complete fails validation (part list mismatch); client retries the missing parts. Byte-identical retries are safe. |
| Gateway crashes between backend Complete and manifest metadata attach | Manifest is supplied as metadata *to* the Complete call, so the backend's Complete is atomic wrt manifest — there is no window. If the backend Complete itself fails, state remains in Valkey and the client retries. |
| Client replays UploadPart with different body | Backend overwrites part; `HSET part:<N>` overwrites the entry with new `enc_len`/`chunks`. Not a security issue because only the final concatenation is decryptable and Complete validates the manifest against the ETag-of-ETags. |
| Orphaned state (client never calls Complete/Abort) | Valkey TTL expires the key after 7 days. No manual cleanup required. Prometheus counter `gateway_mpu_state_ttl_expired_total` increments so operators can observe the pattern. |

**Write-order within `UploadPart`.** The handler performs
`HSET part:<N>` **after** a successful backend `UploadPart`,
then refreshes TTL. This ordering means a backend `PUT` without
a recorded state row is possible on crash (the client retries,
backend overwrites, state converges on next successful part).
The reverse ordering would risk a state row without a backend
part — a harder inconsistency to recover from because `Complete`
cannot validate it against an ETag that does not exist.

## Security Considerations

### Threat Model Expansion

ADR 0002's threat model covers the backend-as-adversary for the
plaintext-parts path. This ADR extends it:

- **IV-reuse resistance.** Structurally impossible within one
  `uploadId` given deterministic HKDF derivation. Across two
  `uploadId`s with the same DEK: impossible by construction
  (DEK is per-upload).
- **Part reordering attack.** Manifest records
  `(part_number → enc_len, chunk_count)`. Reordered parts produce
  wrong IVs during decryption → every chunk tag fails → GET returns
  500 + audit event. Not silently decryptable.
- **Part truncation attack.** Manifest records total plaintext
  length; ranged GET honouring the manifest detects missing bytes.
  A backend that truncates the final part produces a tag-verification
  failure on the last chunk.
- **Valkey state tampering.** An attacker with write access to
  Valkey could substitute a wrapped-DEK from another upload.
  `KeyManager.UnwrapKey` uses the upload's metadata context as
  AAD; a swapped envelope fails unwrap. An attacker who produces
  a forged wrapped-DEK from scratch cannot do so without
  compromising the `KeyManager` (Cosmian KMIP, HSM). An attacker
  who substitutes part records to redirect IV derivation
  produces wrong IVs → AEAD tag failure on GET → fail closed.
- **Valkey read disclosure.** *(Risk mitigated in v1.0 by
  V1.0-CRYPTO-2.)* An attacker with read-only Valkey access
  previously saw wrapped DEKs, IV prefixes, bucket names, object
  keys, and per-part `enc_len`/`chunks`/`etag` — metadata, no
  plaintext. As of v1.0, when `valkey.encrypt_state=true`
  (default), the entire `UploadState` blob is sealed with
  AES-256-GCM (key derived via HKDF-SHA256 from
  `VALKEY_ENCRYPTION_PASSWORD` or the main gateway password with a
  distinct salt `"s3eg-mpu-state-v1"`). A read-only attacker sees
  only opaque ciphertext. Recovering any metadata still requires
  both the encryption key and the `KeyManager`. The
  `gateway_mpu_state_encrypted_writes_total` Prometheus counter
  confirms active encryption; `gateway_mpu_state_legacy_reads_total`
  tracks legacy unencrypted blobs still present during migration.
- **Valkey in-transit.** TLS 1.3 required in production; gateway
  refuses to start with plaintext Valkey + encrypted MPU
  enabled unless the operator explicitly sets
  `MultipartState.Valkey.InsecureAllowPlaintext=true` (dev only;
  emits a loud startup warning and a Prometheus
  `gateway_mpu_valkey_insecure=1` gauge).
- **Replay / rollback.** A rolled-back Valkey snapshot could
  replay an older state. Because Valkey `Complete` deletes the
  key, a rolled-back snapshot resurrects an already-committed
  upload's state; subsequent reads of the final object still
  decrypt correctly because the final object's metadata carries
  the manifest directly. The risk is a confused-deputy replay
  where the gateway believes an old upload is still in-flight
  and accepts more parts — mitigated by the `policy_snapshot`
  recorded at Create time (rejects parts if the bucket's policy
  has since flipped to forbid multipart) and by the `created_at`
  timestamp which must be within the TTL window. Full
  cryptographic rollback protection (signed state with a
  monotonic counter in the `KeyManager`) is deferred to v0.7.

### FIPS Compliance

All primitives (AES-256-GCM, HKDF-SHA256, PBKDF2-HMAC-SHA256) are
FIPS-140 approved. The existing FIPS profile (ADR 0005) is
unchanged. `TestMPU_FIPS` will run the full round-trip under
`-tags=fips`.

### Audit Events

Five new events:

- `mpu.create` — uploadId, bucket, key, KeyManager version.
- `mpu.part` — uploadId, partNumber, encrypted bytes, duration.
- `mpu.complete` — uploadId, manifest size, inline-vs-fallback,
  total bytes.
- `mpu.abort` — uploadId, reason (client / ttl_expired), state
  existed.
- `mpu.valkey_unavailable` — endpoint, operation, error. Emitted
  on every transient Valkey failure to aid operator diagnosis.

## Cross-References

- **ADR 0002** *Multipart Upload Interoperability* — supersedes the
  "parts are plaintext" design decision for buckets with
  `EncryptMultipartUploads=true`. ADR 0002 remains the canonical
  reference for the XML-parsing / validation layer, which is
  unchanged.
- **ADR 0004** *HSM Adapter Contract* — the per-upload DEK wrap/
  unwrap flows through the standard `KeyManager` interface; any
  adapter that passes the rotation conformance suite works here.
- **ADR 0005** *FIPS Crypto Profile* — all primitives approved.
- **ADR 0006** *UploadPartCopy* — extended: plaintext-source fast
  path is disabled when the destination is an encrypted MPU.
- **ADR 0007** *Admin API and Key Rotation* — `RotatableKeyManager`
  drain semantics apply to in-flight uploads; a rotation's "commit"
  phase queries Valkey (`SCAN mpu:*`) for active uploads and
  blocks until each has either completed, aborted, or been
  re-wrapped to the new KEK version.
- **ADR 0008** *Object Lock Ciphertext Semantics* — no change;
  object lock attaches to the final object with the manifest.
- **V0.6-SEC-3** — issue that tracks the implementation of this ADR.

## Future Considerations

1. **Valkey HA patterns.** Document Sentinel and Cluster-mode
   deployments in the operations runbook. The Go client
   (`go-redis/v9`) supports both transparently; the gateway
   just needs connection-string configuration.
2. **Additional `StateStore` implementations.** If operators
   demand DynamoDB or etcd backends in v0.7+, the `StateStore`
   interface accommodates them. Not shipping in v0.6 to avoid
   premature generalisation; the interface exists to preserve
   future freedom, not to enable immediate alternatives.
3. **AWS-ESDK interop.** When the AWS Encryption SDK for Go
   stabilises, evaluate exposing the manifest in the AWS ESDK
   message format for bidirectional interop.
4. **Client-side per-part integrity.** Allow clients to supply
   `x-amz-content-sha256` per part; include in manifest for
   end-to-end integrity beyond AEAD.
5. **Cryptographic rollback protection** on Valkey state: sign
   the state record with a monotonic counter held in the
   `KeyManager` so a rolled-back Valkey snapshot cannot replay
   an older state (noted above under §Security Considerations).
6. **Write-behind caching.** In-process memory cache in front of
   Valkey for read-heavy GET paths (unlikely to matter in
   practice since GET uses the manifest in object metadata, not
   Valkey — Valkey is touched only during multipart flows).

## References

1. David Wong, *Real-World Cryptography* (Manning, 2021),
   ch. 8 §4 "Deriving keys from a master secret" and ch. 4
   "Authenticated encryption."
   https://learning.oreilly.com/library/view/-/9781617296710VE/
2. Jean-Philippe Aumasson, *Serious Cryptography, 2nd Edition*
   (No Starch, 2024), §9.3 "AES-GCM" and §9.5 "Nonce generation for
   AEAD."
   https://learning.oreilly.com/library/view/-/9781098182472/
3. Ross Anderson, *Security Engineering, 3rd Edition* (Wiley, 2020),
   §5.3 on authenticated multipart protocols and key hierarchies.
   https://learning.oreilly.com/library/view/-/9781119642787/
4. Heartin Kanikathottu, *AWS Security Cookbook* (Packt, 2020),
   "Client-side encryption with AWS KMS" recipe — reference for the
   one-DEK-per-upload + per-part-IV convention.
   https://learning.oreilly.com/library/view/-/9781838826253/
5. Bryan Krausen, *Amazon S3 Deep Dive* (Packt video, 2024) —
   constraints imposed by S3's server-side concatenation of
   multipart parts and the ETag-of-ETags contract.
   https://learning.oreilly.com/videos/-/9781836203414/
6. Neil Madden, *API Security in Action* (Manning, 2021), ch. 6
   "Self-contained tokens" and envelope-encryption patterns —
   applied here to the per-upload DEK + wrapped envelope model.
   https://learning.oreilly.com/library/view/-/9781617296024/
7. Heather Adkins et al., *Building Secure and Reliable Systems*
   (O'Reilly / Google, 2020), ch. 5 "Design for Least Privilege"
   and ch. 10 "Self-Inflicted Attacks" — opt-in default for
   `EncryptMultipartUploads` and the fail-closed state semantics.
   https://learning.oreilly.com/library/view/-/9781492083115/
8. Brandon Rich, *AWS Certified Developer Study Guide, 2nd Edition*
   (Sybex, 2025) — canonical description of AWS SDK's multipart
   encryption conventions (per-upload data key, per-part IV
   indexed by part number).
   https://learning.oreilly.com/library/view/-/9781394274802/
9. NIST SP 800-38D, *Recommendation for Block Cipher Modes of
   Operation: Galois/Counter Mode (GCM) and GMAC*, §8.2 "IV
   Construction" and §8.3 "Constraints on the number of
   invocations."
10. RFC 5869, *HMAC-based Extract-and-Expand Key Derivation
    Function (HKDF)*.
11. AWS S3 API — *Multipart Upload Overview*.
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
12. AWS Encryption SDK — *Message Format Reference* (for
    comparison of envelope layout).
    https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html
13. Wasabi, *Minimum Storage Duration Policy*. 90-day default
    minimum on Pay-Go, 30 days on Reserved Capacity Storage.
    Overwrites count as delete-plus-create for billing purposes
    — the superseded generation is billed for its remaining
    retention period regardless.
    https://docs.wasabi.com/docs/how-does-wasabis-minimum-storage-duration-policy-work
14. AWS S3 — *Storage class comparison*. 30-day minimum for
    Standard-IA, One Zone-IA, Glacier Instant Retrieval;
    90-day minimum for Glacier Flexible Retrieval; 180-day
    minimum for Glacier Deep Archive.
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html
15. Valkey project. BSD-3-licensed, Linux Foundation stewarded
    fork of Redis; wire-protocol compatible.
    https://valkey.io/
16. `redis/go-redis/v9` Go client library; speaks the Redis
    protocol against Valkey, Redis, and other
    protocol-compatible stores.
    https://github.com/redis/go-redis
