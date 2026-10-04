# Gateway Architecture

The gateway is a Go service between S3 clients and an object-store backend. It
authenticates and authorizes plaintext client requests, applies bucket encryption
policy, and stores ciphertext. Compatibility is deliberately bounded; consult
[S3 operations and limitations](S3_API_IMPLEMENTATION.md), not an assumption of
complete AWS parity.

## Contents

- [Request flow](#request-flow)
- [Component ownership](#component-ownership)
- [State and security boundaries](#state-and-security-boundaries)
- [Deployment and validation](#deployment-and-validation)

## Request Flow

```text
S3 client
  → HTTP middleware / payload verification
  → gateway authentication and bucket-scope authorization
  → API handler / encryption policy selection
  → crypto, shared metadata, multipart orchestration as required
  → backend client using configured backend credentials
  → S3-compatible object store
```

PUT encrypts according to bucket policy; bypass buckets deliberately store the
client's bytes unchanged. GET/HEAD classify the format, resolve size and metadata,
authenticate required preflight records, and project a plaintext-facing response.
Copy reads the authorized source and rebinds encrypted output to the destination.
Configuration subresources generally proxy backend XML rather than implement
missing backend features. Errors distinguish backend availability from integrity
failure; late stream failures cannot change already-written status headers.

## Component Ownership

| Component | Owner |
|---|---|
| Startup, listeners, dependency wiring | `cmd/server` |
| Request routing/auth, copy/MPU orchestration | `internal/api` |
| Validated config and ordered bucket policies | `internal/config` |
| AEAD formats, KDF limits, key providers | `internal/crypto` |
| Shared standard object fields | `internal/objectmeta` |
| Backend SDK/transport/adapters | `internal/s3` |
| Multipart content claims/lifecycle | `internal/mpu` |
| Advisory listing sizes | `internal/sizecache` |
| Operational listener and bearer auth | `internal/admin` |

The principal interfaces are `EncryptionEngine`, `KeyManager`, `StateStore`,
`SizeCache`, and `s3.Client`; read their source definitions rather than copied
pseudocode. API object-response/error helpers own client-visible projection.
See [encryption formats and metadata](ENCRYPTION_DESIGN.md) and
[contributor boundaries](DEVELOPMENT_GUIDE.md#code-ownership-and-conventions).

## State and Security Boundaries

- Gateway credentials and backend IAM are separate. Credential scopes authorize
  buckets and operations; encryption policies choose crypto behavior, never access.
- Payload AEAD binds current encrypted objects to bucket/key independently of a
  key provider's advisory metadata. Backend-native relocation is not a safe move.
- Encrypted MPU uses Valkey-backed immutable first-content claims and guarded
  completion/abort transitions. Changed part content is rejected rather than
  reusing deterministic nonces; replica state must remain shared and compatible.
- Valkey stores multipart routing and the plaintext-size index through one shared
  connection pool. State encryption is envelope-based; size cache behavior is
  advisory. Losing required MPU state fails closed, while listing misses may
  expose backend ciphertext sizes. See the [operations runbook](RUNBOOK.md).
- Verification may spool plaintext request bodies to private temporary files.
  Optional response and DEK caches also retain sensitive material; size their
  limits and protect the process/filesystem accordingly.
- File configuration reloads use validated component snapshots. These are not
  one global transaction; process-environment and many key settings require restart.

## Deployment and Validation

The production entry point uses `net/http` and registered API routes. Deploy with
TLS, separate operational access, protected keys, writable bounded spool storage,
and correct shared-state prerequisites. Container/Helm manifests, not historical
architecture examples, define the shipped images and settings.

- [Deployment/configuration](DEPLOYMENT.md)
- [Upgrade and rollback constraints](MIGRATION.md)
- [Capacity and horizontal scaling](PERFORMANCE.md)
- [Tests and provider-selection evidence](TESTING.md)
- [Accepted future work](ROADMAP.md)
- [Architecture decision records](adr/)

Go's concurrency, HTTP, crypto, and SDK ecosystem support this boundary design;
historical decisions are retained in ADRs rather than duplicated as implementation
phases or a blanket “production readiness complete” assertion here.
