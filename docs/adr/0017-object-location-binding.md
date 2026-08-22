# ADR 0017: Object Location Binding

## Status

Accepted. Implemented for current bound writes with explicit legacy dual-read
compatibility.

## Date

2026-08-22

## Context

Encrypted payloads can be copied or renamed by an operator or backend without
passing through the gateway. If authentication covers only ciphertext framing
and metadata, ciphertext from object A can be substituted for object B. KMS
provider request metadata is not a universal control: adapters may ignore
metadata and password mode has no provider at all. The gateway needs one
provider-independent boundary covering direct objects, chunked objects, and
encrypted multipart uploads.

## Decision

The gateway binds payload AEAD authentication to a trusted route-derived
`crypto.ObjectContext` containing the bucket and object key. The context is
never selected from untrusted manifest fields or provider metadata. New
encrypted writes generate a random nonzero 16-byte binding ID and carry that
ID in trusted main metadata and the authenticated payload/manifest protocol.

### Canonical AAD

The implementation uses domain-separated canonical AAD. The reference grammar
is the `buildObjectAAD` implementation in `internal/crypto/engine.go`: it
encodes the fixed prefix `S3EGAAD`, version `uint16_be(1)`, each domain,
bucket, key, and binding component as `uint32_be(length) || bytes`, followed by
`uint16_be(field_count)` and fixed-width `uint64_be` fields. Every integer is
big-endian and all fields are length-delimited; callers must not invent a
second framing.

The exact domains are protocol values, including the object/chunk domains for
buffered and chunked encryption, `aadMPUV2Chunk` for MPU data chunks, and
`aadMPUV2Manifest` for the encrypted MPU companion. The domain is part of the
authenticated grammar, so data, terminal, MPU chunk, and manifest uses cannot
be confused. SEC-37's chunked-v2 terminal extension remains the sole terminal
framing; this decision introduces no competing chunk or terminal format.

### Authentication and compatibility

Declared v2 formats require the expected marker, trusted binding, canonical
AAD, and authentication. A v2 authentication, relationship, or terminal
failure is final: readers do not fall back to generic or legacy decryption.
Legacy formats remain readable through explicit v1 paths only, allowing
operators to rewrite them through the gateway.

An encrypted MPU v2 manifest authenticates both the parent object and its
companion object relationship. The parent and companion use the same trusted
bucket context, exact keys, and one shared random binding ID. The main object's
trusted metadata selects the ID; a manifest-selected ID is never authoritative.

### Provider boundary and copy semantics

`KeyManager.WrapKey` and `UnwrapKey` metadata is advisory. Provider adapters may
ignore it, and it is not an object-location integrity mechanism. Payload AEAD
`ObjectContext` binding is enforced independently for password mode and all
KeyManager modes.

Gateway `CopyObject` always decrypts the source and re-encrypts the destination
under the destination context with a fresh binding, including when source and
destination keys are identical. It must not perform a backend-native encrypted
byte copy. A raw backend relocation of bound ciphertext plus metadata to a new
location fails authentication.

## Consequences

- Backend operators cannot relocate bound encrypted bytes by editing keys or
  metadata; the operation must be a gateway-mediated rewrite.
- Gateway copies and GET-through-gateway -> PUT-through-gateway migrations
  produce ciphertext authenticated for the destination location.
- Legacy objects remain readable, but migration is required to obtain current
  bound formats, including legacy MPU v1 rewrites.
- KMS adapters retain provider-specific envelope behavior without being
  responsible for payload location integrity.
- Tests must exercise exact data substitution and assert that authentication
  failures produce no plaintext.

## Migration

Operators must use gateway `CopyObject` or read the source through the gateway
and write the destination through the gateway. Backend-native move, copy, or
rename is not a supported migration mechanism. See `docs/MIGRATION.md` for
inventory, rewrite, and verification procedures.
