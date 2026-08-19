# ADR 0016: Authenticated Chunked Completeness

## Status

Accepted. V2 is implemented; V1 remains readable and is explicitly selected for compatibility reads only. New v2 writers receive version 2 and the terminal AEAD through typed constructors and reject unknown versions or a missing terminal AEAD.

## Context

The versioned encrypt-reader wrapper accepts the independently constructed
terminal `cipher.AEAD` explicitly. The engine owns the DEK and constructs this
AES-256-GCM instance; the wrapper never derives a terminal key from an opaque
data AEAD or receives raw key material.

The existing v1 chunked format independently authenticates data records but does not authenticate end-of-object state. Removing complete trailing records can therefore leave a shorter stream whose remaining records verify. A reader cannot distinguish that truncation from an intentional shorter object.

## Decision

Introduce a versioned v2 format. Data records remain independently authenticated, and a fixed terminal record is appended:

```text
DataRecord_0 || ... || DataRecord_(N-1) || TerminalRecord
```

The terminal uses AES-256-GCM, contains exactly 16 plaintext bytes, and is therefore exactly 32 bytes including its 16-byte tag. Its plaintext is two network-order uint64 values:

```text
uint64_be(data-record-count) || uint64_be(total-plaintext-size)
```

An empty v2 object consists only of the terminal record encoding `(0, 0)`.

### Domains

For v2, HKDF-SHA-256 derives 12-byte nonces from the manifest base IV. The exact `info` values are:

```text
Data nonce:     "chunked-v2/data-nonce" || 0x00 || uint64_be(index)
Terminal nonce: "chunked-v2/terminal-nonce" || 0x00
```

The exact AAD values are:

```text
Data:     "chunked-v2/data" || 0x00 || uint64_be(index)
Terminal: "chunked-v2/terminal" || 0x00
```

The fixed labels make data and terminal nonce domains disjoint. Fixed-width fields make AAD encoding unambiguous. All integer fields use big-endian network byte order.

### Known-answer vectors

For base IV `424242424242424242424242`, HKDF-SHA-256 output (12 bytes) is:

```text
data nonce index 0          = 6d644467c05283e8db1c8252
data nonce index 18446744073709551615 = 08856a568afb01fe3a1a9b7f
terminal nonce               = 144496f4b7471b156ee4c11b
```

The corresponding exact AAD bytes are:

```text
Data index 0 = 6368756e6b65642d76322f64617461000000000000000000
Data index MaxUint64 = 6368756e6b65642d76322f6461746100ffffffffffffffff
Terminal = 6368756e6b65642d76322f7465726d696e616c00
```

The terminal nonce differs byte-for-byte from both data nonce vectors, proving
the terminal/data nonce domains do not collide at the boundary indices.

### Size equations

For plaintext size `P`, chunk size `S`, and `N = 0` when `P == 0`, otherwise `ceil(P/S)`:

```text
v1 ciphertext = P + N*16
v2 ciphertext = P + N*16 + 32
```

The shared arithmetic rejects negative values, invalid versions and chunk sizes, non-canonical ciphertext lengths, and overflow. Encrypted data ranges never include the v2 terminal; callers fetch the terminal separately.

## Compatibility and rollout

Version 1 remains readable with its existing HKDF `"chunk-iv" || uint32_be(index)` derivation and nil AAD. V1 selection is explicit and its unauthenticated completeness limitation is migration-required; appending a v2 terminal to v1 ciphertext is not a valid upgrade. The supported upgrade is an ordinary GET through the gateway (which decrypts v1 with its existing domains) followed by a PUT through the gateway (which re-encrypts as v2 with an authenticated terminal); the rewritten manifest must then be verified as version 2. Operators identify v1 objects through the `class_e_chunked_v1` audit classification and execute this GET→PUT procedure as documented in `docs/MIGRATION.md`. Old readers must be drained before v2 writers are enabled. Rollback is constrained: once v2 objects exist, rollback is permitted only to a release that understands v2; rollback to a v1-only writer is not permitted without first draining or isolating v2-producing nodes and preserving v2-capable readers.

## Verification model

The implemented read paths authenticate the terminal before success-producing GET, range GET, HEAD, CopyObject, and UploadPartCopy operations. Optimized ranges fetch the requested data records plus a separate fixed 32-byte suffix request. Full streaming decryption verifies the terminal again at EOF to protect against changes after preflight. The terminal commits exact count and size, detecting missing, substituted, or extra terminal/data records.

## Relationship to ADR 0001

ADR 0001's range-performance objective remains unchanged: only data records covering a requested plaintext range should be fetched and decrypted. This ADR supersedes ADR 0001 portions that assume v1-only framing or that verifying touched records is sufficient for object completeness. Range optimization remains terminal-exclusive; the implemented API performs the bounded terminal preflight separately from the data-range request.

## Alternatives considered

- Keep v1 and rely on backend `Content-Length`: rejected because length is not cryptographically authenticated and does not bind the expected record count.
- Add a terminal without versioned domains: rejected because data and terminal records would share protocol domains and could be confused.
- Authenticate the entire stream in one final pass: rejected because it would remove streaming and range performance benefits.
