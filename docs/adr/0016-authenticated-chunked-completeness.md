# ADR 0016: Authenticated Chunked Completeness

## Status

Accepted for the SEC-37 protocol foundation. Writer, reader, and API migration are deferred to the subsequent implementation phases.

## Context

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

### Size equations

For plaintext size `P`, chunk size `S`, and `N = 0` when `P == 0`, otherwise `ceil(P/S)`:

```text
v1 ciphertext = P + N*16
v2 ciphertext = P + N*16 + 32
```

The shared arithmetic rejects negative values, invalid versions and chunk sizes, non-canonical ciphertext lengths, and overflow. Encrypted data ranges never include the v2 terminal; callers fetch the terminal separately.

## Compatibility and rollout

Version 1 remains readable with its existing HKDF `"chunk-iv" || uint32_be(index)` derivation and nil AAD. V1 completeness is explicitly unauthenticated and must be treated as migration-required; appending a v2 terminal to v1 ciphertext is not a valid upgrade because the data authentication domains differ. Upgrade is GET through the gateway followed by PUT through the gateway.

Unknown versions fail closed before plaintext or destination writes. New writers and full readers will be migrated together in a later phase. This foundation does not alter existing streaming behavior.

## Verification model

Future read paths will authenticate the terminal before success-producing GET, range GET, HEAD, CopyObject, and UploadPartCopy operations. Full streaming decryption will verify it again at EOF to protect against changes after preflight. The terminal commits exact count and size, detecting missing, substituted, or extra terminal/data records.

## Relationship to ADR 0001

ADR 0001's range-performance objective remains unchanged: only data records covering a requested plaintext range should be fetched and decrypted. This ADR supersedes its v1-only format and authentication assumptions, including the claim that verifying touched records is sufficient for object completeness. Range optimization remains terminal-exclusive and requires a separate terminal verification step for v2.

## Alternatives considered

- Keep v1 and rely on backend `Content-Length`: rejected because length is not cryptographically authenticated and does not bind the expected record count.
- Add a terminal without versioned domains: rejected because data and terminal records would share protocol domains and could be confused.
- Authenticate the entire stream in one final pass: rejected because it would remove streaming and range performance benefits.
