# Re-encryption & Migration Guide

> **`s3eg-migrate` has been removed.** The offline migration tool that accessed
> the S3 backend directly has been replaced by the **GET-through-gateway →
> PUT-through-gateway** pattern using any standard S3 client. The read-only
> audit commands are available via `s3eg-cli` (see [Audit Tool](#audit-tool-s3eg-cli)).

## Overview

All re-encryption is now done by reading plaintext **through** the gateway and
writing it back **through** the gateway. This ensures:

- The gateway's crypto engine handles all format/algorithm/KDF decisions.
- No separate crypto stack needs to track gateway evolution.
- Standard S3 tools (`awscli`, `s5cmd`, `mc`) perform the copy.

## Supported Re-encryption Patterns

### Standard re-encryption (GET → PUT)

```bash
# 1. Inspect objects before migration (optional but recommended)
s3eg-cli inspect --config gateway.yaml my-bucket path/to/object.txt

# 2. Download through gateway, re-upload through gateway
aws s3 cp s3://my-bucket/path/to/object.txt \
  s3://my-bucket/path/to/object.txt \
  --endpoint-url https://gateway.example.com

# Or with s5cmd:
s5cmd cp "s3://my-bucket/path/to/*" "s3://my-bucket/path/to/" \
  --endpoint-url https://gateway.example.com

# 3. Verify the object was re-encrypted
s3eg-cli inspect --config gateway.yaml my-bucket path/to/object.txt
```

The gateway's `Decrypt` path transparently handles all legacy formats. The
`Encrypt` path produces objects with the current encryption parameters.

### Full bucket re-encryption

```bash
# List all encrypted objects using s3eg-cli audit (dry-run first)
s3eg-cli list-algorithm --config gateway.yaml my-bucket

# Re-encrypt via awscli sync
aws s3 sync s3://my-bucket/ s3://my-bucket/ \
  --endpoint-url https://gateway.example.com

# Verify no legacy objects remain
s3eg-cli list-algorithm --config gateway.yaml my-bucket --output json
```

### KDF parameter upgrade (e.g. 100k → 600k PBKDF2)

Objects encrypted before V1.0-SEC-H03 with the legacy 100k PBKDF2 iteration
count are **still readable** through the gateway — the engine selects the
correct KDF based on per-object metadata. To explicitly upgrade:

```bash
# 1. Configure the desired iteration count in gateway.yaml:
#    encryption.kdf.pbkdf2.iterations: 600000

# 2. Roll gateway pods to pick up the new config.

# 3. Re-encrypt each object via GET → PUT through the gateway.
aws s3 cp s3://my-bucket/path/to/legacy-object \
  s3://my-bucket/path/to/legacy-object \
  --endpoint-url https://gateway.example.com

# 4. Verify via inspect
s3eg-cli inspect --config gateway.yaml my-bucket path/to/legacy-object
```

## Audit Tool (`s3eg-cli`)

`s3eg-cli` is the read-only audit tool for inspecting encryption envelopes on
backend objects. It communicates only through `HeadObject`, bounded ranged
`GetObject` (first 64 bytes), and `ListObjects` — no write operations.

### Sub-commands

```bash
# Inspect a single object's encryption envelope
s3eg-cli inspect <bucket> <key> [--config F] [--output text|json]

# Verify a specific key version
s3eg-cli verify-key <bucket> <key> [--key-version N] [--config F]

# Scan a bucket for algorithm/class distribution
s3eg-cli list-algorithm <bucket> [--prefix P] [--workers N] [--config F]
```

### Exit codes

| Command | Code | Meaning |
|---|---|---|
| `inspect` | 0 | Success (object may be plaintext; check `encrypted` field) |
| `inspect` | 3 | Object not found |
| `verify-key` | 0 | Match |
| `verify-key` | 3 | Object not found |
| `verify-key` | 4 | Key version mismatch |
| `list-algorithm` | 0 | Success |
| `list-algorithm` | 1 | Error during scan |

### Examples

```bash
# Inspect with JSON output
s3eg-cli inspect --config gateway.yaml --output json my-bucket important/doc.pdf

# Verify key version
s3eg-cli verify-key --config gateway.yaml --key-version 2 my-bucket important/doc.pdf

# Scan entire bucket
s3eg-cli list-algorithm --config gateway.yaml my-bucket

# Scan with prefix and custom concurrency
s3eg-cli list-algorithm --config gateway.yaml --prefix backups/ --workers 8 my-bucket
```

## No-AAD Recovery (Pre-Marker Objects)

Objects encrypted before AAD was introduced may lack both the AAD commitment
and the `x-amz-meta-enc-legacy-no-aad` marker. These objects **fail to decrypt**
through the gateway by default, because the no-AAD fallback at engine.go:818 is
gated on the marker being `"true"`.

### Recovery procedure

1. **Enable the recovery flag in `gateway.yaml`:**
   ```yaml
   encryption:
     allow_unmarked_no_aad_fallback: true
   ```

2. **Roll the gateway pods.** The new setting takes effect immediately.

3. **Use `s3eg-cli inspect` to find affected objects:**
   Look for objects where `AAD Scheme: v1-no-aad` — these are objects that
   decrypt via the no-AAD path because the flag is active.

4. **Re-encrypt each affected object via GET → PUT through the gateway:**
   ```bash
   aws s3 cp s3://my-bucket/path/to/legacy-object \
     s3://my-bucket/path/to/legacy-object \
     --endpoint-url https://gateway.example.com
   ```

5. **Disable the recovery flag:**
   ```yaml
   encryption:
     allow_unmarked_no_aad_fallback: false
   ```
   Roll the pods again. The flag is fail-closed by default and should only be
   enabled during a controlled recovery window.

6. **Verify no affected objects remain:**
   ```bash
   s3eg-cli inspect --config gateway.yaml --output json my-bucket path/to/legacy-object
   # Look for "aad_scheme": "v2-aad" — the re-encrypted object now has AAD.
   ```

### Security note

The `allow_unmarked_no_aad_fallback` flag weakens the SEC-4 security property:
an attacker with backend write access could delete the AAD marker from a modern
object and the gateway would attempt no-AAD decryption. **Enable only during a
controlled recovery window, then disable immediately.**

## Removing Compression (v1.0)

Objects written with `compression.enabled: true` carry the
`x-amz-meta-compression-enabled: true` marker. Before upgrading past the
compression removal:

1. List affected objects:
   ```bash
   s3eg-cli list-algorithm --config gateway.yaml my-bucket
   ```
   (Compression markers are visible in the full metadata output.)

2. For each affected object, download through the *old* gateway and re-upload
   through the new gateway (or any version with compression disabled):
   ```bash
   aws s3 cp s3://my-bucket/path/to/object \
     s3://my-bucket/path/to/object \
     --endpoint-url https://old-gateway.example.com
   ```

## Upgrading to Argon2id KDF

V1.0-CRYPTO-1 introduces Argon2id as an alternative KDF. To migrate existing
PBKDF2-SHA256 objects to Argon2id:

1. Configure the gateway:
   ```yaml
   encryption:
     kdf:
       algorithm: argon2id
   ```

2. Roll gateway pods to pick up the new config.

3. Re-encrypt each object via GET → PUT through the gateway:
   ```bash
   # Use any S3 tool to copy objects through the gateway
   aws s3 cp s3://my-bucket/path/to/object \
     s3://my-bucket/path/to/object \
     --endpoint-url https://gateway.example.com
   ```

4. Verify via `s3eg-cli inspect` — the KDF params will show the Argon2id
   parameters.

## Migrating from password-only to KEK envelope encryption

1. Configure the key manager in `gateway.yaml`:
   ```yaml
   encryption:
     password: "<existing-password>"  # kept for decrypting old objects
     key_manager:
       enabled: true
       provider: "self_contained"
   ```

2. Roll gateway pods. New objects use the KEK; old objects are decrypted
   transparently via the password fallback.

3. Re-encrypt existing password-only objects via GET → PUT to migrate them
   to KEK wrapping. No migration window is required — the gateway handles
   mixed modes transparently.

## Comp Copy of the Old Migration Tool

The old `s3eg-migrate` binary is still published as a **deprecation shim** that
prints a usage notice and exits non-zero. It is available at the same download
URLs as previous releases. Operators relying on automated migration scripts
should update to the GET → PUT pattern described in this document.

```bash
$ s3eg-migrate
s3eg-migrate is deprecated; use s3eg-cli instead.
For re-encryption use GET-through-gateway -> PUT-through-gateway.
See docs/MIGRATION.md for details.
```
