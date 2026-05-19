# Offline Migration Tool (s3eg-migrate)

This document is the operator runbook for the `s3eg-migrate` offline migration
tool, which re-encrypts objects in an S3 bucket to bring them up to the current
encryption format.

## Overview

The migration tool supports three primary use cases:

1. **Format migration** — migrate objects from legacy encryption formats to the
   modern format (HKDF chunk-IV derivation, AAD integrity, streaming fallback v2).
2. **Key rotation** — re-encrypt all objects from an old KEK version to a new
   KEK version (complements the online drain-and-cutover rotation with a complete
   offline path).
3. **Algorithm change** — migrate from AES-256-GCM to ChaCha20-Poly1305 or vice
   versa.

The tool operates **read-decrypt-reencrypt-write** directly on the S3 backend
without involving the running gateway process. It is **idempotent** and
**resumable**: progress is stored in a JSON state file and can be continued
after interruption.

## Prerequisites

- `s3eg-migrate` binary from the matching release.
- S3 credentials with `GetObject`, `PutObject`, `HeadObject`, `ListObjectsV2`,
  `DeleteObject`, and `CopyObject` permissions on the target bucket.
- The gateway configuration file (`gateway.yaml`) used by the target deployment.

## Supported Gateway Versions

| Gateway version | Read capability | Write capability | Recommended approach |
|---|---|---|---|
| **v0.6.4** | Legacy (XOR-IV, no-AAD, fallback-v1) and modern | Modern (HKDF, AAD, fallback-v2) | **Option A** — migrate before upgrade |
| **v0.7.0** | Legacy (via compat window) and modern | Modern (default) | **Option B** — migrate after upgrade |

## Upgrade Options

### Option A — Migrate Before Upgrade (Recommended for Production)

Best for deployments with continuous writes because the gateway never serves
partially-migrated objects under v0.7.0 semantics.

```bash
# 1. Upgrade gateway to v0.6.4 (if not already there)
# 2. Dry-run to assess the bucket
s3eg-migrate \
  --config gateway.yaml \
  --gateway-version 0.6.4 \
  --bucket mybucket \
  --prefix backups/ \
  --dry-run

# 3. Migrate all object classes
s3eg-migrate \
  --config gateway.yaml \
  --gateway-version 0.6.4 \
  --bucket mybucket \
  --prefix backups/ \
  --migration-class all \
  --workers 4

# 4. Verify with another dry-run (should report 0 legacy objects)
s3eg-migrate \
  --config gateway.yaml \
  --gateway-version 0.6.4 \
  --bucket mybucket \
  --prefix backups/ \
  --dry-run

# 5. Upgrade gateway to v0.7.0
```

### Option B — Migrate After Upgrade

Acceptable for environments with a maintenance window or read-mostly buckets.

```bash
# 1. Upgrade gateway to v0.7.0
# 2. Dry-run to assess the bucket
s3eg-migrate \
  --config gateway.yaml \
  --gateway-version 0.7.0 \
  --bucket mybucket \
  --prefix backups/ \
  --dry-run

# 3. Migrate all object classes
s3eg-migrate \
  --config gateway.yaml \
  --gateway-version 0.7.0 \
  --bucket mybucket \
  --prefix backups/ \
  --migration-class all \
  --workers 4

# 4. Verify with another dry-run (should report 0 legacy objects)
s3eg-migrate \
  --config gateway.yaml \
  --gateway-version 0.7.0 \
  --bucket mybucket \
  --prefix backups/ \
  --dry-run
```

## CLI Reference

```
s3eg-migrate \
  --config gateway.yaml \           # gateway config file
  --gateway-version 0.7.0 \         # REQUIRED: 0.6.4 or 0.7.0
  --source-key-version 1 \          # optional: force old KEK version
  --target-key-version 2 \          # optional: force new KEK version
  --bucket mybucket \               # target S3 bucket
  --prefix backups/ \               # optional: restrict scope
  --workers 4 \                     # default 4
  --dry-run \                       # scan only, no writes
  --verify \                        # enable post-write verification (default on)
  --no-verify \                     # disable verification
  --state-file migration.json \     # resume state file
  --migration-class all \           # all | sec2 | sec4 | sec27
  --verify-delay 500ms \            # pause before verify read
  --log-level info \                # debug | info | warn | error
  --output json                     # text (default) | json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All eligible objects migrated (or already modern). |
| `1` | Fatal error (config invalid, unsupported version, S3 unavailable). |
| `2` | Partial migration: some objects failed; see state file. |

### Migration classes

| Class | Flag | Description |
|---|---|---|
| `all` | — | Migrate all legacy object classes. |
| `sec2` | `ClassA_XOR` | XOR-IV derivation → HKDF (chunked objects only). |
| `sec4` | `ClassB_NoAAD` | No-AAD legacy → AAD (non-chunked objects). |
| `sec27` | `ClassC_*` | Outer-AEAD fallback v1 → streaming fallback v2. |

## Object Classification

The tool inspects `HeadObject` metadata to classify each object before deciding
whether to migrate:

- **ClassModern** — already using the latest format; skipped.
- **ClassA_XOR** (`sec2`) — chunked object without `x-amz-meta-enc-iv-deriv`.
- **ClassB_NoAAD** (`sec4`) — non-chunked object with
  `x-amz-meta-enc-legacy-no-aad=true`.
- **ClassC_Fallback_XOR** (`sec27`) — fallback object with v1 wrapper and XOR IV.
- **ClassC_Fallback_HKDF** (`sec27`) — fallback object with v1 wrapper but HKDF IV
  already present.
- **ClassPlaintext** — not encrypted; skipped.

## Dry-Run Mode

Use `--dry-run` to safely assess a bucket before making any changes:

```bash
s3eg-migrate --config gateway.yaml --gateway-version 0.7.0 \
  --bucket mybucket --dry-run --output json
```

This produces a report with per-class counts and sample keys for each legacy
class, without writing anything.

## Resume and State File

Progress is saved automatically to the state file (default:
`<bucket>[-<prefix>]-<gateway-version>-migration.json`). If a run is interrupted,
simply re-run the same command; the tool resumes from the last checkpoint.

**Important:** The state file embeds the `--gateway-version`. Resuming with a
different version is rejected to prevent accidental cross-version runs.

## Post-Write Verification

By default, after each `PutObject` the tool re-reads the object and decrypts it
with the target engine to confirm correctness. For large objects (> 256 MiB) it
falls back to metadata checks plus first/last 4 KiB hash comparison.

Use `--verify-delay 500ms` (or `2s`) when running against distributed MinIO to
 tolerate eventual consistency between PutObject and the verify read.

## Companion Object Cleanup

For fallback objects whose metadata exceeded the S3 header limit, a companion S3
object stores the manifest. After successful migration, the tool deletes the old
companion object automatically (best-effort; failure is logged but does not fail
the migration).

## Performance Recommendations

| Factor | Recommendation |
|---|---|
| **Workers** | Default is 4. Increase for high-latency backends; decrease if S3 returns 429/503. |
| **Network placement** | Run the tool in the same VPC/region as the S3 endpoint to minimize transfer costs. |
| **Large fallback-v1 objects** | Peak memory is approximately 2× object size for CLASS C. Reduce `--workers` for buckets containing many large fallback objects. |
| **Verify delay** | Set to `500ms`–`2s` for distributed MinIO; keep at `0` for AWS S3 and single-node MinIO. |

## Safety Mechanisms

| Mechanism | Behaviour |
|---|---|
| **Dry-run** | No `PutObject` calls; safe to run repeatedly. |
| **Verify-after-write** | Re-read + decrypt + hash compare after every PutObject (default on). |
| **Idempotency** | Already-migrated objects are skipped via state checkpoint. |
| **Resume** | Interrupted runs continue from the last checkpoint. |
| **Atomic overwrite** | S3 `PutObject` on the same key is atomic; no temporary objects. |
| **Error isolation** | Single-object failure does not abort the run. |
| **State file gateway version** | Resuming with a mismatched `--gateway-version` is rejected. |

## Disaster Recovery

### Interrupted migration

Re-run the exact same command. The state file contains the checkpoint and the
tool will skip already-migrated objects.

### Corrupt state file

If the state file is lost or corrupt, start a fresh run with a new
`--state-file`. The tool will re-scan all objects; already-modern objects are
skipped by metadata inspection, so the only cost is extra HEAD requests.

### Failed objects

Objects that fail to migrate are recorded in the state file (`failed` array).
After fixing the root cause (e.g. restoring a missing key version), re-run the
same command. Failed objects are re-attempted on every run (they are not
skipped by the checkpoint).

### Rollback

S3 has no transactions, so a true rollback is not possible. The state file lists
all migrated objects. In case of failure, non-migrated objects can still be read
via the old key path while the engine's dual-read window remains open.

## Backfill Legacy No-AAD Objects

Objects written before AAD was introduced may lack both the AAD commitment and
the `MetaLegacyNoAAD` flag. These objects will fail to decrypt after SEC-4 is
active. A backfill step is required **before** migration:

```bash
# The backfill sub-command attempts decrypt (AAD → no-AAD) and tags objects
# that succeed on the no-AAD path with MetaLegacyNoAAD=true.
#
# NOTE: This sub-command is not yet implemented in the CLI.  For now, operators
# must manually CopyObject with the added metadata flag, or use a preliminary
# script.  This capability will be added in a future release.
```

## Limitations

- **Multipart upload (MPU) objects** are out of scope; the tool skips them
  safely (`ClassModern`).
- **In-place encryption** (encrypting previously unencrypted objects) is not
  supported.
- **Cross-bucket migration** is planned for a future release.

## Upgrading KDF parameters

Objects written before V1.0-SEC-H03 were encrypted with PBKDF2-SHA256 at
100,000 iterations. V1.0-SEC-H03 raises the default to 600,000 iterations and
stores the KDF parameters in object metadata (`x-amz-meta-encryption-kdf-params`).

**Objects encrypted with the old default (100k) are decrypted transparently via
the KDF-params metadata fallback; no manual intervention is required.** The
migration tool is only needed if the operator wants to actively upgrade old
objects to the new iteration count.

### Runbook: `s3eg-migrate --filter=kdf`

1. Verify the new gateway is running with `encryption.kdf.pbkdf2.iterations: 600000`.
2. Run a dry-run scan to count affected objects:
   ```bash
   s3eg-migrate \
     --bucket my-bucket \
     --filter kdf \
     --dry-run \
     --state-file /tmp/kdf-migration.json
   ```

3. When satisfied, run the actual migration:
   ```bash
   s3eg-migrate \
     --bucket my-bucket \
     --filter kdf \
     --state-file /tmp/kdf-migration.json \
     --workers 8 \
     --verify
   ```

4. Optionally rerun with `--dry-run` to confirm 0 ClassD objects remain.

Because `deriveKeyWithParams` reads iterations from metadata on decrypt, the
source engine automatically handles both 100k and 600k objects during the
migration window. No separate `--source-iterations` flag is strictly required.

## Upgrading to Argon2id KDF

V1.0-CRYPTO-1 introduces an alternative key derivation function: Argon2id
(identified by `x-amz-meta-encryption-kdf-algorithm: argon2id` in object
metadata). Objects encrypted with PBKDF2-SHA256 remain **fully readable** —
the engine selects the correct KDF based on the metadata on decrypt.

**Argon2id defaults are chosen for ~1 second on a modern server core:**
- `time`: 2
- `memory`: 19456 KiB (19 MiB)
- `threads`: 1

### Runbook: enabling Argon2id for new objects

1. Upgrade the gateway to the V1.0-CRYPTO-1 release.
2. Edit `gateway.yaml`:
   ```yaml
   encryption:
     kdf:
       algorithm: argon2id  # "pbkdf2-sha256" to keep current behaviour
       argon2id:
         time: 2
         memory: 19456
         threads: 1
   ```
3. Rolling-restart the gateway pods.
4. Confirm the gateway logs show `kdf_algorithm=argon2id` at startup.
5. **New objects** are now encrypted with Argon2id. Existing objects continue
   to use whatever KDF they were created with.

### Runbook: migrating existing objects to Argon2id

To re-encrypt all existing PBKDF2-SHA256 objects with Argon2id:

1. Verify the gateway is running with `encryption.kdf.algorithm: argon2id`.
2. Run a dry-run scan:
   ```bash
   s3eg-migrate \
     --bucket my-bucket \
     --filter kdf \
     --dry-run \
     --state-file /tmp/argon2id-migration.json
   ```
3. When satisfied, run the actual migration:
   ```bash
   s3eg-migrate \
     --bucket my-bucket \
     --filter kdf \
     --state-file /tmp/argon2id-migration.json \
     --workers 8 \
     --verify
   ```
4. Optionally rerun with `--dry-run` to confirm 0 ClassD objects remain.

### FIPS environments

When the binary is compiled with `-tags=fips`, Argon2id is **disabled** and
the gateway refuses to start if `algorithm: argon2id` is configured. Use
PBKDF2-SHA256 exclusively in FIPS mode.

## Future Work

In v3.0, once all deployments have confirmed migration, the legacy read paths
(XOR-IV, no-AAD fallback, fallback-v1) will be removed from the gateway engine.
