# Re-encryption & Migration Guide

> **`s3eg-migrate` has been removed.** The offline migration tool that accessed
> the S3 backend directly has been replaced by the **GET-through-gateway →
> PUT-through-gateway** pattern using any standard S3 client. The read-only
> audit commands are available via `s3eg-cli` (see [Audit Tool](#audit-tool-s3eg-cli)).

## Overview

Use this guide for coordinated upgrades, password/KMS migration, explicit
re-encryption, and controlled recovery. Key source/rotation setup lives in
[key management](KMS_COMPATIBILITY.md), not a separate migration tutorial.

## Contents

- [0.12 coordinated upgrade](#012-upgrade-notice-including-0123)
- [Location binding](#object-location-binding)
- [Controlled recovery and re-encryption](#supported-re-encryption-patterns)
- [Read-only audit tool](#audit-tool-s3eg-cli)
- [No-AAD recovery](#no-aad-recovery-pre-marker-objects)
- [Removing compression](#removing-compression-v10)
- [Password to envelope/KMS](#migrating-from-password-only-to-kek-envelope-encryption)

**Never use an in-place no-op sync as proof of re-encryption.** Preserve original
bytes, complete metadata, manifests, and keys before any recovery procedure.

## 0.12 upgrade notice (including 0.12.3)

The 0.12 release line changes encryption write formats and deployment
prerequisites. Plan a coordinated upgrade rather than a rolling mix of old and
new writers.

**If the currently deployed version is earlier than `0.12.0-rc1`, these full
instructions remain mandatory when upgrading directly to `0.12.3`.** The
0.12 patch releases retain the format, state-v2 writer, KDF-limit, rollback,
and location-binding requirements below. Version `0.12.1` restored
authenticated HTTPS upload compatibility and fixed the Helm chart's default
writable spool storage; `0.12.2` and `0.12.3` retain those fixes.

Version `0.12.2` adds atomic bucket-policy reloads, reverse-proxy signing fixes,
metadata consistency, and numeric/transport hardening. COPY inherits source
metadata; use REPLACE for destination metadata changes. Client writes using
gateway-reserved metadata names are rejected. Configure final backend endpoints
because passthrough redirects are no longer followed, and fix invalid audit
TLS settings or unsafe audit-file permissions before rollout. See the
[0.12.2 changelog](../CHANGELOG.md) and
[transport and audit deployment guidance](DEPLOYMENT.md#backend-redirects-kms-tls-and-audit-sinks).
The reload fix prevents new GH-339 bypass-bucket miswrites but does not repair
existing objects; follow the
[controlled recovery procedure](#recovering-gh-339-bypass-bucket-miswrites).

Version `0.12.3` fixes backend error classification during encrypted reads,
presigned URL lifetimes, and URL-encoded CopyObject/UploadPartCopy sources.
These fixes require no additional encryption-policy, key, credential, or
object-format migration. Restore the `5m` authentication clock-skew default if
it was enlarged only as a presigned-URL workaround. Keep signed copy-source
headers encoded through frontend proxies and audit earlier copies/moves of
escaped keys for wrong-object selection; the fix does not repair existing
destinations or recover deleted sources. See the
[0.12.3 changelog](../CHANGELOG.md) and the
[copy-source deployment and recovery guidance](DEPLOYMENT.md#url-encoded-copy-sources-gh-346).

The procedure also applies when upgrading from the stable `0.11.10` release or
any `0.12.0` release candidate. The stable release no longer carries the
release-candidate restriction, but the format and rollback constraints remain.

1. Ensure build and runtime environments use Go 1.27.1 or later.
2. Before enabling chunked v2 writers, drain v1-only readers. Once v2 objects
   exist, retain a v2-capable release for rollback; rewrite v1 objects with
   GET-through-gateway -> PUT-through-gateway when authenticated completeness
   is required.
3. Before deploying the encrypted MPU state-v2 writer, complete a separate
   scale-down to exactly one old replica and drain or abort in-flight encrypted
   MPUs. For Helm-managed deployments, first run `helm upgrade RELEASE CHART
   --reuse-values --set replicaCount=1`, then wait for `kubectl rollout status
   deployment/DEPLOYMENT`. Only then upgrade the image and set
    `--set-string config.multipartState.valkey.stateV2Writer.enabled.value=true`.
    The chart renders
   `VALKEY_MPU_STATE_V2_WRITER=true`; the gateway derives the internal
   capability and terminates that single old writer before starting the state-v2
   replacement, which atomically initializes `mpu:writer-version`. Do not run
   version-1 and version-2 MPU
   writers together, and drain or abort version-2 encrypted MPUs before
   rollback.
4. Inventory KDF parameters before lowering decrypt limits. Rewrite objects or
   retain limits that cover them; deploy a new lower limit uniformly to every
   replica, never as a mixed-limit fleet.
5. Do not use backend-native moves, copies, or renames for objects written by
   this release. Move encrypted objects through gateway `CopyObject` or a
   GET-through-gateway -> PUT-through-gateway rewrite so their location binding
   is regenerated.

### Temporary spool storage for Helm deployments

**Configure a writable spool volume before upgrading the image to `0.12.0`.**
The chart sets `securityContext.readOnlyRootFilesystem: true` and does not
provide a writable temporary volume by default. The `0.12.0` gateway creates a
temporary file to verify signed SigV4 payloads before dispatch, even for an
empty-body GET such as ListObjects. Without a writable spool directory,
authenticated S3 requests can return HTTP 500 `InternalError` while `/ready`
still succeeds.

Add the following chart values alongside the existing settings (keep the root
filesystem read-only):

```yaml
config:
  server:
    spoolDirectory:
      value: /tmp
extraVolumes:
  - name: gateway-temp
    emptyDir: {}
extraVolumeMounts:
  - name: gateway-temp
    mountPath: /tmp
```

`emptyDir` is local to each pod, backed by node ephemeral storage by default,
and removed with the pod. Size ephemeral-storage requests and limits for the
expected verified-body workload; the default aggregate spool budget is 10 GiB
per gateway process. After rollout, verify a signed ListObjects request through
the gateway as well as `/ready`.

Charts `0.12.1` and later provide the `/tmp` `emptyDir` and spool setting by default,
so this specific workaround is unnecessary when installing or upgrading with
the `0.12.3` chart. Existing `extraVolumeMounts` entries at `/tmp` take
precedence; keep them writable. The explicit values above remain necessary for
the published `0.12.0` chart. They do not replace any of the coordinated
upgrade steps above for installations earlier than `0.12.0-rc1`.

For a Helm-managed upgrade, install or upgrade the chart at `0.12.0` and use
the image tag `0.12.0` (or `0.12.0-fips` with the FIPS values overlay). Keep
the existing encryption password/key-manager and backend credentials unchanged.
The state-v2 writer switch is intentionally a separate second upgrade as
described in step 3 above. After rollout, verify `/ready` (or one of the
S3-compatible readiness aliases) and confirm that all replicas report the same
Valkey MPU writer capability before restoring normal traffic.

The detailed procedures below remain the authoritative instructions for each
change.

### SEC-39 KDF limit rollout

Before lowering decrypt limits, inventory `x-amz-meta-encryption-kdf-params` with
backend metadata and `s3eg-cli inspect`. Classify each object as
`within-limit`, `above-operational-limit`, or `invalid-hard-limit`, recording
bucket, key, algorithm, requested costs, and proposed maxima. MPU v2 costs are
embedded in manifests and cannot be inventoried from object headers; retain the
old limit until those uploads are read and rewritten.

Migrate outliers with GET through readers using the old limit, then PUT through
writers configured with supported costs and verify a subsequent GET and HEAD.
Deploy readers covering the complete inventory first, rewrite and verify all
outliers, then lower limits on every replica in one coordinated rollout. Do not
send traffic to mixed-limit replicas. Data above a hard limit must be rewritten
through the prior trusted release before upgrading.

All re-encryption is now done by reading plaintext **through** the gateway and
writing it back **through** the gateway. This ensures:

- The gateway's crypto engine handles all format/algorithm/KDF decisions.
- No separate crypto stack needs to track gateway evolution.
- Standard S3 tools (`awscli`, `s5cmd`, `mc`) perform the copy.

## Object Location Binding

Current encrypted writes bind payload authentication to the gateway-derived
bucket and object key. A raw backend move, copy, or rename that preserves the
ciphertext and metadata but changes the object location therefore fails
authentication; editing metadata to try to repair the move is not supported
and must never be used as a recovery procedure. This binding is enforced by
the payload AEAD independently of whether the DEK is protected by password
mode or a `KeyManager` provider.

Use the gateway's `CopyObject`, which decrypts the source and re-encrypts the
destination with a fresh binding, or use the supported GET-through-gateway ->
PUT-through-gateway migration pattern. This includes rewriting legacy MPU v1
objects into the current bound formats. Objects being moved between locations
should be read and re-written at the destination through the gateway rather
than relocated with a backend-native copy or rename.

## Supported Re-encryption Patterns

### Recovering GH-339 bypass-bucket miswrites

On releases affected by GH-339, a configuration reload could store gateway
ciphertext in a `disable_encryption` bucket while returning a successful PUT.
After the bypass policy returns, GET fails with 409
`EncryptionConfigurationMismatch`. Installing the fix prevents new miswrites
but does not rewrite existing ones.

1. Pause application writes and avoid reloads on affected gateway instances.
   Preserve a backend backup/version of each suspect object **and its complete
   metadata** before attempting recovery.
2. Inventory suspect objects using backend encryption markers or the read-only
   `s3eg-cli`. A larger listing size alone is not proof of encryption.
3. Use an isolated, access-controlled, encryption-enabled gateway reader with
   the original encryption settings/keys and the original bucket/key identity
   to download each affected object. Verify the recovered application bytes
   with the application's own integrity checks.
4. PUT those verified bytes through a fixed gateway with the intended bypass
   policy, retaining required user/content metadata. Use distinct reader and
   writer endpoints and an explicit download/upload; a server-side copy or
   no-op sync is not a substitute for this recovery.
5. Verify byte-identical backend content, absence of gateway encryption markers,
   and successful gateway GET/HEAD before resuming the application.

For restic, recovered bytes are still **restic-encrypted** pack data; bypassing
gateway encryption does not remove application encryption. Validate the
repository after repair. Do not strip gateway encryption metadata, serve raw
ciphertext as if it were recovered data, or relocate ciphertext to another
bucket/key: authenticated location binding must remain valid during reading.

The older mismatch error text mentions a "migration tool", but `s3eg-migrate`
has been removed and `s3eg-cli` is read-only. Recovery requires the controlled
GET-through-reader → PUT-through-bypass-writer workflow above.

### Standard re-encryption (GET → PUT)

```bash
# 1. Inspect objects before migration (optional but recommended)
s3eg-cli inspect --config gateway.yaml my-bucket path/to/object.txt

# 2. Use a protected workspace: the intermediate file contains plaintext.
umask 077
workdir="$(mktemp -d)"
aws s3 cp s3://my-bucket/path/to/object.txt "$workdir/object" \
  --endpoint-url https://reader-gateway.example.com
# Verify application bytes; retain standard/user metadata for the destination PUT.
aws s3 cp "$workdir/object" s3://my-bucket/path/to/object.txt \
  --endpoint-url https://writer-gateway.example.com

# 3. Verify the object was re-encrypted
s3eg-cli inspect --config gateway.yaml my-bucket path/to/object.txt
```

Use reader/writer credentials and settings appropriate to each endpoint; they
may be the same only when it is safe for the intended migration. A local-file PUT
does not automatically preserve source standard headers, tags, ACLs, retention,
or user metadata: inventory and deliberately restore required fields, then verify
GET/HEAD/application integrity. Protect and remove the temporary plaintext using
your storage policy after verification. Unsupported/hard-limit formats need the
appropriate prior trusted reader, not unconditional “all legacy formats” fallback.

### Chunked v1 completeness migration

Chunked v1 objects are readable, but their independently authenticated data
records do not authenticate the expected object length. Removing complete
trailing chunks can therefore go undetected. The read-only classifier reports
these objects as `class_e_chunked_v1` and `NeedsMigration` is true; chunked v2
objects remain `modern`. Unsupported or malformed manifests are `unknown` and
must be investigated rather than migrated blindly.

Inventory chunked objects with `s3eg-cli list-algorithm` or `inspect`, then
rewrite each v1 object through the gateway using GET -> PUT. Verify afterward
that the manifest reports version 2 and that the object is no longer classified
as `class_e_chunked_v1`. Do not append a 32-byte trailer to v1 ciphertext in
place: v2 changes the data AAD and nonce domains, so only a plaintext
round-trip safely upgrades the object.

### Full bucket re-encryption

```bash
# List all encrypted objects using s3eg-cli audit (dry-run first)
s3eg-cli list-algorithm --config gateway.yaml my-bucket

# Download a controlled inventory to protected local storage, then upload each
# verified object through the intended writer. Use the single-object procedure.
# An S3-to-same-S3 sync may skip unchanged objects and is NOT re-encryption.

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
# Follow the explicit download → verified upload procedure above.

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
   Treat inspection as envelope classification, not proof of successful decrypt.
   Confirm actual readability with the controlled prior reader and application
   integrity verification; never infer it solely from the recovery flag.

4. **Re-encrypt each affected object via GET → PUT through the gateway:**
   ```bash
    # Explicitly download via the isolated recovery reader, verify the bytes,
    # and PUT via the normal bound-format writer as described above.
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
    # GET plaintext through the OLD compression-capable reader into protected
    # local storage, then PUT through the NEW writer with compression disabled.
    # Do not do both operations through the old endpoint.
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
    # Use the explicit gateway download → verified upload procedure above.
   ```

4. Verify via `s3eg-cli inspect` — the KDF params will show the Argon2id
   parameters.

## Migrating from password-only to KEK envelope encryption

### Before you begin

Inventory objects/formats/KDF limits, legacy MPU/state envelopes, metadata keys,
and backup recovery requirements. Retain original password and complete backend
backups. Set up a persistent KEK or healthy external KMS with correct TLS/auth,
and validate against a nonproduction copy before switching writers. An ephemeral
memory-provider key is not recoverable after restart; its hex/raw decoder differs
from self-contained AES's base64 input.

### Configure and verify

1. Configure the actual persistent key source, not just a provider name:
   ```yaml
   encryption:
     password: "<existing-password>"  # kept for decrypting old objects
     key_manager:
        enabled: true
        provider: "self_contained"
        self_contained:
          type: aes
          aes:
            active_version: 1
            keys:
              - version: 1
                key_source: "env:S3EG_AES_KEK"
   ```

2. Apply a reviewed deployment retaining the existing password and old key material.
   New objects use the configured KEK. Existing password objects/MPU envelopes use
   password compatibility; this is separate from provider dual-read windows.

3. Verify a newly written object, an old single-object read, and an old MPU read
   where applicable. Inspect envelope/key version with read-only `s3eg-cli` or
   authorized backend access; gateway HEAD hides internal metadata.
4. Rewrite the controlled inventory with explicit GET→PUT when retiring the old
   password. Keep decryption material until cold objects, state, metadata, manifests,
   and required backups no longer depend on it. Follow the existing coordinated
   upgrade/MPU constraints if binaries or writer formats change too.

For Cosmian use its key IDs/TLS config; for OpenBao/Vault use Transit auth/key
policy. Provider-specific examples, retention, and first rotation are in
[key management](KMS_COMPATIBILITY.md#dual-read-window-and-key-rotation).

### Rollback and troubleshooting

Rollback must retain the provider/key that can read new envelope writes as well
as original password-readable objects. Simply disabling KMS cannot decrypt its
new ciphertext. Pause writes, restore a compatible retained config/provider,
verify both generations, and diagnose endpoint/TLS/key-policy or source problems.
Do not use a gateway metadata query as proof that a key version is absent; use
backend/read-only inspection and successful plaintext round trips. Preserve keys
for locked data and state-key envelopes, not only actively accessed objects.

## Deprecated Migration Tool

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
