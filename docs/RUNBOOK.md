# Operations Runbook and Admin API

**Baseline: v0.12.3.** Use this guide for recovery, state/key operations, incidents,
and the admin HTTP reference. Runtime setup: [deployment](DEPLOYMENT.md); key
provider/rotation: [key management](KMS_COMPATIBILITY.md); dashboards/profiling:
[observability](OBSERVABILITY.md); upgrades: [migration](MIGRATION.md).

Gateway-managed CORS recovery below applies to **unreleased main (GH-322)**;
the v0.12.3 release does not include that mode.

## Contents

- [First response](#first-response)
- [Valkey state at-rest encryption](#valkey-state-at-rest-encryption)
- [ListObjects plaintext-size cache](#listobjects-plaintext-size-cache-v10-s3-3)
- [Unreleased gateway CORS data-loss recovery](#gateway-cors-valkey-data-loss-and-recovery)
- [Metadata encryption key management](#metadata-encryption-key-management)
- [Admin API reference](#admin-api-reference)
- [Alert playbooks](#alert-playbooks)
- [Per-bucket traffic](#per-bucket-traffic)

## First Response

1. Preserve the failing request shape, object identity, version, timing, and logs
   without credentials/signatures/plaintext. Determine whether failure is auth,
   backend availability, key-provider, state, or integrity.
2. Check `/ready` dependency results and liveness separately. A healthy probe is
   not proof that signed S3 uploads, writable spools, or every object can be read.
3. Before recovery changes, back up ciphertext **and complete metadata**, manifests,
   necessary state, keys/config, and versions. Pause writes where consistency requires.
4. Use the established backend/key identity. Never disable encryption, remove
   metadata, relocate ciphertext, or discard state keys as a generic fix.
5. Verify recovered application bytes, GET/HEAD, new writes, and relevant state
   before resuming traffic. Record which focused checks versus full workflows ran.

## Valkey State At-Rest Encryption

New state metadata is encrypted with a random shared DEK wrapped by KeyManager.
The envelope is stored under **`mpu:state-key-wrapped`** with atomic initialization;
replicas unwrap the same key. It is a required recovery dependency, not a disposable
upload record. The main/password fallback manager can support legacy wraps; keep
the original password when those envelopes remain in use.

```yaml
multipart_state:
  valkey:
    addr: valkey.internal:6379
    password_env: VALKEY_PASSWORD
    tls:
      enabled: true
      ca_file: /etc/gateway/valkey-ca.pem
    encrypt_state: true
    allow_legacy_plaintext_state: false
    state_v2_writer: true
```

At-rest encryption defaults enabled. TLS is independently required unless an
explicit development plaintext override is selected. Some hash protocol fields
must remain available to Valkey scripts; “metadata encryption” is not a claim that
the store exposes no operational identifiers. Exact fields and limits live in config.

### Enabling encryption and verification

Configure a persistent key manager (or the consistent password-based manager),
Valkey address/auth/TLS, and the state-v2 writer. Verify initialization/readiness,
create/upload/retry/abort/complete, and the encrypted-state metrics. Inspect backend
state only through authorized tooling; do not print keys or full sensitive records.

The legacy `encryption_password_env`/HKDF material is read compatibility for old
state, **not the new-state encryption authority**. New ciphertext depends on the
wrapped state DEK. Keep its provider key/version in backup and retirement inventories.

### Legacy plaintext migration

AEAD failures do not silently downgrade to plaintext by default.
`VALKEY_ALLOW_LEGACY_PLAINTEXT_STATE=true` is an explicit one-time migration
escape hatch. Drain/abort legacy encrypted uploads under the
[coordinated upgrade](MIGRATION.md#012-upgrade-notice-including-0123); old encrypted
state is abort-only for modern part/complete paths. Disable the escape hatch after
the approved migration window, and monitor legacy read/in-flight metrics.

Do not shorten TTL blindly to force migration; state expiration can orphan backend
MPUs. Missing state fails closed rather than switching an encrypted upload to
plaintext. `MPU_ALLOW_UNTRACKED_PLAINTEXT_UPLOADS` is a separate temporary legacy
plaintext-routing exception, not a recovery setting for encrypted uploads.

### Rotation and recovery

Preserve the state-key envelope and old unwrap capability when rotating KEKs.
Promoting a provider version does not itself rewrap all state/backups. Never delete
`mpu:state-key-wrapped` to “reset” state while dependent uploads exist. Test backup
restore with the matching provider keys. Losing state can require backend abort/
cleanup and starting new uploads; surviving ciphertext parts alone are insufficient.

Disabling `encrypt_state` is not a recommended incident workaround. Changing TLS,
passwords, provider versions, and writer capability needs coordinated rollout,
not a mixed fleet. See [key retention](KMS_COMPATIBILITY.md#dual-read-window-and-key-rotation).

## ListObjects Plaintext Size Cache (V1.0-S3-3)

The advisory `plainsize:<bucket>` cache is written through on PUT/copy/completion
and evicted on deletes; one HMGET resolves a page. It shares Valkey connectivity
with MPU state but has different failure semantics: unresolved sizes can remain
ciphertext while MPU state must fail closed. ETags remain backend-defined.

Watch `list_size_cache_hits_total`, `list_size_cache_misses_total`, and
`list_size_fallback_head_total{result}`. To warm previously uncached objects:

```yaml
list_size_translate:
  enabled: true
  fallback_head_enabled: true
  fallback_head_concurrency: 10
  fallback_head_timeout: 5s
```

This adds backend HEAD/format reads and billing/latency. Use durable cache storage,
bounded settings, and monitor before enabling on large buckets. Disable fallback
when it is no longer needed. There is no implemented admin warm-cache endpoint.
During Valkey outage, listings can still succeed with incorrect encrypted sizes;
sync tools may re-transfer. Restore Valkey, then warm through writes or deliberate
fallback. A successful listing is not proof of correct size/ETag parity; see
[listing limits](S3_API_IMPLEMENTATION.md#listings-and-pagination).

## Metadata Encryption Key Management

The separate metadata key protects gateway crypto metadata, not all user metadata.
Generate a base64 32-byte key with `openssl rand -base64 32` and save it in a
protected secret file (`0600`, appropriate service ownership). Do not reuse a
published example key. Configure `encryption.metadata_encryption_key_file` /
`ENCRYPTION_METADATA_KEY_FILE`. The mutually exclusive inline field requires at
least 128 characters and is hashed to 32 bytes; prefer protected secret sources.

Startup wraps the loaded key through the active KeyManager when available. This
does not replace your persistent metadata-key source/backup with a magical server
registry. **Key loss can make existing encrypted metadata and data unreadable.**
Retain the original key and provider dependencies, including backups and cold objects.

Metadata-key replacement has no general automatic old-key registry. Do not simply
replace the key and assume old objects stay readable: use an isolated reader with
the old key and a writer with the new key, explicitly GET→PUT, preserve metadata,
and verify before retiring anything. See [migration](MIGRATION.md).

Verification uses authorized backend/read-only `s3eg-cli` inspection plus a
gateway plaintext round trip. Gateway HEAD hides `enc-metadata` and other reserved
markers; their absence from client responses is expected, not evidence the feature
is disabled. See [metadata model](ENCRYPTION_DESIGN.md#encrypted-object-metadata-model)
and actual metadata metrics in [observability](OBSERVABILITY.md).

## Admin API Reference

The admin listener is separate from the S3 data plane, disabled by default, normally
loopback-bound. Non-loopback requires TLS. Bearer tokens are distinct from S3 keys.

```yaml
admin:
  enabled: true
  address: 127.0.0.1:8081
  auth:
    type: bearer
    token_file: /etc/gateway/admin-token
  rate_limit:
    requests_per_minute: 30
```

Token file permissions `0600` or stricter; minimum token size is validated.
Inline token requires explicit development opt-in. Environment counterparts:
ADMIN_ENABLED, ADMIN_ADDRESS, ADMIN_TLS_ENABLED/CERT_FILE/KEY_FILE,
ADMIN_AUTH_TYPE/TOKEN_FILE/TOKEN, ADMIN_ALLOW_INLINE_TOKEN, ADMIN_RATE_LIMIT_RPM.
File token refresh/rotation follows server behavior; do not expose bearer material.

### Rotation endpoints

All requests use `Authorization: Bearer <token>`, with JSON request bodies.
Promotion state is process-local; target each intended replica or coordinate
deployment, not arbitrary load-balanced start/status/commit calls.

| Method/path | Input | Success / errors |
|---|---|---|
| POST `/admin/kms/rotate/start` | Optional target_version, grace_period (default 30s) | 202 rotation_id/phase/current/target/provider; 501 unsupported manager, 400 ambiguous/bad request, 404 missing key, 409 conflict |
| GET `/admin/kms/rotate/status` | None | 200 snapshot with phases and in-flight wraps |
| POST `/admin/kms/rotate/commit` | Optional force; use cautiously | 200 snapshot; 409 not ready, 500 promotion failure |
| POST `/admin/kms/rotate/abort` | None | 200 aborted snapshot when phase permits; conflict/error otherwise |

Phases: idle, draining, ready_for_cutover, committing, committed, aborted.
The HTTP contract is not a proof that all loaded providers can promote versions.
Follow [provider-specific rotation](KMS_COMPATIBILITY.md#dual-read-window-and-key-rotation).

```bash
ADMIN=http://127.0.0.1:8081
TOKEN="$(cat /etc/gateway/admin-token)"
curl --fail-with-body -X POST "$ADMIN/admin/kms/rotate/start" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target_version":2,"grace_period":"30s"}'
curl --fail-with-body "$ADMIN/admin/kms/rotate/status" -H "Authorization: Bearer $TOKEN"
# After checking the ready phase and the intended replica:
curl --fail-with-body -X POST "$ADMIN/admin/kms/rotate/commit" -H "Authorization: Bearer $TOKEN"
```

### Multipart administration

| Method/path | Response / operational warning |
|---|---|
| GET `/admin/mpu/list` | 200 active_uploads/count/timestamp from state store; not all backend orphan MPUs |
| POST `/admin/mpu/abort/{uploadId}` | 200 status/upload/bucket/key after state deletion; 404 NoSuchUpload, 400 empty ID, 500 state failures |

Admin abort attempts backend abort best-effort, then deletes state **even if the
backend abort failed**. A 200 therefore does not prove no backend orphan remains.
Use it only with a reviewed cleanup procedure and inspect backend uploads afterward.

### Profiling endpoints and metrics

Profiling is opt-in under `admin.profiling.enabled`, inherits bearer/rate controls,
and can contain sensitive process data. `/admin/debug/pprof/` exposes cmdline,
profile, symbol, trace, heap, goroutine, allocs, block, mutex, threadcreate.
CPU/trace seconds are capped and concurrency bounded (429 Retry-After); invalid
seconds returns 400. Canonical settings/endpoints/recipes are in
[observability](OBSERVABILITY.md#runtime-profiling), not duplicated here.

Rotation emits key_rotation.start/committed/aborted audit events and bounded
operation/duration/in-flight/active-version metrics. Profiling emits fetch audit
and request metrics. See source and observable families rather than relying on
an old copied metric inventory.

## Alert Playbooks

### high-error-rate

Check backend status, scope/auth failures, dependency readiness, and logs. Separate
storage failures from decrypt/tamper errors. Reduce load or repair upstream health;
do not move ciphertext to an arbitrary failover bucket or silently downgrade crypto.

### high-latency

Inspect CPU/heap/GC, backend latency, Valkey/KMS retries, spool pressure, and listing
HEAD amplification. Scale based on measured bottlenecks. Increasing buffers/chunks
without memory/concurrency accounting is not a universal fix.

### encryption-errors

Preserve bytes/metadata/version. Check keys, allowed formats/KDF costs, location
binding, and genuine tamper/truncation. Backend availability errors have their own
provenance. Do not strip markers or serve ciphertext as recovered plaintext.

### kms-unhealthy

Check provider-specific health, TLS chain/hostname, egress, key existence, and auth.
An HTTP server response is not a successful wrap/unwrap. Restore the same provider
identity/old keys; switching to password mode cannot decrypt KMS-wrapped objects.

### kms-outage-degraded-mode

Bounded retry/breaker may fail fast; optional cached unwrap results can serve some
reads until TTL, not all objects or new writes. Failure codes vary by API path.
Restore provider connectivity/policy and verify wrap/unwrap plus reads/writes;
do not promise every PUT/part has one universal failure status.

### kms-auth-token-expired

Transit AppRole/Kubernetes can re-login on renewal/request failure; fixed-token
lifecycle is operator-owned. Check role/JWT/secret source and lookup/renew policy.
Growing reauth failure indicates broken credentials, not a problem solved by restart.

### valkey-down

Check TLS/auth/DNS, pod/disk/memory state, and persistent data. Required MPUs fail
closed; listings can retain ciphertext sizes. Recovery needs original state-key
envelope and provider keys. If state is gone, drain/abort backend uploads and create
new ones; do not assume the old encrypted MPU can resume from backend parts alone.

### Gateway CORS Valkey data loss and recovery

**Unreleased main (GH-322):** Before enabling gateway mode, confirm retained-storage
persistence, an independent backup, and an exercised restore. A startup persistence
warning/check does not establish backup health. CORS rules are durable Valkey policy
without TTL, not disposable upload state, and are not recreated by config reload.

Readiness can be healthy after an empty reset: probe an authorized `GET ?cors` for
a known configured bucket. Store outage/corruption returns 503 ServiceUnavailable;
a missing policy returns 404 NoSuchCORSConfiguration and can activate configured
fallback. Review/disable broad fallback before recovery. Restore the tested Valkey
backup or re-apply exported known XML with signed `PUT ?cors` using a bucket manage
grant. Verify preflight and an actual ETag-readable response on **each replica**.
Static templates cannot recover API mutations unless those policies were exported.

### Encrypted MPU nonce-safety rollout

Follow [coordinated migration](MIGRATION.md#012-upgrade-notice-including-0123):
drain/abort legacy encrypted MPUs, separately scale down old writers before image
upgrade, enable state-v2 writers uniformly, verify writer capability/readiness.
Do not mix old mutable writers with immutable content claims. Changed-content
409s require abort/new upload, not retry with another nonce. Rollback requires
draining v2 uploads and retaining a reader capable of stored object formats.

### valkey-insecure

Remove development plaintext/TLS-verification overrides, configure trusted CA and
matching hostname/client auth, and coordinate restart. State encryption does not
replace transport confidentiality.

### tls-cert-expiry

Check certificate expiry and issuing trust for the actual listener/backend/KMS.
Rotate secrets/certificates through supported deployment, verify handshake and
signed S3 requests. Avoid global insecure verification as an expiry workaround.

### backend-retries

Inspect retry give-up reason, provider throttling, endpoint/region, and seekable-body
semantics. More retries can amplify load; repair the bottleneck and validate the
operation's mutation/idempotence behavior before raising limits.

### valkey-legacy-state

Investigate explicit legacy fallback, restored old snapshots, or mismatched replica
settings. Retain required legacy decrypt material during approved drain/abort;
disable plaintext fallback afterward. Elapsed TTL alone is not an audit proving
all backups/state have migrated.

## Troubleshooting

| Symptom | Check |
|---|---|
| Ready but signed uploads fail | Writable spool, operation caps, backend signing/proxy behavior |
| State decrypt / unwrap failure | Wrapped state DEK, original provider/password, retained versions, matching snapshot |
| Listing sync loops | Advisory ciphertext size misses, fallback costs, backend ETags |
| Old objects fail after key change | Retained keys/metadata key, identity binding, reader limits; isolate recovery |
| Admin abort succeeded but uploads persist | Best-effort backend abort; inspect and explicitly clean backend orphans |

## Per-Bucket Traffic

```promql
sum by (bucket, direction) (rate(s3_client_bytes_total[5m]))
sum by (bucket, operation, status_code) (rate(s3_client_requests_total[5m]))
```

These count application-body traffic, not backend/internal encrypted traffic.
Bucket labels can increase cardinality/expose names; see
[client traffic metrics](OBSERVABILITY.md#client-traffic-metrics-v10-obs-2).
