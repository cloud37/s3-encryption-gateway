# S3 Encryption Gateway — Operations Runbook

This runbook covers operational procedures for the S3 Encryption Gateway.

---

## Valkey State At-Rest Encryption

### Overview

As of v1.0 (V1.0-CRYPTO-2), the multipart-upload state store encrypts all
`UploadState` blobs in Valkey using AES-256-GCM. The encryption key is derived
from a dedicated password via HKDF-SHA256 with a fixed public salt
`"s3eg-mpu-state-v1"` that is distinct from any other key in the system.

When `valkey.encrypt_state=true` (the default), every `Create` writes an
opaque ciphertext blob to Valkey. A read-only attacker with access to Valkey
memory dumps, RDB/AOF files, or replication streams sees only random-looking
bytes. They cannot recover bucket names, object keys, IV prefixes, wrapped
DEKs, or any other upload metadata without the encryption key.

---

### Enabling Encryption

**Step 1 — Set the encryption password secret.**

```bash
# Kubernetes — create or update the secret
kubectl create secret generic s3gw-valkey-enc \
  --from-literal=VALKEY_ENCRYPTION_PASSWORD="$(openssl rand -base64 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

**Step 2 — Configure the gateway.**

In `config.yaml`:

```yaml
multipart_state:
  valkey:
    encryption_password_env: "VALKEY_ENCRYPTION_PASSWORD"
    encrypt_state: true   # default; can be omitted
```

Or via environment variables:

```bash
export VALKEY_ENCRYPTION_PASSWORD_ENV="VALKEY_ENCRYPTION_PASSWORD"
export VALKEY_ENCRYPT_STATE="true"
```

**Step 3 — Inject the secret into the gateway pod.**

```yaml
# Helm values
multipartState:
  valkey:
    encryptionPasswordEnv: "VALKEY_ENCRYPTION_PASSWORD"
    encryptState: true

env:
  - name: VALKEY_ENCRYPTION_PASSWORD
    valueFrom:
      secretKeyRef:
        name: s3gw-valkey-enc
        key: VALKEY_ENCRYPTION_PASSWORD
```

**Step 4 — Rolling restart.**

Restart all gateway replicas. The new password takes effect immediately for
all new `CreateMultipartUpload` calls. In-flight uploads that were created
before the restart use the old (plaintext) state, which the fallback path
handles transparently (see "Legacy Plaintext Migration" below).

---

### Verifying Encryption Is Active

Scrape the Prometheus endpoint and check:

```promql
# Encrypted writes — should be > 0 after the first multipart upload
rate(gateway_mpu_state_encrypted_writes_total[5m])

# Legacy reads — should decrease toward 0 as old uploads expire
rate(gateway_mpu_state_legacy_reads_total[5m])
```

**Expected steady state:** `encrypted_writes_total` increases with every
multipart upload; `legacy_reads_total` is 0 after all pre-migration uploads
have completed or expired via TTL (default: 7 days).

---

### Legacy Plaintext Migration

The gateway uses a **lazy migration** strategy. No operator action is required:

1. New uploads are always written encrypted.
2. Old plaintext blobs are read with a transparent fallback: if AES-GCM
   decryption fails, the raw JSON is parsed as plaintext. A single `WARN`
   log is emitted (de-duplicated via `sync.Once`):
   ```
   Unencrypted Valkey state detected — enable valkey.encrypt_state=true
   ```
3. Each legacy fallback increments `gateway_mpu_state_legacy_reads_total`.
4. Plaintext blobs expire automatically via the Valkey TTL (default 7 days).
   After the TTL window, no plaintext state remains.

**No manual re-encryption step is needed.** Operators who want to accelerate
the migration can reduce `valkey.ttl_seconds` temporarily (forcing faster
expiry of old uploads) — but this risks aborting in-flight uploads. Do not
change TTL unless all in-flight uploads are complete or aborted.

---

### Rotating the Encryption Key

Key rotation requires a brief window where both the old and new keys must be
available. Because the gateway does not support simultaneous dual-key decryption
for state blobs, the recommended procedure is:

1. **Complete or abort all in-flight multipart uploads.** Query
   `ListMultipartUploads` across all buckets and wait for the list to drain,
   or issue `AbortMultipartUpload` for stale uploads.

2. **Set the new password in the secret store** and update the Kubernetes
   secret (or equivalent).

3. **Rolling restart** the gateway replicas with the new
   `VALKEY_ENCRYPTION_PASSWORD`. Replicas with the new key write new blobs
   encrypted with the new key. Any blobs written by the old replicas (with
   the old key) that are still in Valkey will fail decryption and trigger the
   legacy plaintext fallback — but since those blobs were encrypted (not
   plaintext), they will return `ErrStateDecryptFailed` and the upload will
   fail. This is why Step 1 is critical.

4. **Verify** that `gateway_mpu_state_legacy_reads_total` remains 0 after
   the restart.

> **Warning:** Password loss = inability to read in-flight MPU state. The
> underlying object encryption DEK is safe (it is wrapped by the
> `KeyManager`), but the upload's Valkey metadata becomes unreadable. Always
> back up the password in a secure secrets manager (e.g., Vault, AWS Secrets
> Manager, GCP Secret Manager).

---

### Disabling Encryption (Deprecated)

Setting `encrypt_state: false` disables at-rest encryption. This option is
**deprecated as of v1.0** and will be removed in v2.0.

A startup warning is logged when this option is set:

```
multipart_state.valkey.encrypt_state is false — at-rest encryption is
disabled for Valkey multipart state (deprecated, will be removed in v2.0)
```

Use this option only as a temporary escape hatch during a migration or for
local development. Do not use in production.

---

### Monitoring Alerts

Recommended alert rules:

```yaml
# Alert if legacy reads appear in steady state (after migration window)
- alert: MPUStateLegacyReadsActive
  expr: increase(gateway_mpu_state_legacy_reads_total[1h]) > 0
  for: 30m
  labels:
    severity: warning
  annotations:
    summary: "Unencrypted Valkey state blobs are being read"
    description: >
      gateway_mpu_state_legacy_reads_total is increasing. Unencrypted
      multipart-upload state blobs are present in Valkey. These will expire
      via TTL after {{ $labels.valkey_ttl_seconds }} seconds. If this alert
      fires more than 7 days after enabling encrypt_state=true, investigate
      whether a gateway replica is still running with encryption disabled.

# Alert if encrypted writes stop (encryption may have been accidentally disabled)
- alert: MPUStateEncryptedWritesStopped
  expr: rate(gateway_mpu_state_encrypted_writes_total[15m]) == 0
    and rate(gateway_mpu_state_store_ops_total{op="create",result="success"}[15m]) > 0
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "MPU state encrypted writes have stopped despite active creates"
    description: >
      Multipart upload creates are succeeding but the encrypted-writes counter
      is not incrementing. This may indicate encrypt_state was set to false or
      the encryption key is missing.
```

---

### Troubleshooting

| Symptom | Likely Cause | Remediation |
|---|---|---|
| Gateway fails to start: `"valkey state encryption enabled but no encryption password available"` | `VALKEY_ENCRYPTION_PASSWORD` env var is empty or the named env var is not injected | Verify the secret is mounted; check `kubectl describe pod` for env vars |
| `gateway_mpu_state_legacy_reads_total` is increasing after migration window | A gateway replica was restarted without the new password, or a plaintext backup was restored | Ensure all replicas use the same `VALKEY_ENCRYPTION_PASSWORD`; check for Valkey RDB restores |
| Multipart uploads fail with `mpu: state decrypt failed` | Encryption password was rotated without draining in-flight uploads | Follow the key-rotation procedure (drain uploads first) |
| Startup warning: `encrypt_state is false` | `valkey.encrypt_state: false` is set in config | Remove the override to re-enable at-rest encryption |
