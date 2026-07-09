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

## ListObjects Plaintext Size Cache (V1.0-S3-3)

### Overview

`handleListObjects` resolves plaintext sizes for encrypted objects via a
write-through Valkey hash (`plainsize:<bucket>`) instead of issuing one
`HeadObject` per listed key. The index is populated by `PutObject`,
`CompleteMultipartUpload`, and `CopyObject`, and evicted by `DeleteObject` /
`DeleteObjects`. A whole listing page resolves with a single `HMGET`.

This is what makes sync clients (rclone, restic, Duplicati, s5cmd) observe
`ListObjects[i].Size == HeadObject(key).Content-Length`. Without it, every
encrypted object looks "modified" on every sync run and is re-transferred.

The size cache shares the **same Valkey instance and connection pool** as the
multipart-upload state store — there is no second Valkey deployment. Unlike MPU
state, the size cache is **fail-soft**: if Valkey is unavailable, listings
return ciphertext sizes (the pre-v0.11.1 behaviour) with no `5xx`. Valkey is
strongly recommended for ListObjects, not a hard dependency.

### Metrics to watch

| Metric | Meaning |
|---|---|
| `list_size_cache_hits_total{bucket}` | Keys resolved from the cache (good) |
| `list_size_cache_misses_total{bucket}` | Keys absent from the cache |
| `list_size_fallback_head_total{bucket,result}` | `HeadObject` calls from the opt-in fallback batch (`hit`/`timeout`/`error`) |

Track the warm-up ratio:

```promql
sum(rate(list_size_cache_hits_total[5m]))
  /
(sum(rate(list_size_cache_hits_total[5m])) + sum(rate(list_size_cache_misses_total[5m])))
```

A ratio climbing toward 1.0 during normal traffic means the cache is warming.
A rising `list_size_fallback_head_total` indicates billing exposure on
per-API-call backends (Wasabi, R2, B2) — disable `fallback_head_enabled` if
cost is a concern.

### Warming legacy objects

Objects uploaded before V1.0-S3-3 was deployed are **not** auto-indexed. They
populate naturally as they are re-uploaded or copied. To warm them via normal
listing traffic, temporarily enable the fallback HEAD batch:

```yaml
list_size_translate:
  enabled: true
  fallback_head_enabled: true      # opt-in; bounded by concurrency + timeout
  fallback_head_concurrency: 10
  fallback_head_timeout: 5s
```

Watch `list_size_fallback_head_total` and the warm-up ratio; once misses trend
to near-zero, set `fallback_head_enabled: false` again to stop the HEAD cost.
A proactive admin warm-up endpoint (`POST /admin/warm-size-cache`) is noted as
a follow-up in the plan but is not yet implemented.

### Behaviour during a Valkey outage

- `ListObjects` keeps serving `200 OK` with **ciphertext sizes** for all keys.
  No `5xx`, no panic. Expect a log line at `WARN` level:
  `handleListObjects: size cache GetBatch failed; returning ciphertext sizes`.
- Sync clients will flag every encrypted object as modified and re-transfer
  until Valkey recovers and the cache re-warms. This is a correctness/
  efficiency regression, not a data-loss event.
- Multipart uploads are unaffected by the size cache; they remain fail-closed
  on Valkey outage (see [valkey-down](#valkey-down)).
- On recovery, the cache re-warms through normal write traffic (or the fallback
  HEAD batch if enabled). There is no manual repair step.

---

## Alert Playbooks

### high-error-rate

**Alert:** `S3GatewayHighErrorRate`
**Severity:** critical
**Expression:** `rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05`

**Symptom:** The gateway is returning 5xx errors for more than 5% of requests.

**Diagnosis:**
1. Check the backend S3 provider health and connectivity.
2. Examine gateway logs for error stacks: `kubectl logs -l app=s3-encryption-gateway --tail=100 | grep -E '"level":"error"'`.
3. Check if the issue is isolated to specific routes: `sum by (path) (rate(http_requests_total{status=~"5.."}[5m]))`.
4. Verify the encryption engine and KMS are operational.

**Mitigation:**
- If backend is degraded, fail over to a secondary S3 endpoint if configured.
- If KMS is unreachable, ensure the KMS endpoint is accessible (see #kms-unhealthy).
- If the gateway is overloaded, scale up replicas: `kubectl scale deployment s3-encryption-gateway --replicas=N`.
- Restart a single replica to confirm if the issue is process-level (memory leak, goroutine leak).

---

### high-latency

**Alert:** `S3GatewayHighLatency`
**Severity:** warning
**Expression:** `histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 2`

**Symptom:** P99 request latency exceeds 2 seconds.

**Diagnosis:**
1. Check CPU and memory metrics in the Runtime dashboard row.
2. Verify backend S3 latency: `rate(s3_operation_duration_seconds_sum[5m]) / rate(s3_operation_duration_seconds_count[5m])`.
3. Check Valkey latency for MPU operations: `rate(gateway_mpu_state_store_latency_seconds_sum[5m]) / rate(gateway_mpu_state_store_latency_seconds_count[5m])`.
4. Look for GC pressure: check goroutines and heap memory.

**Mitigation:**
- If backend latency is high, check the upstream S3 provider.
- If Valkey latency is high, scale Valkey or add replicas.
- Increase gateway replica count to spread load.
- Consider increasing `chunk_size` if small chunks cause excessive per-chunk overhead.

---

### encryption-errors

**Alert:** `S3GatewayEncryptionErrors`
**Severity:** critical
**Expression:** `increase(encryption_errors_total[5m]) > 0`

**Symptom:** Encryption operations are failing.

**Diagnosis:**
1. Check the error type: `sum by (error_type) (rate(encryption_errors_total[5m]))`.
2. Verify KMS connectivity (see #kms-unhealthy).
3. Check if the operation is Encrypt or Decrypt: `rate(encryption_operations_total[5m])`.
4. Examine gateway logs for AEAD or key-derivation errors.

**Mitigation:**
- If KMS-related: ensure the KMS endpoint is reachable and the key exists.
- If algorithm mismatch: the gateway might not support the algorithm used to encrypt stored objects. Verify `supported_algorithms` in config.
- If memory-related: ensure the gateway has sufficient memory for chunked encryption.
- Restart the gateway pod if the error is transient.

---

### kms-unhealthy

**Alert:** `S3GatewayKMSUnhealthy`
**Severity:** critical
**Expression:** `gateway_kms_healthy == 0`

**Symptom:** KMS health check has been failing for more than 2 minutes.

**Diagnosis:**
1. Check KMS provider endpoint from the gateway pod: `kubectl exec POD -- curl -v http://kms-endpoint:port/`.
2. Verify network policies allow egress to the KMS endpoint.
3. Check TLS certificates if the KMS uses mTLS.
4. Inspect KMS server logs (external system).

**Mitigation:**
- Restart the KMS service if self-hosted (Cosmian, Vault).
- If using AWS KMS, check AWS health dashboard.
- If the outage is prolonged, consider switching to a different KMS provider (requires config change and restart).
- As a last resort, switch to password-only mode (no KMS) to restore service, then resolve the KMS issue.

### kms-outage-degraded-mode

**Scenario:** KMS is fully unavailable (network partition, KMS service down).

**Behaviour under V1.0-KMS-1 harness:**
- The retry wrapper will exhaust `max_elapsed_time` (default 30 s) per request,
  then return an error.
- If the circuit breaker is enabled (recommended), after `consecutive_failures`
  failures (default 5) it trips open and all subsequent WrapKey/UnwrapKey calls
  fail immediately with `ErrProviderUnavailable` (503 to clients). This prevents
  goroutine pile-up during prolonged outages.
- The DEK cache (if enabled) continues to serve previously-cached unwrap results
  for up to `ttl` seconds (default 60 s). READ operations for recently-accessed
  objects continue to succeed from cache; write operations (new PutObject,
  UploadPart) fail immediately.
- The health-check goroutine updates `gateway_kms_healthy` to 0, triggering the
  `S3GatewayKMSUnhealthy` alert.

**Recovery:**
1. When the KMS recovers, the circuit breaker Half-Open probe succeeds and the
   breaker closes automatically.
2. The health-check goroutine updates `gateway_kms_healthy` to 1.
3. No gateway restart is required.

**Fail-closed guarantee:** Write operations (new object encryption) always
require a successful `WrapKey` call; the DEK cache covers only reads. A
gateway running with a downed KMS will accept GET requests for cached objects
but reject PUT/POST operations. This is the correct degraded-mode posture.

---

### valkey-down

**Alert:** `S3GatewayValkeyDown`
**Severity:** critical
**Expression:** `gateway_mpu_valkey_up == 0`

**Symptom:** Valkey (Redis) has been unreachable for more than 2 minutes.

**Diagnosis:**
1. Check Valkey pod status: `kubectl get pods -l app=valkey`.
2. Test connectivity from the gateway pod: `kubectl exec POD -- nc -zv valkey 6379`.
3. Verify Valkey configuration (address, TLS, credentials).
4. Check Valkey server logs.

**Mitigation:**
- Restart the Valkey pod: `kubectl rollout restart deployment/valkey`.
- If Valkey has persistent storage, check for disk or memory pressure.
- In-flight multipart uploads will fail until Valkey is restored — the uploads are not lost on the S3 side, but the state store is temporarily unavailable.
- `ListObjects` **degrades, not fails**: listings return `200 OK` with ciphertext sizes, so sync clients (rclone, restic, s5cmd) will re-transfer encrypted objects until Valkey recovers and the size cache re-warms. No data loss; see [ListObjects Plaintext Size Cache](#listobjects-plaintext-size-cache-v10-s3-3).
- After Valkey recovers, in-flight uploads with active TTLs will be readable again, and the size cache re-warms through normal write traffic.

---

### valkey-insecure

**Alert:** `S3GatewayValkeyInsecure`
**Severity:** warning
**Expression:** `gateway_mpu_valkey_insecure == 1`

**Symptom:** Valkey connection is established without TLS.

**Diagnosis:**
1. Check Helm values or config YAML for `multipart_state.valkey.tls.enabled`.
2. Verify that Valkey is configured with TLS enabled.
3. Check if `insecure_allow_plaintext: true` is set.

**Mitigation:**
- Set `multipartState.valkey.tls.enabled: true` in Helm values.
- Configure Valkey with TLS certificates.
- Remove `insecure_allow_plaintext` from production config.
- Rolling restart the gateway.

---

### tls-cert-expiry

**Alert:** `S3GatewayTLSCertExpiringSoon` (warning, < 7 days) / `S3GatewayTLSCertExpiryCritical` (critical, < 2 days)
**Expression:** `gateway_tls_cert_expiry_seconds < 604800` / `gateway_tls_cert_expiry_seconds < 172800`

**Symptom:** The gateway's TLS serving certificate is approaching its expiration date.

**Diagnosis:**
1. Check certificate details: `openssl x509 -in /path/to/cert.crt -noout -enddate`.
2. Verify the cert file path matches `tls.cert_file` in config.
3. Check the `role` label (data_plane, admin, metrics) on the metric to identify which listener.

**Mitigation:**
1. Generate a new certificate and key.
2. Update the Kubernetes secret or mounted file with the new cert.
3. Rolling restart the gateway pods.
4. Verify the new cert: `echo | openssl s_client -connect GATEWAY:443 -servername GATEWAY 2>/dev/null | openssl x509 -noout -enddate`.

---

### backend-retries

**Alert:** `S3GatewayHighRetryGiveUpRate`
**Severity:** warning
**Expression:** `rate(s3_backend_retry_give_ups_total[5m]) > 0.1`

**Symptom:** The gateway is giving up on backend S3 requests at a high rate.

**Diagnosis:**
1. Check which operation is failing: `sum by (final_reason) (rate(s3_backend_retry_give_ups_total[5m]))`.
2. Verify backend S3 health.
3. Check backend retry configuration: `initial_backoff`, `max_attempts`, `mode`.
4. Look for network issues between gateway and backend.

**Mitigation:**
- Increase `backend.retry.max_attempts` if the backend is experiencing transient failures.
- Check for throttling by the upstream S3 provider (request rate limiting).
- Verify network stability between gateway and backend.
- If the backend is degraded, fail over to a secondary endpoint.

---

### valkey-legacy-state

**Alert:** `S3GatewayLegacyValkeyStateReads`
**Severity:** info
**Expression:** `increase(gateway_mpu_state_legacy_reads_total[1h]) > 0`

**Symptom:** The gateway is reading unencrypted Valkey state blobs.

**Diagnosis:**
1. Check if a recent migration to `encrypt_state: true` is still in progress.
2. If the alert fires more than 7 days after the migration, investigate whether a gateway replica has encryption disabled.
3. Check `valkey.ttl_seconds` — default is 7 days (604800 seconds).

**Mitigation:**
- No action required if this is during the TTL-based migration window (up to 7 days after enabling encrypt_state).
- If persistent beyond 7 days, verify all replicas have `encrypt_state: true` and the encryption password is correctly injected.
- If a replica is running without encryption, rolling restart with the correct configuration.

---

## Troubleshooting

| Symptom | Likely Cause | Remediation |
|---|---|---|
| Gateway fails to start: `"valkey state encryption enabled but no encryption password available"` | `VALKEY_ENCRYPTION_PASSWORD` env var is empty or the named env var is not injected | Verify the secret is mounted; check `kubectl describe pod` for env vars |
| `gateway_mpu_state_legacy_reads_total` is increasing after migration window | A gateway replica was restarted without the new password, or a plaintext backup was restored | Ensure all replicas use the same `VALKEY_ENCRYPTION_PASSWORD`; check for Valkey RDB restores |
| Multipart uploads fail with `mpu: state decrypt failed` | Encryption password was rotated without draining in-flight uploads | Follow the key-rotation procedure (drain uploads first) |
| Startup warning: `encrypt_state is false` | `valkey.encrypt_state: false` is set in config | Remove the override to re-enable at-rest encryption |
