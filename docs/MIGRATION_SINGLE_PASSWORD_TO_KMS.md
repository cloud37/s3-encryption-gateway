# Migration Guide: Single-Password Mode → KMS Mode

This guide walks operators through migrating an S3 Encryption Gateway deployment
from **single-password mode** (static `encryption.password`) to
**KMS mode** (`encryption.key_manager.enabled: true`) with minimal downtime.

KMS mode unlocks safe key rotation, dual-read windows for backward
compatibility, Prometheus metrics for key health, and audit logging for every
wrapping/unwrapping event.

---

## Table of Contents

1. [Before You Begin](#1-before-you-begin)
2. [Concepts](#2-concepts)
3. [Migration Strategies](#3-migration-strategies)
4. [Step-by-Step: Memory Provider (local / single-node)](#4-step-by-step-memory-provider)
5. [Step-by-Step: Cosmian KMIP Provider (production)](#5-step-by-step-cosmian-kmip-provider)
6. [Verifying the Migration](#6-verifying-the-migration)
7. [First Key Rotation After Migration](#7-first-key-rotation-after-migration)
8. [Rollback](#8-rollback)
9. [Troubleshooting](#9-troubleshooting)
10. [Reference](#10-reference)

---

## 1. Before You Begin

### Prerequisites

| Requirement | Details |
|---|---|
| Gateway version | v0.6 or later |
| Go test access | `go test ./...` must pass before and after |
| Backup | All encrypted objects backed up or snapshots taken |
| KMS (for production) | Cosmian KMS ≥ 5.22.0 running and reachable from the gateway |
| Admin API | `admin.enabled: true` configured; bearer token on hand |
| Monitoring | Prometheus scraping `/metrics`; `kms_*` metrics visible |

### What does NOT change

- **Object ciphertext on disk.** Existing objects encrypted under the old
  password are **never rewritten** during migration. They continue to be
  accessible via the dual-read window.
- **Client behaviour.** S3 API is identical before and after. No client
  changes are required.
- **Data-plane address/port.** The S3 listener address is unchanged.

### What DOES change

- New objects are wrapped with the KMS-managed key instead of the raw
  `PBKDF2(password, …)` derivation path.
- Gateway startup now contacts the KMS and fails closed if the KMS is
  unreachable.
- Prometheus exposes additional `kms_*` metrics.
- Admin API endpoints (`/admin/kms/rotate/*`) become active.

---

## 2. Concepts

### Encryption modes

| Mode | Config | DEK wrapping |
|---|---|---|
| **Single-password** | `key_manager.enabled: false` | `PBKDF2(password, per-object-salt)` — no external dependency |
| **KMS (memory)** | `key_manager.enabled: true`, `provider: memory` | In-process AES-256 key-wrap (RFC 3394) against a master key in env/file |
| **KMS (Cosmian)** | `key_manager.enabled: true`, `provider: cosmian` | Remote KMIP WrapKey/UnwrapKey call |

### Dual-read window

When KMS mode is first enabled the gateway sets the new KMS provider as the
active wrapper for **new** writes. Old objects still carry a
`x-amz-meta-encryption-key-version` of `0` (or absent, which is treated as
legacy single-password). The `dual_read_window` setting controls how many
previous key versions the engine tries when unwrapping a DEK; set it to `1`
to cover the single-password → version-1 transition, and increase it if you
later rotate more than once without retiring old versions.

### Migration path summary

```
Single-password (v≡0) → KMS v1 (active)
                              ↑
                        dual_read_window: 1 allows reading v0 objects
```

---

## 3. Migration Strategies

| Strategy | Best for | Downtime |
|---|---|---|
| **Rolling restart** (recommended) | Kubernetes / multi-replica | None — replicas drain in-flight requests, restart one at a time |
| **Stop-write / restart** | Single-instance, low risk | Seconds — stop traffic, restart, resume |
| **Blue-green** | Strict zero-downtime SLA | None — cut over via load-balancer |

All strategies follow the same configuration steps below. The difference is
only in _how_ you apply the new configuration and restart.

---

## 4. Step-by-Step: Memory Provider

The `memory` provider stores a master AES-256 key in an environment
variable or file. It has no external runtime dependency and is suitable for:

- Local development and testing
- Single-node deployments where the host is already the trust boundary
- Evaluating KMS mode before connecting an external KMIP server

> **Warning**: an auto-generated master key (`master_key_source: ""`) is
> **lost on pod/container restart**. Every previously wrapped DEK becomes
> unrecoverable. Always supply an explicit key source in production.

### 4.1 Generate and store the master key

```bash
# Generate a 32-byte (256-bit) master key and base64-encode it
openssl rand -base64 32
# Example output: y7Kp+8rVtA3...==

# Store it securely — DO NOT commit to git
export MEMORY_KM_MASTER_KEY_SOURCE="env:MEMORY_MASTER_KEY"
export MEMORY_MASTER_KEY="y7Kp+8rVtA3...=="

# For Kubernetes, use a Secret:
kubectl create secret generic gateway-master-key \
  --from-literal=master-key="$(openssl rand -base64 32)"
```

### 4.2 Update configuration

Edit your `config.yaml`:

```yaml
encryption:
  password: "your-existing-password"  # Keep — still needed to decrypt old objects
  key_manager:
    enabled: true
    provider: memory
    dual_read_window: 1  # Covers the old single-password objects
    memory:
      master_key_source: "env:MEMORY_MASTER_KEY"
      # Alternatively:
      # master_key_source: "file:/etc/gateway/master.key"
```

Environment:

```bash
export MEMORY_MASTER_KEY="<base64-encoded-256-bit-key>"
```

### 4.3 Validate and restart

```bash
# Lint the config
yamllint config.yaml

# Dry-run (if supported by your build)
./s3-encryption-gateway --config config.yaml --validate

# Rolling restart (Kubernetes)
kubectl rollout restart deployment/s3-encryption-gateway

# Direct restart (systemd)
systemctl restart s3-encryption-gateway
```

### 4.4 Smoke test

```bash
# Upload a new object
aws s3 cp test.txt s3://my-bucket/test-after-migration.txt \
  --endpoint-url http://gateway:8080

# Confirm new object has key version 1
aws s3api head-object --bucket my-bucket --key test-after-migration.txt \
  --endpoint-url http://gateway:8080 \
  --query 'Metadata."x-amz-meta-encryption-key-version"'
# Expected: "1"

# Confirm an OLD object (key version absent / 0) still downloads correctly
aws s3 cp s3://my-bucket/old-object.bin /tmp/old-object.bin \
  --endpoint-url http://gateway:8080
```

---

## 5. Step-by-Step: Cosmian KMIP Provider

The `cosmian` provider calls a Cosmian KMS server for all WrapKey/UnwrapKey
operations. It is the recommended provider for production deployments.

### 5.1 Start Cosmian KMS

```bash
docker run -d --rm --name cosmian-kms \
  -p 5696:5696 -p 9998:9998 \
  --entrypoint cosmian_kms \
  ghcr.io/cosmian/kms:5.22.0
```

For production, follow the
[Cosmian installation guide](https://docs.cosmian.com/key_management_system/installation/installation_getting_started/)
for TLS and identity configuration.

### 5.2 Create the first wrapping key

1. Open the Cosmian KMS UI: `http://kms-host:9998/ui`
2. Navigate to **Keys → Create New Key**
3. Set:
   - **Algorithm**: AES-256
   - **Key Type**: Symmetric
   - **Usage**: Encryption + Decryption
4. Save the **Key ID** (e.g. `wrapping-key-v1`).

### 5.3 Update configuration

```yaml
encryption:
  password: "your-existing-password"  # Keep — still needed to read old objects
  key_manager:
    enabled: true
    provider: cosmian
    dual_read_window: 1  # Covers the old single-password objects
    cosmian:
      endpoint: "http://kms-host:9998/kmip/2_1"  # JSON/HTTP (recommended)
      # endpoint: "http://kms-host:9998"            # Base URL also works
      # For binary KMIP (requires TLS):
      # endpoint: "kms-host:5696"
      # ca_cert: "/etc/gateway/kms-ca.pem"
      # client_cert: "/etc/gateway/client.crt"
      # client_key: "/etc/gateway/client.key"
      timeout: "10s"
      keys:
        - id: "wrapping-key-v1"
          version: 1
```

Environment variables (alternative to embedding in config):

```bash
export COSMIAN_KMS_ENDPOINT="http://kms-host:9998/kmip/2_1"
export COSMIAN_KMS_TIMEOUT="10s"
export KEY_MANAGER_PROVIDER="cosmian"
export KEY_MANAGER_ENABLED="true"
```

### 5.4 Validate connectivity

```bash
# Test KMS reachability
curl -f http://kms-host:9998/kmip/2_1 || echo "KMS not reachable"

# Validate gateway config
./s3-encryption-gateway --config config.yaml --validate
```

### 5.5 Deploy

**Kubernetes / Helm rolling restart (recommended):**

```bash
helm upgrade s3-encryption-gateway ./helm/s3-encryption-gateway \
  --set encryption.keyManager.enabled=true \
  --set encryption.keyManager.provider=cosmian \
  --set encryption.keyManager.dualReadWindow=1 \
  --set encryption.keyManager.cosmian.endpoint="http://kms-host:9998/kmip/2_1" \
  --set "encryption.keyManager.cosmian.keys[0].id=wrapping-key-v1" \
  --set "encryption.keyManager.cosmian.keys[0].version=1"
```

Or apply a values file and let Kubernetes perform the rolling update:

```bash
kubectl apply -f config.yaml
kubectl rollout restart deployment/s3-encryption-gateway
kubectl rollout status deployment/s3-encryption-gateway
```

**Direct / systemd:**

```bash
systemctl restart s3-encryption-gateway
```

### 5.6 Smoke test

```bash
# Check readiness
curl http://gateway:8080/readyz
# {"status":"ready",...}

# Upload a new object and verify key version
aws s3 cp test.txt s3://my-bucket/test-kms.txt \
  --endpoint-url http://gateway:8080
aws s3api head-object --bucket my-bucket --key test-kms.txt \
  --endpoint-url http://gateway:8080 \
  --query 'Metadata."x-amz-meta-encryption-key-version"'
# Expected: "1"

# Read an old (single-password) object
aws s3 cp s3://my-bucket/old-object.bin /tmp/old-object.bin \
  --endpoint-url http://gateway:8080
# Should succeed without error
```

---

## 6. Verifying the Migration

### 6.1 Health endpoints

```bash
# Data-plane readiness (includes KMS health check)
curl -s http://gateway:8080/readyz | jq .

# Expected when KMS is healthy:
# {"status":"ready","checks":{"kms":"ok",...}}
```

### 6.2 Prometheus metrics

After migration the following metrics should appear in `/metrics`:

| Metric | Expected value |
|---|---|
| `kms_active_key_version{provider="…"}` | `1` (or your active version) |
| `kms_rotation_operations_total` | `0` initially |
| `kms_rotation_in_flight_wraps` | `0` |

```bash
curl -s http://gateway:8080/metrics | grep '^kms_'
```

### 6.3 Audit logs

New encrypt/decrypt operations emit structured JSON. Verify that
`key_version` is `1` on new objects and that legacy reads (old objects)
show `rotated_read: true` when dual-read is triggered:

```bash
# Tail logs for key events
journalctl -u s3-encryption-gateway -f | jq 'select(.event_type == "decrypt")'

# Check for legacy (single-password) reads
journalctl -u s3-encryption-gateway | \
  jq 'select(.metadata.rotated_read == true)' | head -20
```

### 6.4 Full go test suite

```bash
go test ./... -race -short
```

All tests must pass unchanged. If any test touches `ENCRYPTION_PASSWORD`
and the KMS provider, ensure the test environment has the master key set.

---

## 7. First Key Rotation After Migration

After migration you are on key version `1`. When you later need to rotate:

### 7.1 Create a new wrapping key in your KMS

Follow the same steps as §5.2, getting a new key ID (e.g. `wrapping-key-v2`).

### 7.2 Add the new key to configuration

```yaml
encryption:
  key_manager:
    dual_read_window: 2  # Now covers v0 (legacy) and v1 (old KMS)
    cosmian:
      keys:
        - id: "wrapping-key-v2"   # Active key — MUST be first
          version: 2
        - id: "wrapping-key-v1"   # Previous key — kept for dual-read
          version: 1
```

### 7.3 Use the Admin API rotation workflow

```bash
TOKEN="$(cat /etc/gateway/admin-token)"
ADMIN="http://127.0.0.1:8081"

# Start draining in-flight wraps
curl -s -X POST "$ADMIN/admin/kms/rotate/start" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"grace_period": "30s"}'

# Poll until ready for cutover
while true; do
  STATUS=$(curl -s "$ADMIN/admin/kms/rotate/status" \
    -H "Authorization: Bearer $TOKEN")
  PHASE=$(echo "$STATUS" | jq -r .phase)
  echo "Phase: $PHASE, in-flight: $(echo "$STATUS" | jq .in_flight_wraps)"
  [ "$PHASE" = "ready_for_cutover" ] && break
  sleep 2
done

# Commit the rotation
curl -s -X POST "$ADMIN/admin/kms/rotate/commit" \
  -H "Authorization: Bearer $TOKEN"
```

See [KEY_ROTATION_RUNBOOK.md](KEY_ROTATION_RUNBOOK.md) for the full runbook,
including grace-period monitoring, re-encryption of cold objects, and
Object Lock interaction.

---

## 8. Rollback

If a problem is detected after migration, roll back by reverting to the
previous configuration and restarting:

```bash
# 1. Restore previous config
cp config.yaml.backup-$(date +%Y%m%d) config.yaml

# 2. Restart
kubectl rollout restart deployment/s3-encryption-gateway
# or
systemctl restart s3-encryption-gateway

# 3. Verify health
curl http://gateway:8080/readyz
```

**Important**: Objects written while KMS mode was active have
`x-amz-meta-encryption-key-version: 1` in their metadata and reference a
KMS-wrapped DEK. After rollback to single-password mode the gateway will
attempt `PBKDF2(password, salt)` for these objects and fail to decrypt
them (the wrapped DEK metadata will be ignored). Ensure you do **not**
delete KMS keys or discard the master key before confirming all recently
written objects are either:

- Not yet critical (can be re-uploaded), or
- Re-downloaded and verified in the rolled-back state.

---

## 9. Troubleshooting

### Gateway fails to start: "KMS health check failed"

**Cause**: The configured KMS endpoint is not reachable at startup.

```bash
# Verify connectivity
curl -f "$COSMIAN_KMS_ENDPOINT" && echo "OK" || echo "UNREACHABLE"

# For TLS issues, test with curl explicitly
curl --cacert /etc/gateway/kms-ca.pem \
  --cert /etc/gateway/client.crt \
  --key /etc/gateway/client.key \
  https://kms-host:9998/kmip/2_1
```

**Resolution**:
1. Ensure the KMS service is running and healthy.
2. Check firewall rules between gateway and KMS.
3. For Kubernetes, verify `NetworkPolicy` and `Service` DNS resolution.

---

### Old objects fail to decrypt: "ErrUnwrapFailed"

**Cause**: `dual_read_window` is not set high enough, or `encryption.password`
was removed from config before all old objects were migrated.

**Resolution**:
1. Set `dual_read_window` to at least `1` (covers one previous key version).
2. Keep `encryption.password` in config while any single-password objects
   still exist on disk.
3. Check `x-amz-meta-encryption-key-version` on the failing object:
   ```bash
   aws s3api head-object --bucket BUCKET --key KEY \
     --endpoint-url http://gateway:8080 \
     --query 'Metadata."x-amz-meta-encryption-key-version"'
   ```
   - Absent or `"0"` → single-password object; requires `encryption.password` in config.
   - `"1"` → KMS v1 object; requires the KMS key `version: 1` in `keys:` list.

---

### New objects show key version `0` or no version after migration

**Cause**: `key_manager.enabled` is `false` or the wrong config file is being
loaded by the running process.

```bash
# Confirm the process is using the updated config
ps aux | grep s3-encryption-gateway
# Look for --config flag or CONFIG_FILE env var

# Confirm KMS is active
curl -s http://gateway:8080/metrics | grep 'kms_active_key_version'
# Should return a non-zero value
```

---

### "master key lost on restart" (memory provider only)

**Cause**: `master_key_source: ""` was used (auto-generate) and the
process restarted.

**Resolution**: Provide an explicit key source:

```yaml
memory:
  master_key_source: "env:MEMORY_MASTER_KEY"
```

Auto-generation should only be used in ephemeral test environments.

---

### High `kms_rotated_reads_total` rate

If the metric climbs rapidly this is expected immediately after migration
as old objects are accessed for the first time. The rate should trend to
zero as users access objects (which continue to read with the old key but
are not re-encrypted unless explicitly copied). To accelerate, re-encrypt
cold objects by copying them through the gateway:

```bash
while read key; do
  aws s3 cp "s3://bucket/$key" "s3://bucket/$key" \
    --endpoint-url http://gateway:8080 \
    --metadata-directive COPY
done < cold-object-list.txt
```

---

## 10. Reference

### Configuration fields

| Field | Default | Description |
|---|---|---|
| `encryption.password` | `""` | Legacy single-password; keep during migration for dual-read of old objects |
| `encryption.key_manager.enabled` | `false` | `true` activates KMS mode |
| `encryption.key_manager.provider` | `cosmian` | `cosmian`, `memory`, or `hsm` (-tags hsm) |
| `encryption.key_manager.dual_read_window` | `1` | Number of previous key versions to try on decrypt |
| `encryption.key_manager.memory.master_key_source` | `""` | Secret reference: `env:VAR`, `file:PATH`, or `""` (auto, dev only) |
| `encryption.key_manager.cosmian.endpoint` | `""` | KMIP endpoint URL or `host:port` for binary |
| `encryption.key_manager.cosmian.timeout` | — | Required when KMS is enabled |
| `encryption.key_manager.cosmian.keys` | `[]` | Ordered list of wrapping keys; first entry is active |

### Key metadata written to objects

| Header | Value | Notes |
|---|---|---|
| `x-amz-meta-encryption-wrapped-key` | Base64 DEK ciphertext | Written only in KMS mode |
| `x-amz-meta-encryption-kms-id` | Wrapping key ID / ARN | Written only in KMS mode |
| `x-amz-meta-encryption-kms-provider` | e.g. `cosmian-kmip` | Written only in KMS mode |
| `x-amz-meta-encryption-key-version` | Integer version | `0` / absent = legacy single-password |

### Related documentation

| Document | Contents |
|---|---|
| [KMS_COMPATIBILITY.md](KMS_COMPATIBILITY.md) | Adapters, interface invariants, custom adapter guide |
| [KEY_ROTATION_RUNBOOK.md](KEY_ROTATION_RUNBOOK.md) | Operational runbook for subsequent key rotations |
| [ADMIN_API.md](ADMIN_API.md) | Admin API reference (rotate/start, rotate/commit, etc.) |
| [FIPS.md](FIPS.md) | FIPS 140-3 build profile; use with `-tags fips` |
| [ENCRYPTION_DESIGN.md](ENCRYPTION_DESIGN.md) | Low-level chunked-AEAD design, metadata layout |
| [docs/adr/0004-hsm-adapter-contract.md](adr/0004-hsm-adapter-contract.md) | HSM adapter contract |
| [docs/adr/0007-key-rotation-drain-commit.md](adr/0007-key-rotation-drain-commit.md) | Drain-commit rotation design |
