# S3 Encryption Gateway

![GitHub Release](https://img.shields.io/github/v/release/cloud37/s3-encryption-gateway)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/s3-encryption-gateway)](https://artifacthub.io/packages/helm/s3-encryption-gateway/s3-encryption-gateway)

[![Conformance](https://github.com/cloud37/s3-encryption-gateway/actions/workflows/conformance.yml/badge.svg)](https://github.com/cloud37/s3-encryption-gateway/actions/workflows/conformance.yml)
[![Security Scanning](https://github.com/cloud37/s3-encryption-gateway/actions/workflows/security.yml/badge.svg)](https://github.com/cloud37/s3-encryption-gateway/actions/workflows/security.yml)
[![Mutation Testing](https://github.com/cloud37/s3-encryption-gateway/actions/workflows/mutation.yml/badge.svg)](https://github.com/cloud37/s3-encryption-gateway/actions/workflows/mutation.yml)

## The Problem

Countless applications write data to S3-compatible storage — database backups, log archives, ML training data, CI/CD artifacts — but most of them don't encrypt that data client-side.

**The real threat isn't a rogue storage provider.** Most people reasonably trust their cloud provider and their server-side encryption (SSE). The much more common and practical risk is a **misconfigured IAM policy, overly broad bucket policy, accidentally public ACL, or compromised access key**. Any mistake at the IAM or policy layer directly exposes your plaintext data — because without client-side encryption, whoever can reach the bucket can read everything in it.

By adding a cryptographic layer at the gateway, a configuration mistake in your cloud account no longer immediately translates into a data breach. An attacker who gains unauthorized S3 access — through a policy misconfiguration, a leaked key, or any other account-level compromise — only retrieves ciphertext. They would also need to compromise the gateway — which in a typical deployment never leaves your private network.

This is defense-in-depth for object storage: your cloud account's access controls remain your first line of defense; client-side encryption is the second — and it holds even when the first fails.

Beyond misconfiguration risk, there are valid reasons to want an independent crypto layer: regulated environments that require customer-managed keys, multi-tenant shared infrastructure, or simply a preference for not relying solely on provider controls.

Modifying every application to implement client-side encryption isn't realistic. Different tools use different S3 SDKs, different languages, and different upload strategies. Some are closed-source. Some are operators you don't control.

**The result:** sensitive data sits on object storage, protected only by IAM policies and SSE keys the provider controls — one misconfiguration away from full exposure.

## The Solution

The S3 Encryption Gateway is a transparent HTTP proxy that sits between your applications and any S3-compatible storage backend. It encrypts data on the way in and decrypts it on the way out — without changing a single line of application code.

```
┌─────────────┐          ┌──────────────────────┐          ┌─────────────────┐
│  S3 Client  │──S3 API──▶  Encryption Gateway │──S3 API──▶  S3 Backend    │
│  (any app) ◀──────────│  encrypt/decrypt    ◀──────────│  (AWS, MinIO,   │
└─────────────┘  plain   └──────────────────────┘  cipher  │   Hetzner, ...) │
                 text                               text   └─────────────────┘
```

**Transparent**: Point your S3 endpoint URL at the gateway — that's it. No application changes required.

## Who Needs This?

| Category | Examples | What they store | Encrypts itself? |
|---|---|---|---|
| **Databases** | CNPG, Zalando Postgres, MySQL Operator | Backups, WAL archives | ❌ |
| **Backup tools** | Velero, Restic, Longhorn, Kasten | Cluster/app backups, snapshots | ⚠️ Varies |
| **Log & metrics** | Loki, Thanos, Mimir, Tempo, Cortex | Logs, metrics, traces | ❌ |
| **File sharing** | Nextcloud, Seafile, ownCloud | User files, documents, photos | ⚠️ Partial/complex |
| **Data platforms** | Spark, Trino, Iceberg, Delta Lake | Analytics data, query results | ❌ |
| **ML platforms** | MLflow, Kubeflow, DVC, JupyterHub | Models, training data, experiments | ❌ |
| **CI/CD & Git** | GitLab, Gitea, Forgejo, Jenkins | Artifacts, LFS, packages | ⚠️ Varies |
| **Chat & social** | Mattermost, Mastodon | Uploads, media, attachments | ❌ |
| **IaC state** | Terraform, OpenTofu, Pulumi | State files (often containing secrets!) | ⚠️ Often forgotten |
| **Container registries** | Harbor, GitLab Registry | Image layers, blobs | ❌ |
| **Custom apps** | Any S3 client | Whatever you store | ⚠️ Your responsibility |

If your compliance team, CISO, or data protection officer asks *"Are our S3 objects encrypted client-side?"* — and the honest answer is *"not all of them"* — this gateway fixes that in one place, for all applications at once.

## Born from Production

We built this gateway because we needed it ourselves. We run cloud platforms for customers and use CloudNativePG as our PostgreSQL operator on Kubernetes. CNPG handles automated backups, WAL archiving, and point-in-time recovery — but it writes those database dumps to S3 unencrypted.

Full database backups in plaintext on object storage wasn't acceptable. But modifying every application that writes to S3 wasn't practical either — the problem wasn't limited to CNPG.

So we built a transparent proxy that solves the problem once, for every application, without touching a single line of application code. The S3 Encryption Gateway is running in production, protecting data across multiple environments and storage backends.

---

## Features

### Object Encryption

All objects are encrypted before being sent to the backend and decrypted on retrieval. Encryption is transparent — any S3 client works without modification.

**Recommended: Envelope encryption** with a locally-held AES-256 or RSA key, or an external KMS (Cosmian KMIP). A random per-object Data Encryption Key (DEK) is wrapped with the Key Encryption Key (KEK) at encrypt time and unwrapped at decrypt time — no key derivation on the hot path. Envelope encryption is **50–76× faster** than PBKDF2 600k for single-object uploads and over **70× faster** for range reads. See the [Encryption Modes Guide](docs/ENCRYPTION_MODES.md) for full benchmark tables and a mode comparison.

**Password-derived (legacy, simpler deployment):** Derives per-object keys from a gateway password via PBKDF2 or argon2id. Requires no key infrastructure — just a single `ENCRYPTION_PASSWORD` environment variable — but runs key derivation on every request. See the [Encryption Modes Guide](docs/ENCRYPTION_MODES.md) for throughput numbers and a [migration guide](docs/ENCRYPTION_MODES.md#migration-between-modes) if you are switching from password-derived to envelope encryption.

- **AES-256-GCM** (default) or **ChaCha20-Poly1305**: Authenticated encryption with per-object keys
- **Chunked streaming**: Large files are encrypted in chunks with per-chunk IVs, enabling efficient range requests
- **Range requests**: Fetches only the encrypted chunks covering the requested plaintext byte range
- **FIPS-compliant profile**: Build with `-tags=fips` to restrict to AES-256-GCM + HKDF-SHA256 (FIPS-140 approved). Under envelope encryption, DEK wrapping uses AES-256-GCM (AES KEK) or RSA-OAEP/SHA-256 (RSA KEK) — both FIPS-approved. The `argon2id` KDF is rejected at startup under `-tags=fips`.

### Per-Bucket Policies

Policies let you override encryption behaviour on a per-bucket basis using glob-pattern matches. Use them for multi-tenant setups (different keys per tenant) or when specific buckets must bypass encryption.

**Via YAML files** (mount any number of files; load them with `policies:` in config):

```yaml
# policy/acme.yaml
id: acme
buckets: ["acme-*"]
encryption:
  password: "acme-secret"
  preferred_algorithm: ChaCha20-Poly1305
```

```yaml
# policy/legacy.yaml
id: legacy
buckets: ["restic-backups"]
disable_encryption: true
```

**Via environment variables** — no policy files needed:

```bash
# Policy 0: encrypt acme-* with a per-tenant password
GW_POLICY_0_ID="acme"
GW_POLICY_0_BUCKETS="acme-*"
GW_POLICY_0_ENCRYPTION_PASSWORD="acme-secret"
GW_POLICY_0_ENCRYPTION_ALGORITHM="ChaCha20-Poly1305"

# Policy 1: bypass encryption for restic backups
GW_POLICY_1_ID="legacy"
GW_POLICY_1_BUCKETS="restic-backups"
GW_POLICY_1_DISABLE_ENCRYPTION="true"
```

All `GW_POLICY_N_*` fields are hot-reloaded on SIGHUP. Available variables map 1:1 to `PolicyConfig` fields; see `config.yaml.example` for the complete list.

### Encrypted Multipart Uploads

Large objects uploaded via the S3 multipart API are encrypted end-to-end. Each upload gets its own key; each chunk gets a deterministic, collision-free IV derived via HKDF-SHA256.

- **Per-upload DEK**: Fresh 32-byte AES-256-GCM key generated at `CreateMultipartUpload`
- **DEK wrapping**: Via the configured `KeyManager` (Cosmian KMIP, HSM, or built-in password-based `PasswordKeyManager`)
- **Per-chunk IV**: `HKDF-Expand(SHA-256, dek, salt=sha256(uploadId), info=ivPrefix‖BE32(part)‖BE32(chunk))` — deterministic and collision-free
- **AEAD manifest**: Encrypted companion object at `<key>.mpu-manifest`; main object metadata carries a pointer
- **Ranged GET across part boundaries**: Precise byte-range fetch via `EncRangeForPlaintextRange`; only the chunks covering the requested plaintext range are fetched and decrypted
- **Tamper detection**: AES-GCM tag failure on any chunk returns 500 and emits an `mpu.tamper_detected` audit event; first-chunk tamper returns 500 before any body is written
- **State store**: Valkey (or any Redis-protocol-compatible store); 7-day TTL; one hash per active upload
- **FIPS**: AES-256-GCM + HKDF-SHA256 — both FIPS-140 approved (works under `-tags=fips`)
- **Opt-in per bucket** via policy; requires Valkey for in-flight state

See [ADR 0009](docs/adr/0009-encrypted-multipart-uploads.md) for the full design rationale.

#### Enabling encrypted multipart uploads

Encrypted multipart uploads require a **Valkey** (or Redis-protocol-compatible) instance for in-flight state storage. The same Valkey instance and connection pool also back the [ListObjects plaintext size cache](#listobjects-plaintext-size-translation) — a single Valkey deployment serves both features. Enable per bucket via policy and configure the state store in the gateway config:

```yaml
# config.yaml
multipart_state:
  valkey:
    addr: "valkey.internal:6379"
    password_env: "VALKEY_PASSWORD"  # env var name (not the literal password)
    tls:
      enabled: true
      ca_file: "/etc/gateway/valkey-ca.pem"
      cert_file: "/etc/gateway/valkey-client.pem"
      key_file:  "/etc/gateway/valkey-client-key.pem"
    ttl_seconds: 604800  # 7 days — refreshed on every UploadPart
    pool_size: 16
```

```yaml
# policy/my-bucket.yaml
id: my-encrypted-bucket
buckets:
  - "my-important-bucket"
encrypt_multipart_uploads: true
```

All Valkey settings are also available as environment variables (`VALKEY_ADDR`, `VALKEY_TLS_ENABLED`, `VALKEY_TLS_CA_FILE`, `VALKEY_TTL_SECONDS`, etc.).

`encrypt_multipart_uploads` defaults to `true` as of v0.8. Buckets without a matching policy, or policies that omit the field, will use the encrypted multipart upload path automatically. Set `encrypt_multipart_uploads: false` explicitly in the policy to opt a specific bucket out.

#### Fail-closed guarantees

The gateway refuses to silently degrade security under any of these conditions:

| Situation | Behaviour |
|---|---|
| `encrypt_multipart_uploads: true` on any policy + Valkey address not configured at startup | Process exits with a `Fatal` log — **no silent fallback to plaintext** |
| Valkey reachable at startup but transient failure mid-upload | 503 ServiceUnavailable on the affected request; client retries are safe because the IV schedule is deterministic |
| `UploadPart` succeeds on backend but `AppendPart` to Valkey fails | 503 ServiceUnavailable; client retries overwrite the same part idempotently |
| Policy is flipped mid-upload | In-flight uploads use the `PolicySnapshot` captured at `CreateMultipartUpload`; the flip only affects new uploads |
| No `KeyManager` and an encrypted-MPU request arrives | 503 ServiceUnavailable with reason `"KeyManager not configured"` |
| Plaintext Valkey + production config (`insecure_allow_plaintext: false`) | Startup refuses; emits a `gateway_mpu_valkey_insecure=1` gauge if overridden |
| State decryption AEAD failure (`allow_legacy_plaintext_state: false`, default) | Request returns error; no silent plaintext fallback (V1.0-SEC-30) |

The dedicated escape hatch for deployments that cannot run Valkey at all:

```yaml
server:
  disable_multipart_uploads: true  # env: SERVER_DISABLE_MULTIPART_UPLOADS
```

This enforces a 5 GiB single-PUT ceiling but guarantees all data is encrypted and requires no state infrastructure.

#### UploadPart memory cap (`server.max_part_buffer`)

Each `UploadPart` request is buffered into a seekable in-memory buffer so the AWS SDK V2 SigV4 signer can re-read the body for payload hashing and retries. The default cap is **64 MiB** — parts larger than this are refused with HTTP 413 before any backend write occurs:

```yaml
server:
  max_part_buffer: 67108864  # 64 MiB (default); env: SERVER_MAX_PART_BUFFER
```

Raise this value if your workload uploads parts larger than 64 MiB. The cap applies to both encrypted and plaintext multipart upload paths. `Server.MaxLegacyCopySourceBytes` (default 256 MiB, set via `server.max_legacy_copy_source_bytes` / `SERVER_MAX_LEGACY_COPY_SOURCE_BYTES`) separately bounds the allocation incurred when copying legacy (non-chunked) encrypted objects with `CopyObject` or `UploadPartCopy`.

#### Deploying Valkey with the Helm chart

The Helm chart bundles an optional Valkey subchart which is off by default:

```yaml
# values.yaml
valkey:
  enabled: true
  architecture: standalone  # or "cluster" for HA
  auth:
    enabled: false           # enable + mount a secret for production
```

When `valkey.enabled=true`, the deployment template auto-wires `VALKEY_ADDR` to the subchart's `<release>-valkey:6379` service. You can also point at an external Valkey cluster via the `config.multipartState.valkey` values stanza — the two paths are mutually exclusive.

> **Cost note for Wasabi / Glacier / S3 IA users:** The Valkey state store exists precisely to avoid writing state objects to S3 — which on backends with minimum-storage-duration policies (Wasabi: 90 days on Pay-Go; Glacier / Standard-IA / One Zone-IA: 30–180 days) would incur significant phantom-storage charges. Your *data* objects still land on whichever backend you choose; only the ephemeral per-upload state lives in Valkey.

### ListObjects Plaintext Size Translation

S3 sync clients (rclone, restic, Duplicati, s5cmd) rely on the invariant `ListObjects[i].Size == HeadObject(key).Content-Length`. Without translation, the  gateway returns ciphertext sizes in listings — every encrypted object looks "modified" on every run, causing infinite re-transfers and error spam.

As of v0.11.0 (V1.0-S3-3), `handleListObjects` resolves plaintext sizes via a **write-through Valkey size cache** — a per-bucket hash (`plainsize:<bucket>`) populated on `PutObject`, `CompleteMultipartUpload`, and `CopyObject`, and evicted on `DeleteObject` / `DeleteObjects`. A whole listing page is resolved with a single `HMGET` round-trip — **zero per-object `HeadObject` calls** when the cache is warm.

- **Shared Valkey instance**: reuses the same `redis.UniversalClient` and connection pool as the multipart-upload state store — no second Valkey deployment or connection pool. See [Encrypted Multipart Uploads](#encrypted-multipart-uploads)for Valkey configuration.
- **Strongly recommended, not a hard dependency**: if Valkey is unavailable, the gateway degrades gracefully to ciphertext sizes (the pre-v1.0 behaviour) — no`5xx`, no crash. ListObjects keeps working; only size accuracy for sync clients is lost until Valkey recovers. (Multipart uploads, by contrast, are **fail-closed** — see the [fail-closed table](#fail-closed-guarantees))
- **Opt-in fallback HEAD batch**: for cache misses (e.g. objects uploaded before this feature), `list_size_translate.fallback_head_enabled: true` issues bounded concurrent `HeadObject` calls to populate the cache. **Disabled by default** to avoid per-API-call billing amplification on Wasabi / R2 / B2.
- **No TTL on size entries**: index entries are permanent until evicted by delete/copy. Legacy objects are not auto-warmed; enable the fallback HEAD batch temporarily or wait for normal write traffic to populate the cache.

```yaml
# config.yaml
list_size_translate:
  enabled: true                   # default true when Valkey is configured
  fallback_head_enabled: false    # opt-in HEAD batch for cache misses (billing!)
  fallback_head_concurrency: 10   # 1–100 concurrent HEADs per listing page
  fallback_head_timeout: 5s       # 100ms–60s per-page deadline
```

All fields are also available as environment variables (`LIST_SIZE_TRANSLATE_ENABLED`, `LIST_SIZE_TRANSLATE_FALLBACK_HEAD_ENABLED`, etc.). If `enabled: true` but no Valkey is configured, the gateway logs a warning and silently disables the lookup.

Three Prometheus metrics track cache health (see [Monitoring](#monitoring--observability)): `list_size_cache_hits_total`, `list_size_cache_misses_total`, and `list_size_fallback_head_total` (label `result`: `hit`/`timeout`/`error`).

See [`docs/plans/V1.0-S3-3-plan.md`](docs/plans/V1.0-S3-3-plan.md) for the full design, and [`docs/RUNBOOK.md`](docs/RUNBOOK.md) for operational guidance.

### Envelope Encryption (Recommended)

Envelope encryption removes key derivation from the per-request hot path: a random per-object Data Encryption Key (DEK) is wrapped with a Key Encryption Key (KEK). The KEK is loaded once at startup. This is **50–76× faster than PBKDF2 600k** and is the recommended path for all production deployments. See [`docs/ENCRYPTION_MODES.md`](docs/ENCRYPTION_MODES.md) for performance benchmarks.

> **Migrating from password-only?** Set `encryption.password` to your existing password and enable `key_manager`. The gateway reads the password for objects encrypted before the switch and uses the KEK for all new objects — no data migration required. To re-encrypt existing objects, use the **GET-through-gateway → PUT-through-gateway** pattern with any standard S3 client. See [`docs/MIGRATION.md`](docs/MIGRATION.md) for details.

Three variants are supported:

#### Self-contained AES KEK (simplest, no external dependencies)

Generate a 32-byte base64 KEK:

```bash
openssl rand -base64 32
# example output: pmW3QqWUWCvjYpcsW1ypkUMPuzdF2w5LfR3ligYtK/o=
```

**Option A — YAML config** (uses `key_source` to read the key from an environment variable):

```yaml
encryption:
  password: "fallback-password-123456"     # for legacy objects encrypted with password
  key_manager:
    enabled: true
    provider: self_contained
    self_contained:
      type: aes
      aes:
        keys:
          - version: 1
            key_source: "env:S3EG_AES_KEK"   # name of the env var holding the base64 key
```

```bash
export S3EG_AES_KEK="pmW3QqWUWCvjYpcsW1ypkUMPuzdF2w5LfR3ligYtK/o="
```

**Option B — environment variables only** (no config file; the `SELF_CONTAINED_AES_KEYS` format is `"version=base64:value"`):

```bash
export KEY_MANAGER_ENABLED=true
export KEY_MANAGER_PROVIDER=self_contained
export SELF_CONTAINED_TYPE=aes
export SELF_CONTAINED_AES_KEYS="1=base64:pmW3QqWUWCvjYpcsW1ypkUMPuzdF2w5LfR3ligYtK/o="
```

#### Self-contained RSA KEK (uses existing PKI)

```yaml
encryption:
  key_manager:
    enabled: true
    provider: self_contained
    self_contained:
      type: rsa
      rsa:
        private_key_source: "file:/run/secrets/kek_rsa.pem"
        key_version: 1
```

#### Cosmian KMIP KMS (external KMS with key rotation)

The gateway supports envelope encryption via **Cosmian KMIP** with key rotation and dual-read windows.

- **Envelope encryption**: A unique DEK is generated per object, then wrapped with the KMS master key
- **Key rotation**: The `dual_read_window` setting allows reading objects encrypted with previous key versions during rotation
- **Fallback support**: Objects encrypted with the password (before KMS was enabled) can still be decrypted
- **Health checks**: KMS health is automatically checked via the `/ready` endpoint

##### Quick start

1. Start Cosmian KMS:

```bash
docker run -d --rm --name cosmian-kms \
  -p 5696:5696 -p 9998:9998 --entrypoint cosmian_kms \
  ghcr.io/cosmian/kms:5.22.0
```

2. Create a wrapping key via the Cosmian KMS UI (http://localhost:9998/ui) and note the key ID.

3. Configure the gateway:

```yaml
encryption:
  password: "fallback-password-123456"
  key_manager:
    enabled: true
    provider: "cosmian"
    dual_read_window: 1
    cosmian:
      endpoint: "http://localhost:9998/kmip/2_1"
      timeout: "10s"
      keys:
        - id: "your-key-id-from-cosmian"
          version: 1
```

Or via environment variables:

```bash
export KEY_MANAGER_ENABLED=true
export KEY_MANAGER_PROVIDER=cosmian
export KEY_MANAGER_DUAL_READ_WINDOW=1
export COSMIAN_KMS_ENDPOINT=http://localhost:9998/kmip/2_1
export COSMIAN_KMS_TIMEOUT=10s
export COSMIAN_KMS_KEYS="your-key-id:1"
```

##### Protocol options

**JSON/HTTP (recommended, tested in CI)**:
- Full URL: `http://localhost:9998/kmip/2_1` or `https://kms.example.com/kmip/2_1`
- Base URL also works: `http://localhost:9998` (path `/kmip/2_1` is auto-appended)
- No client certificates required for HTTP; `ca_cert` recommended for HTTPS

**Binary KMIP (advanced, requires TLS)**:
- Endpoint format: `localhost:5696` or `kms.example.com:5696`
- Requires `ca_cert`, `client_cert`, and `client_key`
- Not fully tested in CI — use with caution

See [`docs/KMS_COMPATIBILITY.md`](docs/KMS_COMPATIBILITY.md) for detailed documentation. AWS KMS and Vault Transit adapters are on the roadmap.

### Compression

Built-in pre-encryption compression was removed in v1.0. For users who need
compression, we recommend external composition:

```
client → s4 (https://github.com/abyo-software/s4) → s3-encryption-gateway → storage
```

### Rate Limiting

Token-bucket rate limiting protects against abuse.

```yaml
rate_limit:
  enabled: true
  limit: 100      # requests per window
  window: "60s"
```

### Caching

Optional in-memory response cache reduces backend traffic for frequently read objects.

```yaml
cache:
  enabled: false
  max_size: 104857600     # 100 MB
  max_items: 1000
  default_ttl: "5m"
```

### Audit Logging

Structured audit events for every S3 operation, with configurable sinks.

```yaml
audit:
  enabled: false
  max_events: 10000
  sink:
    type: "stdout"      # stdout, file, or http
    file_path: ""
    endpoint: ""
    batch_size: 100
    flush_interval: "5s"
```

Multipart-specific audit events: `mpu.create`, `mpu.part`, `mpu.complete`, `mpu.abort`, `mpu.tamper_detected`, `mpu.valkey_unavailable`.

### Monitoring & Observability

#### Health endpoints

- `GET /health` — general health status
- `GET /ready` (alias `/readyz`) — readiness probe with per-dependency status:

```json
{
  "status": "ready",
  "checks": {
    "kms":    "ok",
    "valkey": "ok"
  }
}
```

Returns HTTP 503 with `status: "not_ready"` if any configured dependency fails its health check.

- `GET /live` — liveness probe
- `GET /metrics` — Prometheus metrics

Metrics endpoint routing (in priority order):
1. **Dedicated metrics port** (`metrics.addr: ":9090"` / `METRICS_ADDR`) — recommended for Kubernetes; unauthenticated plain HTTP, restrict via `NetworkPolicy`
2. **Admin port fallback** — when `metrics.addr` is empty and admin is enabled, `/metrics` is served on the admin port (requires bearer auth)
3. **S3 port fallback** — when both `metrics.addr` is empty and admin is disabled, `/metrics` is served on the S3 data-plane port (legacy, no auth)

#### Prometheus metrics

- **HTTP**: request counts, durations, bytes transferred
- **S3 operations**: operation counts, durations, error rates
- **Encryption**: encryption/decryption counts, durations, throughput
- **System**: active connections, goroutines, memory usage

Key metric names: `http_requests_total`, `encryption_operations_total`, `active_connections`, `goroutines_total`, `memory_alloc_bytes`.

Seven metrics track the multipart-encryption hot path:

| Metric | Type | Labels | Emitted on |
|---|---|---|---|
| `gateway_mpu_encrypted_total` | counter | `result` | Every `CompleteMultipartUpload` on encrypted buckets |
| `gateway_mpu_parts_total` | counter | `result` | Every `UploadPart` on encrypted buckets |
| `gateway_mpu_state_store_ops_total` | counter | `op`, `result` | Every Valkey op |
| `gateway_mpu_state_store_latency_seconds` | histogram | `op` | Every Valkey op |
| `gateway_mpu_valkey_up` | gauge | — | Ready-check HealthCheck |
| `gateway_mpu_valkey_insecure` | gauge | — | Startup, if TLS is disabled |
| `gateway_mpu_manifest_bytes` | histogram | — | Every `CompleteMultipartUpload` |

Three metrics track the ListObjects plaintext-size cache (V1.0-S3-3):

| Metric | Type | Labels | Emitted on |
|---|---|---|---|
| `list_size_cache_hits_total` | counter | `bucket` | ListObjects key resolved from the Valkey size cache |
| `list_size_cache_misses_total` | counter | `bucket` | ListObjects key absent from the cache |
| `list_size_fallback_head_total` | counter | `bucket`, `result` (`hit`/`timeout`/`error`) | Each `HeadObject` issued by the opt-in fallback HEAD batch |

Track `hits / (hits + misses)` to watch the cache warm up; a rising
`list_size_fallback_head_total` signals billing exposure on per-API-call backends.

### TLS

The gateway can terminate TLS directly.

```yaml
tls:
  enabled: true
  cert_file: /path/to/cert.pem
  key_file: /path/to/key.pem
```

All responses also include security headers: `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Content-Security-Policy`, and others.

### Admin API

Bearer-authenticated admin endpoints on a separate port:

| Endpoint | Purpose |
|---|---|
| `POST /admin/mpu/abort/{uploadId}` | Force-abort an in-flight upload and delete its Valkey state |
| `GET /admin/mpu/list` | List active uploads (bucket, key, creation time) |

---

## Quick Start

### Prerequisites

- Docker (recommended), or
- Go 1.25+ for local builds

### Docker — Envelope encryption (Recommended)

Generate an AES-256 KEK once and keep it secret — this is the key that protects all your encrypted objects:

```bash
openssl rand -base64 32
# example output: pmW3QqWUWCvjYpcsW1ypkUMPuzdF2w5LfR3ligYtK/o=
```

```bash
docker run -p 8080:8080 \
  -e BACKEND_ENDPOINT="https://s3.amazonaws.com" \
  -e BACKEND_REGION="us-east-1" \
  -e BACKEND_ACCESS_KEY="your-key" \
  -e BACKEND_SECRET_KEY="your-secret" \
  -e ENCRYPTION_PASSWORD="your-existing-password" \
  -e KEY_MANAGER_ENABLED=true \
  -e KEY_MANAGER_PROVIDER=self_contained \
  -e SELF_CONTAINED_TYPE=aes \
  -e SELF_CONTAINED_AES_KEYS="1=base64:pmW3QqWUWCvjYpcsW1ypkUMPuzdF2w5LfR3ligYtK/o=" \
  -e GW_CRED_0_ACCESS_KEY="gateway-access-key" \
  -e GW_CRED_0_SECRET_KEY="gateway-secret-key" \
  cloud37io/s3-encryption-gateway:0.10.2
```

> **Replace the example KEK.** The value shown in `SELF_CONTAINED_AES_KEYS` is a documentation placeholder — generate your own with `openssl rand -base64 32` and keep it in a secrets manager. Anyone with this key can decrypt your objects.

> **`ENCRYPTION_PASSWORD`** is the fallback for objects encrypted before you enabled `KEY_MANAGER`. If you have no existing objects, set it to any strong random value. If you are migrating from password-only mode, set it to your existing encryption password — existing objects will continue to decrypt transparently.

This runs **envelope encryption** — per-object DEKs wrapped with a local AES-256 KEK. No key derivation on the hot path. See [Envelope Encryption](#envelope-encryption-recommended) above and [benchmark results](docs/ENCRYPTION_MODES.md).

### Docker — Password-only (simpler deployment, slower)

```bash
docker run -p 8080:8080 \
  -e BACKEND_ENDPOINT="https://s3.amazonaws.com" \
  -e BACKEND_REGION="us-east-1" \
  -e BACKEND_ACCESS_KEY="your-key" \
  -e BACKEND_SECRET_KEY="your-secret" \
  -e ENCRYPTION_PASSWORD="your-password" \
  -e GW_CRED_0_ACCESS_KEY="gateway-access-key" \
  -e GW_CRED_0_SECRET_KEY="gateway-secret-key" \
  cloud37io/s3-encryption-gateway:0.10.2
```

Runs PBKDF2-SHA256 600k on every request. No key infrastructure needed — just a single password — but throughput is **50× lower** than envelope encryption.

> **Authentication is required.** As of v0.8, every request must include valid AWS Signature V4 or V2 credentials matching an entry in `auth.credentials`. Unauthenticated requests will receive `AccessDenied`.

Point any S3 client at the gateway instead of directly at S3:

```bash
# Before: direct to S3 (unencrypted)
aws s3 cp backup.sql s3://my-bucket/ --endpoint-url https://s3.amazonaws.com

# After: through the gateway (encrypted)
aws s3 cp backup.sql s3://my-bucket/ --endpoint-url http://localhost:8080
```

### Kubernetes (Helm)

**Envelope encryption (recommended):**

```bash
# Generate a KEK — replace the placeholder below with this output
openssl rand -base64 32
# example output: pmW3QqWUWCvjYpcsW1ypkUMPuzdF2w5LfR3ligYtK/o=

kubectl create secret generic s3-encryption-gateway-secrets \
  --from-literal=backend-access-key=YOUR_KEY \
  --from-literal=backend-secret-key=YOUR_SECRET \
  --from-literal=encryption-password=YOUR_EXISTING_PASSWORD \
  --from-literal=gateway-access-key=YOUR_GATEWAY_ACCESS_KEY \
  --from-literal=gateway-secret-key=YOUR_GATEWAY_SECRET_KEY \
  --from-literal=master-key=pmW3QqWUWCvjYpcsW1ypkUMPuzdF2w5LfR3ligYtK/o=
```

```yaml
# values.yaml
config:
  encryption:
    keyManager:
      enabled:
        value: "true"
      provider:
        value: self_contained
      selfContained:
        type:
          value: aes
        aes:
          activeVersion:
            value: "1"
          keys:
            - version: 1
              secretKeyRef:
                name: s3-encryption-gateway-secrets
                key: master-key
```

**Password-only (simpler, slower):**

```bash
kubectl create secret generic s3-encryption-gateway-secrets \
  --from-literal=backend-access-key=YOUR_KEY \
  --from-literal=backend-secret-key=YOUR_SECRET \
  --from-literal=encryption-password=YOUR_PASSWORD \
  --from-literal=gateway-access-key=YOUR_GATEWAY_ACCESS_KEY \
  --from-literal=gateway-secret-key=YOUR_GATEWAY_SECRET_KEY
```

```bash
helm install s3-encryption-gateway ./helm/s3-encryption-gateway
```

See the [Helm chart documentation](helm/s3-encryption-gateway/README.md) for detailed deployment options.

### Docker — Local testing with RustFS

[RustFS](https://rustfs.com) is a lightweight, S3-compatible object store ideal for local development. It is actively maintained (unlike MinIO, which is archived for self-hosted use):

```bash
docker network create s3gw-net

# Start RustFS
docker run -d --name rustfs --network s3gw-net \
  -p 9000:9000 -p 9001:9001 \
  -e RUSTFS_ACCESS_KEY=minioadmin \
  -e RUSTFS_SECRET_KEY=minioadmin \
  rustfs/rustfs:latest

# Start the gateway pointing at RustFS
docker run -p 8080:8080 --network s3gw-net \
  -e BACKEND_ENDPOINT="http://rustfs:9000" \
  -e BACKEND_REGION="us-east-1" \
  -e BACKEND_ACCESS_KEY="minioadmin" \
  -e BACKEND_SECRET_KEY="minioadmin" \
  -e BACKEND_USE_PATH_STYLE="true" \
  -e ENCRYPTION_PASSWORD="dev-password" \
  -e KEY_MANAGER_ENABLED=true \
  -e KEY_MANAGER_PROVIDER=self_contained \
  -e SELF_CONTAINED_TYPE=aes \
  -e SELF_CONTAINED_AES_KEYS="1=base64:pmW3QqWUWCvjYpcsW1ypkUMPuzdF2w5LfR3ligYtK/o=" \
  -e GW_CRED_0_ACCESS_KEY="gw-access-key" \
  -e GW_CRED_0_SECRET_KEY="gw-secret-key" \
  cloud37io/s3-encryption-gateway:0.10.2
```

### Docker Compose

For local development and testing with a bundled MinIO backend:

```bash
cp docker/docker-compose.example.yml docker-compose.yml
cp docker/docker-compose.env.example .env
nano .env  # Edit with your configuration
docker-compose up -d
```

Access MinIO Console at http://localhost:9001. Gateway API at http://localhost:8080.

### Building from Source

```bash
make build
# or
go build -o bin/s3-encryption-gateway ./cmd/server
./bin/s3-encryption-gateway
```

---

## Configuration

Create a `config.yaml` file (see `config.yaml.example` for reference):

```yaml
listen_addr: ":8080"
log_level: "info"

auth:
  credentials:
    - access_key: "YOUR_GATEWAY_ACCESS_KEY"
      secret_key: "YOUR_GATEWAY_SECRET_KEY"
      # proxied_bucket: "optional-bucket-filter"

backend:
  endpoint: "https://s3.amazonaws.com"
  region: "us-east-1"
  access_key: "YOUR_ACCESS_KEY"
  secret_key: "YOUR_SECRET_KEY"
  provider: "aws"
  use_path_style: false  # set true for some S3-compatible providers

encryption:
  password: "fallback-for-legacy-objects"    # only needed when migrating from password-only
  preferred_algorithm: "AES256-GCM"          # or "ChaCha20-Poly1305"
  supported_algorithms:
    - "AES256-GCM"
    - "ChaCha20-Poly1305"

  # --- Envelope encryption (Recommended) ---
  # Remove key_manager entirely to use password-only PBKDF2 derivation instead.
  key_manager:
    enabled: true
    provider: self_contained                  # or "cosmian"
    self_contained:
      type: aes
      aes:
        keys:
          - version: 1
            key_source: "env:S3EG_AES_KEK"    # name of the env var holding the base64 key

  # --- Password-only KDF (legacy, slower) ---
  # Only active when key_manager.enabled is false or key_manager is absent.
  # kdf:
  #   algorithm: "pbkdf2-sha256"  # or "argon2id"
  #   argon2id:
  #     time: 2
  #     memory: 19456
  #     threads: 1

# multipart_state:
#   valkey:
#     addr: "valkey.internal:6379"
#     # State encryption uses a random DEK wrapped by the configured
#     # KeyManager (envelope pattern). Requires key_manager to be
#     # enabled. (V1.0-SEC-30)
#     tls:
#       enabled: true
#     # allow_legacy_plaintext_state: false  # true only during one-time
#     #                                      # migration from plaintext (V1.0-SEC-30)

# list_size_translate: ListObjects plaintext-size cache (V1.0-S3-3). Reuses the
#   Valkey instance above; strongly recommended so rclone/restic/s5cmd see correct
#   sizes. Degrades to ciphertext sizes if Valkey is absent — no hard dependency.
# list_size_translate:
#   enabled: true                   # default true when Valkey is configured
#   fallback_head_enabled: false    # opt-in HEAD batch for cache misses (billing!)
#   fallback_head_concurrency: 10
#   fallback_head_timeout: 5s

# NOTE: built-in compression was removed in v1.0 (V1.0-MAINT-2).
# Use external composition: client → s4 → s3-encryption-gateway → storage

rate_limit:
  enabled: false
  limit: 100
  window: "60s"

cache:
  enabled: false
  max_size: 104857600     # 100MB
  max_items: 1000
  default_ttl: "5m"

audit:
  enabled: false
  max_events: 10000
  sink:
    type: "stdout"      # stdout, file, or http
    file_path: ""
    endpoint: ""
    batch_size: 100
    flush_interval: "5s"
```

Environment variables are also supported for every setting:

```bash
export LISTEN_ADDR=":8080"
export BACKEND_ENDPOINT="https://s3.amazonaws.com"
export BACKEND_REGION="us-east-1"
export BACKEND_ACCESS_KEY="your-access-key"
export BACKEND_SECRET_KEY="your-secret-key"
export BACKEND_USE_PATH_STYLE=false
export ENCRYPTION_PASSWORD="fallback-for-legacy-objects"
export ENCRYPTION_PREFERRED_ALGORITHM="AES256-GCM"
export ENCRYPTION_SUPPORTED_ALGORITHMS="AES256-GCM,ChaCha20-Poly1305"

# --- Envelope encryption (Recommended) ---
export KEY_MANAGER_ENABLED=true
export KEY_MANAGER_PROVIDER=self_contained   # or "cosmian"
export SELF_CONTAINED_TYPE=aes
export SELF_CONTAINED_AES_KEYS="1=base64:pmW3QqWUWCvjYpcsW1ypkUMPuzdF2w5LfR3ligYtK/o="

# --- Password-only KDF (legacy, omit if using envelope encryption) ---
# export ENCRYPTION_KDF_ALGORITHM="pbkdf2-sha256"  # or "argon2id"
# export ENCRYPTION_KDF_ARGON2ID_TIME="2"
# export ENCRYPTION_KDF_ARGON2ID_MEMORY="19456"
# export ENCRYPTION_KDF_ARGON2ID_THREADS="1"
# export VALKEY_ENCRYPTION_PASSWORD_ENV="VALKEY_ENCRYPTION_PASSWORD"
# export VALKEY_ENCRYPT_STATE="true"
export COMPRESSION_ENABLED=false
export RATE_LIMIT_ENABLED=false
export CACHE_ENABLED=false
export AUDIT_ENABLED=false
export TLS_ENABLED=false
```

---

## Use Cases

### Database Backup Encryption

CloudNativePG, Zalando Postgres Operator, and similar database operators write backups directly to S3. Point the backup endpoint at the gateway:

```yaml
# CloudNativePG Cluster example
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
spec:
  backup:
    barmanObjectStore:
      endpointURL: "http://s3-encryption-gateway:8080"
      destinationPath: "s3://database-backups/"
      s3Credentials:
        accessKeyId:
          name: s3-creds
          key: ACCESS_KEY
        secretAccessKey:
          name: s3-creds
          key: SECRET_KEY
```

### Kubernetes Backup Encryption

Velero and similar backup tools can route through the gateway by configuring the S3 endpoint:

```yaml
# Velero BackupStorageLocation example
apiVersion: velero.io/v1
kind: BackupStorageLocation
spec:
  provider: aws
  objectStorage:
    bucket: velero-backups
  config:
    s3Url: "http://s3-encryption-gateway:8080"
    region: us-east-1
```

### Log Data Protection

Log aggregators like Loki store potentially PII-containing log data on S3. Route through the gateway to encrypt at rest:

```yaml
# Loki S3 storage config example
storage_config:
  aws:
    s3: s3://access-key:secret-key@s3-encryption-gateway:8080/loki-logs
    s3forcepathstyle: true
```

### Compliance & Data Sovereignty

The gateway helps satisfy encryption requirements across multiple compliance frameworks:

- **ISO 27001** (A.10.1.1) — Cryptographic controls for data protection
- **BSI C5 / IT-Grundschutz** — Client-side encryption with customer-managed keys
- **GDPR Art. 32** — Technical measures for data protection (encryption at rest)
- **PCI DSS Req. 3** — Protect stored cardholder data

---

## Architecture

```mermaid
flowchart LR
  C["S3 Client<br/>(awscli, SDKs)"] --> |S3 API| G[Encryption Gateway]
  subgraph G["Encryption Gateway"]
    D["Middleware<br/>(logging, recovery, security, rate limit)"]
    E["Encryption Engine<br/>AES-256-GCM default<br/>ChaCha20-Poly1305"]
    K["Key Manager<br/>(AES KEK / RSA KEK / Cosmian KMIP)"]
    CMP["Compression<br/>(optional)"]
    D --> E
    K --> |wrap / unwrap DEK| E
    CMP -.-> |pre/post| E
  end
  G --> |S3 API| B[("S3 Backend<br/>AWS, MinIO, Wasabi, Hetzner")]
  G -.-> |MPU state + ListObjects size cache| V[("Valkey<br/>(Redis-protocol)")]
```

### Data Flow (PUT/GET)

```mermaid
sequenceDiagram
  participant Client
  participant Gateway
  participant S3
  Client->>Gateway: PUT /bucket/key plaintext
  Gateway->>Gateway: generate per-object DEK, wrap with KEK
  Gateway->>Gateway: encrypt AES-GCM or ChaCha20-Poly1305
  Gateway->>S3: PUT /bucket/key ciphertext + metadata
  Note over Gateway,S3: metadata stores wrapped DEK, iv, alg, original size
  Client->>Gateway: GET /bucket/key
  alt Range request
    Gateway->>S3: GET optimized encrypted byte range chunked
  else Full object
    Gateway->>S3: GET object
  end
  Gateway->>Gateway: decrypt stream
  Gateway-->>Client: plaintext
```

---

## Compatible Backends

The gateway works with any S3-compatible storage service. Tested and compatible backends:

| Backend | Status | Notes |
|---|---|---|
| AWS S3 | Tested | Full compatibility |
| MinIO | Tested | Primary development backend |
| Hetzner Object Storage | Tested | Production use |
| Wasabi | Tested | Full compatibility |
| Ceph RGW | Compatible | S3-compatible mode |
| Cloudflare R2 | Compatible | S3-compatible API |
| DigitalOcean Spaces | Compatible | S3-compatible API |
| Backblaze B2 | Compatible | S3-compatible API |

Using a backend not listed here? [Open an issue](https://github.com/cloud37/s3-encryption-gateway/issues) to let us know about your experience.

---

## Security Considerations

- **Key Encryption Key (KEK)**: Store securely using a secrets manager (Kubernetes Secrets, HashiCorp Vault, etc.). For self-contained AES KEK, generate with `openssl rand -base64 32` and inject via environment variable or mounted secret file. Never commit KEKs to version control.
- **Encryption password** (fallback / legacy only): Used only for pre-existing objects when migrating to envelope encryption. If running password-only mode, treat as the primary secret.
- **Backend credentials**: Use IAM roles, service accounts, or secure credential storage
- **Network security**: Deploy behind TLS termination or enable built-in TLS
- **Access control**: Restrict gateway access using network policies, firewalls, or API gateways
- **Rate limiting**: Enable in production to prevent abuse

---

## Roadmap

### v1.0

- **AWS KMS adapter** — native envelope encryption with AWS-managed keys
- **HashiCorp Vault Transit** — key management via Vault's Transit secrets engine

### Shipped in previous versions

See [`CHANGELOG.md`](CHANGELOG.md) for the complete changelog.

### Future

- Azure Key Vault and GCP Cloud KMS adapters
- S3 Encryption Gateway Kubernetes Operator
- Multi-arch images with SBOM and SLSA provenance

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the complete roadmap.

---

## Performance

Per-provider performance baselines and regression gates live in
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md). The nightly
`performance-baseline` workflow re-runs 19 micro-benchmarks plus per-provider
soak tests (MinIO, Garage, RustFS, SeaweedFS) and fails the job on
`> 15 %` throughput regressions or p99 latency growth.

## Test Coverage

The project enforces a **≥ 75% statement coverage gate** on every PR and push to
`make coverage-gate`. Nightly mutation testing (Gremlins) runs on the
critical non-crypto packages. See [`docs/COVERAGE.md`](docs/COVERAGE.md)
for the exclusion policy, regeneration guide, and mutation testing scope.

---

## Contributing

We welcome contributions! Please see [`docs/DEVELOPMENT_GUIDE.md`](docs/DEVELOPMENT_GUIDE.md) for development setup and guidelines.

### Areas Where We'd Love Help

- **Additional KMS adapters** — AWS KMS, Vault Transit, Azure Key Vault, GCP Cloud KMS
- **Backend testing** — testing with more S3-compatible storage providers
- **Interop matrix for encrypted multipart uploads** — verify AWS CLI, boto3, `aws-sdk-go-v2`, `minio-go` all round-trip correctly at 1 MiB / 8 MiB / 100 MiB / 500 MiB payload sizes against real backends
- **Zero-copy streaming encrypt/decrypt** — currently `UploadPart` buffers one part at a time via `io.ReadAll` (V0.6-PERF-1 follow-up)
- **Documentation** — guides, tutorials, and integration examples
- **Performance benchmarks** — throughput and latency measurements across providers

### Getting Started

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linter (`make test && make lint`)
5. Submit a pull request

---

## License

MIT License — see [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/cloud37/s3-encryption-gateway/issues)
- **Documentation**: [`docs/`](docs/) directory
