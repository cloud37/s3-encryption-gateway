# Deployment and Configuration

This guide owns installation, runtime configuration, backend selection, credentials,
and bucket policy. Exact fields/defaults live in [config.yaml.example](../config.yaml.example),
[configuration source](../internal/config/config.go), and the
[Helm reference](../helm/s3-encryption-gateway/README.md). **Baseline: v0.12.3.**

## Contents

- [Quick start deployment](#quick-start-deployment)
- [Configuration sources](#configuration-sources)
- [Backend selection and TLS](#backend-selection-and-tls)
- [Configuring gateway credentials](#configuring-gateway-credentials)
- [Bucket encryption policies](#bucket-encryption-policies)
- [Reverse proxies and load balancers](#reverse-proxies-and-backend-load-balancers)
- [Multipart state and spool prerequisites](#multipart-upload-state-store-valkey)
- [Security and network controls](#security-and-network-controls)
- [Health checks and monitoring](#health-checks-and-monitoring)
- [Troubleshooting](#troubleshooting)

Other topic owners: [S3 compatibility](S3_API_IMPLEMENTATION.md),
[key management/rotation](KMS_COMPATIBILITY.md), [migration](MIGRATION.md),
[operations/admin](RUNBOOK.md), [observability](OBSERVABILITY.md),
[performance/scaling](PERFORMANCE.md), and [progressive delivery](OPS_DEPLOYMENT.md).

## Quick Start Deployment

Choose a protected backend and gateway endpoint, generate persistent keys, and
configure gateway credentials independently of backend IAM. Current encrypted
MPUs require shared Valkey; without it explicitly disable multipart or configure
an appropriate bypass policy rather than relying on silent plaintext fallback.
Do not use production credentials for local tests.

### Docker

```bash
openssl rand -base64 32  # Save as S3EG_AES_KEK in a secrets manager.
```

Provide the necessary env values securely and run the released image:

```bash
docker run --name s3-gateway -p 8080:8080 \
  -e BACKEND_ENDPOINT -e BACKEND_REGION -e BACKEND_ACCESS_KEY -e BACKEND_SECRET_KEY \
  -e ENCRYPTION_PASSWORD -e S3EG_AES_KEK \
  -e KEY_MANAGER_ENABLED=true -e KEY_MANAGER_PROVIDER=self_contained \
  -e SELF_CONTAINED_TYPE=aes \
  -e SELF_CONTAINED_AES_KEYS \
  -e GW_CRED_0_ACCESS_KEY -e GW_CRED_0_SECRET_KEY \
  -e SERVER_DISABLE_MULTIPART_UPLOADS=true \
  cloud37io/s3-encryption-gateway:0.12.3
```

`SELF_CONTAINED_AES_KEYS` is `1=base64:<generated key>`; use documented env mapping,
not arbitrary `${VAR}` interpolation in YAML. `ENCRYPTION_PASSWORD` retains legacy
read/password-envelope compatibility and is still required by production startup.
The example disables MPU explicitly; enable it only after state/key setup below.
Terminate TLS before exposing this endpoint outside a trusted test network.

### Kubernetes / Helm

```bash
kubectl create secret generic s3-encryption-gateway-secrets \
  --from-literal=backend-access-key=YOUR_BACKEND_KEY \
  --from-literal=backend-secret-key=YOUR_BACKEND_SECRET \
  --from-literal=encryption-password=YOUR_EXISTING_OR_NEW_PASSWORD \
  --from-literal=gateway-access-key=YOUR_GATEWAY_KEY \
  --from-literal=gateway-secret-key=YOUR_GATEWAY_SECRET
# Configure keys, backend, TLS, Valkey or explicit MPU disable in reviewed values.
helm upgrade --install s3-encryption-gateway ./helm/s3-encryption-gateway \
  -f values.yaml
```

Use [chart values/schema](../helm/s3-encryption-gateway/) and
[key-manager examples](KMS_COMPATIBILITY.md) to fill actual fields. Keep secrets
out of Git/shell logs. Render with `helm template`, verify mounts and env, then
apply; upgrades before 0.12 require the coordinated migration procedure, not an
unreviewed rolling image change. Raw [k8s manifests](../k8s/) are examples to review
against your current secrets, state, network, and storage setup.

### Verify deployment

Check readiness/liveness, then a **signed** PUT→GET→HEAD→DELETE using gateway
credentials. Verify byte equality, permissions, endpoint/path style, and stateful
MPU if enabled. A 200 health probe alone does not prove writable spools or S3 access.
Use [client recipes](S3_CLI_TOOLS.md), [compatibility](S3_API_IMPLEMENTATION.md),
and [tests](TESTING.md). Do not inspect internal encryption headers through gateway
HEAD; those are intentionally filtered.

## Configuration Sources

Start with `config.yaml.example`. `CONFIG_PATH` chooses the server config file
(default config.yaml); the production server does not implement an arbitrary
`--config`/`--validate` command-line interface. File configuration and documented env overrides
are loaded/validated at startup; the runtime schema and Helm value nesting are not
interchangeable. Helm uses value/valueFrom wrappers and secret mounts. Main-config/
credentials-file changes support validated reload for eligible fields; process
env/Helm changes and key/transport settings may require restart.

`server` sets read/write/header/idle timeouts, header size, trusted proxy CIDRs,
multipart/buffer/spool controls, and HTTPS/HSTS behavior. `cache` is optional
in-process response caching; `rate_limit` is request admission, not bucket access.
Audit/tracing/metrics controls and supported field names are in config/schema and
[observability](OBSERVABILITY.md), not copied speculative env tables here.
Built-in compression is removed; old `COMPRESSION_*` examples are not supported
runtime tuning. See [compression migration](MIGRATION.md#removing-compression-v10).

## Backend Selection and TLS

`backend.type` / BACKEND_TYPE selects s3 (default), gcs, or azure adapters around
configured S3-compatible endpoints. This is not native cloud-API support or full
product certification. Supply endpoint/region/access/secret and outgoing addressing
for the actual provider. Gateway inbound path-style addressing is independent.

```yaml
backend:
  type: s3
  endpoint: https://storage.example.com
  region: us-east-1
  access_key: "<backend access key>"
  secret_key: "<backend secret key>"
  use_path_style: true
  tls:
    ca_file: /etc/gateway/backend-ca.pem
```

### Adapter-specific constraints

| Adapter | Gateway behavior | Boundary |
|---|---|---|
| S3 | Typed SDK plus registered config passthrough | Provider APIs/setup vary; missing gateway option mapping remains missing |
| GCS | Lowercase metadata; UploadPart shim rejects part numbers above 32; fallback Last-Modified on copy | Compatible XML/HMAC endpoint required; native UploadPartCopy/lock delegation differs, test the actual API |
| Azure | PUT metadata key/8 KiB aggregate validation; BlobNotFound mapping; explicit lock APIs return NotImplemented | Compatible endpoint required, no turnkey native Blob SDK contract; metadata budget depends on envelope |

See [S3 provider evidence](S3_API_IMPLEMENTATION.md#backend-and-encryption-mode-coverage).
The GCS default endpoint is storage.googleapis.com; Azure may derive an endpoint
from account_name, but successful construction is not proof that the endpoint
supports the requested S3 operation. Prefer explicit validated endpoint settings.

### Backend TLS trust

HTTPS uses system roots. backend.tls.ca_file / BACKEND_TLS_CA_FILE appends a private
issuing CA and preserves hostname checks; restart after trust changes. Explicit
insecure_skip_verify disables verification for diagnostics only. TLS settings
cannot secure plain HTTP. Configure final endpoint/region; passthrough redirects
are returned rather than followed/replayed to another destination.

## Configuring Gateway Credentials

### Credential Authorization

Gateway auth.credentials entries contain access key, secret source, optional
label, bucket scope, object permission, and independent bucket grants. Omitted
buckets is unrestricted, `[]` denies all, exact names/trailing prefixes restrict,
bare `*` is broad authority. Object `ro` permits reads and `rw` writes; neither
grants bucket lifecycle management. PROXIED_BUCKET further narrows scopes.

```yaml
auth:
  credentials:
    - access_key: tenant-a-client
      secret_key_env: TENANT_A_SECRET
      buckets: ["tenant-a-*"]
      permissions: rw
      bucket_permissions: []
```

create/delete/manage are explicit independent grants. Create also needs global
ALLOW_BUCKET_CREATION=true; delete has no global switch; config PUT/DELETE needs
manage. Source and destination are checked for copy. ListBuckets filters the
effective scope for ro/rw alike; lifecycle grants do not change inventory access.
Backend IAM remains required but is not the gateway authorization boundary.

### Helm credentials

```yaml
config:
  auth:
    credentials:
      - accessKey:
          valueFrom:
            secretKeyRef:
              name: gateway-auth-secrets
              key: access-key
        secretKey:
          valueFrom:
            secretKeyRef:
              name: gateway-auth-secrets
              key: secret-key
        label: tenant-a
```

Use schema-supported permission/scope wrappers for additional fields. Indexed
GW_CRED_N_ACCESS_KEY/SECRET_KEY env values are process-start settings. A Secret
with a full YAML/JSON credential list can be referenced through
config.auth.existingCredentialsSecret.name/key; chart mounts it and sets
AUTH_CREDENTIALS_FILE. It supersedes inline chart credential entries.

### Full Credentials List From a Single Secret

```yaml
config:
  auth:
    existingCredentialsSecret:
      name: gateway-credentials
      key: credentials.yaml
```

The secret's credentials.yaml value is a list of runtime access_key/secret_key/
scope/grant records, not Helm valueFrom structures. Bare-metal/container deployments
can use AUTH_CREDENTIALS_FILE and protected secret_key_env sources. Keep access-key/
secret generation and lifecycle in your secrets system; `openssl rand -hex 16`
and `openssl rand -hex 32` can generate identifiers/secrets without example reuse.

### Presigned URL Lifetime and Clock Skew (GH-345)

Keep clocks synchronized. AUTH_CLOCK_SKEW_TOLERANCE (default 5m) governs header
replay/future skew, not a presigned URL's lifetime. v0.12.3 honors signed expiry;
restore 5m if enlarged only as workaround. Changing live permissions can still
revoke URLs. See [exact auth errors](S3_API_IMPLEMENTATION.md#sigv4-request-time-and-presigned-expiration).

### Legacy SigV2 Migration

Disabled by default. Temporarily set auth.allow_legacy_signature_v2 or
AUTH_ALLOW_LEGACY_SIGNATURE_V2=true only while migrating clients to SigV4 and
draining old URLs. The removed backend.use_client_credentials path is not current
authentication; move clients into gateway credentials instead.

## Bucket Encryption Policies

Policies choose crypto behavior, not access. File globs under policies (or POLICIES
env) and GW_POLICY_N_* indexed rules match bucket globs independently of credential
scope grammar. Encryption/password/provider overrides apply to matching buckets.

```yaml
# config.yaml
policies: [/etc/gateway/policies/*.yaml]
```

```yaml
# policy/tenant.yaml
id: tenant-a
buckets: ["tenant-a-*"]
encryption:
  password: "<protected tenant secret>"
  preferred_algorithm: ChaCha20-Poly1305
encrypt_multipart_uploads: true
```

Explicit application-encrypted bypass:

```yaml
id: restic
buckets: [restic-backups]
disable_encryption: true
```

disable_encryption implies plaintext MPU; require_encryption is mutually exclusive.
Omitted encrypt_multipart_uploads enables it. See PolicyConfig for supported fields,
not a speculative per-policy feature table. Protect policy secrets and follow
[key setup](KMS_COMPATIBILITY.md) for provider overrides.

### Precedence and Merging

File globs are ordered with lexical matches; env policies append in index order
until first absent GW_POLICY_N_ID. **First match wins**, not later env override.
Use GW_POLICY_0_ID/BUCKETS/ENCRYPTION_PASSWORD/ENCRYPTION_ALGORITHM for documented
env mapping. Review ordering with actual bucket names before rollout.

### Atomic Reloads

File/SIGHUP reload validates a complete policy snapshot before replacement. Invalid
sets retain old policies and reject reload before live credentials/gates change.
These are component snapshots, not one global transaction. Env/Helm changes require
restart; key/provider changes need reviewed rotation/deployment. GH-339 prevents
new bypass miswrites but does not repair old ones; use
[controlled recovery](MIGRATION.md#recovering-gh-339-bypass-bucket-miswrites).

## Reverse Proxies and Backend Load Balancers

### Inbound addressing and compatibility

Use https://gateway/bucket/key. DNS alone does not enable bucket.gateway routing.
Preserve signed Host/path/query; do not proxy-decode copy sources. Backend SDK
addressing/credential settings are independent. See [S3 options](S3_API_IMPLEMENTATION.md).

### URL-encoded copy sources (GH-346)

Through v0.12.2, encoded copy sources could fail or select an encoded-looking
sibling. v0.12.3 decodes identity once and re-encodes backend copies. Preserve the
signed header; audit earlier successful escaped-key copies/moves and recover from
backups/versions if wrong bytes were copied/deleted. The fix cannot repair old copies.
See [copy fields](S3_API_IMPLEMENTATION.md#writes-copies-and-multipart-options).

### Frontend header preservation

v0.12.2 GH-338 filtering builds a separate S3-focused backend request and removes
client proxy identity/hop fields before signing. Incoming X-Forwarded-* remains
available to auditing only when trusted-proxy CIDRs permit it. No trusted proxies
by default; do not trust arbitrary headers or strip legitimate signed S3 fields.
Affected <=0.12.1 proxy workaround strips X-Forwarded-For before it reaches the
gateway but loses forwarded client identity; upgrade instead where possible.
The signed zero Content-Length issue remains in v0.12.3 (#356 unreleased fix).

### Backend redirects, KMS TLS, and audit sinks

Passthrough redirects are returned, not followed. Cosmian hostname-skip requires
configured CA chain validation; OpenBao custom-CA exception is also hostname-only.
Backend/Valkey/audit verification bypasses are diagnostic insecure settings, not
substitutes for trusted certs. Invalid audit TLS/file modes reject delivery rather
than weakening it. Audit files default 0600; safe group-readable modes require
explicit reviewed configuration. Keep their parent directories protected.

## Multipart Upload State Store (Valkey)

Encrypted MPU requires shared Valkey and key management. State metadata uses a
random shared DEK stored as mpu:state-key-wrapped, not the old password-derived
new-write scheme. Keep state-envelope/keys/backups; default plaintext fallback off.
VALKEY_ADDR/USERNAME/PASSWORD_ENV/DB, TLS CA/cert/key fields, TTL (7 days), pool,
reservation lease, state_v2_writer and legacy-routing settings live in config/schema.
Use explicit development plaintext override only in controlled tests.

Blue/green/canary must share external state across releases; see
[progressive delivery](OPS_DEPLOYMENT.md). Follow coordinated state writer upgrade,
not mixed old mutable/new claim writers. See [state operations](RUNBOOK.md#valkey-state-at-rest-encryption).

### Temporary spool storage

Signed body verification needs a writable private spool directory, even while
the root filesystem stays read-only. Current charts supply /tmp emptyDir by
default; keep overriding mounts writable. server.spool_directory selects another
volume; configure disk/ephemeral limits above the aggregate process budget.
Defaults: 5 GiB/request, 10 GiB/process; part cap 64 MiB. Concurrent copy/part
buffers need memory too. See [capacity](PERFORMANCE.md#valkey-and-spool-capacity).

## Docker Container Design

Use maintained [Dockerfile](../Dockerfile) / [FIPS Dockerfile](../Dockerfile.fips),
not a duplicated sample build. They own version/runtime/user/health-check behavior.
FIPS is static CGO-disabled and has its own [build/module constraints](ENCRYPTION_DESIGN.md#fips-build-profile).

## Kubernetes Deployment

Chart and [k8s examples](../k8s/) supply resources to adapt, not one universal
secure deployment. Configure appropriate service/ingress/controller TLS, secrets,
state, metrics listener, storage, pod security, and disruption budgets. Helm
value nesting differs from runtime YAML. Review rendered objects against your
cluster policies and dependencies before applying.

## Security and Network Controls

Run nonroot, deny unnecessary privilege/capabilities, and retain read-only root with
bounded writable spools. Use current Pod Security admission/securityContext, not
removed PodSecurityPolicy API. Restrict ingress, admin/metrics access, and egress
to actual backend/KMS/Valkey/DNS; a generic 443-only rule breaks other required
dependencies. Trusted proxies and rate limits are not substitutes for S3 scopes.
TLS may terminate at ingress or gateway; HSTS forcing is explicit when appropriate.

Key backups, ciphertext metadata/manifests, and state recovery must survive pod
loss. GitOps tracks **non-secret** configuration; a generic stateless label does
not remove these recovery dependencies. See [runbook](RUNBOOK.md) and [migration](MIGRATION.md).

## Health Checks and Monitoring

Use /live for liveness, /ready or /readyz for dependency readiness, and supported
exact MinIO/RustFS health aliases. Metrics bind dedicated port when configured,
otherwise admin fallback or legacy data-plane fallback; protect whichever is used.
Choose ServiceMonitor/NetworkPolicy targeting the actual listener. Canonical
metric/audit/tracing/dashboard/profiling recipes are in [observability](OBSERVABILITY.md).

## Resource Management and Scaling

Measure peak part/copy/spool/KDF/provider load before selecting CPU/memory/disk,
HPA, termination grace, and topology/disruption settings. Use
[performance/scaling](PERFORMANCE.md) and maintained HPA/KEDA examples. Special
writer-version migration can override ordinary rolling strategy; never copy an
old maxSurge example as proof the upgrade is safe.

## Troubleshooting

| Symptom | Check |
|---|---|
| Startup/CrashLoop | Actual config/env, persistent key source, Valkey TLS/unwrap/writer capability, logs |
| Ready but S3 returns 500 | Private writable spool, signed body mode, typed backend/crypto failures |
| Signature failure via proxy | Preserved Host/path/signed headers, encoded copy source, release fixes and zero-length exception |
| 403 bucket mutation | Independent create/delete/manage grants and global creation gate, backend IAM |
| Missing metrics | Actual metrics/admin/data listener, auth, ServiceMonitor port, policy |
| Slow sync / large part failure | Listing size/ETag limits, fallback costs, part cap, disk budget, backend/KMS |
| Old objects fail after key change | Retained keys/password/metadata/manifests and reader limits, not encryption downgrade |

Use [runbook playbooks](RUNBOOK.md#alert-playbooks) for incident response. Guidance
was checked against repository sources; no external O'Reilly MCP verification was
available. Do not infer full production certification from a sample manifest.
