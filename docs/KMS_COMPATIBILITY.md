# Encryption Modes, Key Management, and Rotation

**Baseline: v0.12.3.** This guide owns key-provider selection, key sources,
provider authentication, rotation, and retention. Encryption formats/FIPS live in
[encryption design](ENCRYPTION_DESIGN.md); upgrades and re-encryption live in
[migration](MIGRATION.md); admin HTTP contracts live in the [runbook](RUNBOOK.md#admin-api-reference).

## Contents

- [Choosing an encryption mode](#choosing-an-encryption-mode)
- [Supported adapters](#supported-adapters)
- [Self-contained AES and RSA](#self-contained-adapter)
- [Cosmian KMIP](#cosmian-kmip-adapter)
- [OpenBao / Vault Transit](#openbao--vault-transit-adapter)
- [Memory adapter](#memory-adapter)
- [Production hardening](#production-hardening)
- [Dual-read window and key rotation](#dual-read-window-and-key-rotation)
- [Custom adapter contract](#key-manager-interface)
- [Troubleshooting](#troubleshooting)

## Choosing an Encryption Mode

| Mode | Key source | When appropriate | Important constraint |
|---|---|---|---|
| Password PBKDF2-SHA256 | Gateway password, per-object parameters | Simpler deployment or legacy reads | Default 600,000 iterations; derivation adds request cost, retain configured decrypt limits |
| Password Argon2id | Gateway password and memory/time parameters | Password-only non-FIPS deployments | Not available in FIPS build; budget memory/concurrency and KDF limits |
| Local envelope (recommended low-latency path) | AES-256 or RSA KEK from protected env/file | No external KMS, controlled key lifecycle | KEK loss makes wrapped DEKs unreadable; preserve versions |
| External envelope | Cosmian or OpenBao/Vault Transit | External key custody/auth/rotation | Availability, TLS, policy, and retained provider versions are dependencies |

Password configuration examples:

```yaml
encryption:
  password: "<secret supplied securely>"
  kdf:
    algorithm: pbkdf2-sha256
    pbkdf2:
      iterations: 600000
```

For Argon2id use `algorithm: argon2id` with `time: 2`, `memory: 19456` KiB,
`threads: 1` under `encryption.kdf.argon2id`, subject to validation/decrypt limits.
Stored parameters select legacy readers; changing the new-write setting does not
rewrite old objects. Do not equate different KDF settings with identical security
without deployment-specific assessment. Measured historical throughput and
methodology are in [performance](PERFORMANCE.md#encryption-mode-benchmarks).

Envelope mode generates a per-object DEK and wraps it with a KEK. The production
server still requires an encryption password/key-file source; retain the original
password for legacy object/MPU reads. Password fallback is distinct from a KMS
dual-read window and cannot decrypt arbitrary objects wrapped by an unavailable KMS.

## Supported Adapters

| Configured provider | Released status / key lifecycle |
|---|---|
| `self_contained` | Local AES-GCM/RSA-OAEP envelope; versioned AES keys and explicit rotation |
| `cosmian` / `kmip` | Cosmian KMIP; JSON/HTTPS conformance and binary TLS path with narrower evidence |
| `openbao`, `openbao-transit`, `vault`, `vault-transit` | Transit API; token/AppRole/Kubernetes authentication and renewal |
| `memory` | In-process AES key-wrap; explicit persistent secret required outside disposable tests |
| `hsm` | Nonfunctional PKCS#11 skeleton/stub; not supported deployment or a promised release |
| AWS KMS / Azure Key Vault / GCP KMS | Not implemented provider adapters; no date commitment |

Selecting an unknown provider fails; a conceptual historical example is not a
registered adapter. See [`BuildKeyManager`](../internal/api/crypto_factory.go).

## Self-Contained Adapter

### AES KEK

Generate and securely retain a base64 32-byte KEK:

```bash
openssl rand -base64 32
```

```yaml
encryption:
  password: "<existing password for legacy reads>"
  key_manager:
    enabled: true
    provider: self_contained
    self_contained:
      type: aes
      aes:
        active_version: 1
        keys:
          - version: 1
            key_source: "env:S3EG_AES_KEK"
```

AES key sources: `env:VAR`, `base64:DATA`, or `file:PATH`, decoded as base64 key
material. Use protected secret files/env, not committed literal keys. Multiple
versions support retained reads and explicit active-version promotion. AES-GCM
wrapping uses random nonces; observe key-volume/retirement policy and do not
interpret a convenient nominal wrap count as an unlimited safe key lifetime.

### RSA KEK

```yaml
encryption:
  password: "<existing password>"
  key_manager:
    enabled: true
    provider: self_contained
    self_contained:
      type: rsa
      rsa:
        private_key_source: "file:/run/secrets/kek_rsa.pem"
        key_version: 1
```

RSA private-key sources accept `file:`, `env:` PEM, or literal PEM; minimum key
size 2048 bits, wrapping RSA-OAEP/SHA256. Key replacement is not an automatic
multi-version RSA rollout—preserve ability to read old envelopes and migrate
before removing the old private key. Go big.Int zeroization is best-effort;
the unsupported HSM stub is not a remedy.

## Cosmian KMIP Adapter

Use an existing TLS-protected Cosmian KMS and create a wrapping key through its
authorized management interface. The local test fixture uses a container; its
HTTP ports are not production TLS configuration.

```yaml
encryption:
  password: "<existing password>"
  key_manager:
    enabled: true
    provider: cosmian
    dual_read_window: 2
    cosmian:
      endpoint: "https://kms.example.com/kmip/2_1"
      ca_cert: /etc/gateway/kms-ca.pem
      timeout: 10s
      keys:
        - id: "active-wrapping-key"
          version: 2
        - id: "retained-wrapping-key"
          version: 1
```

- JSON/HTTPS full path or base URL accepted; binary KMIP uses `host:5696` with
  CA/client certificate/client key. JSON has the broader automated evidence;
  binary requires separate deployment verification.
- Plain HTTP carries plaintext DEKs and is rejected unless explicit
  `insecure_allow_plaintext_transport: true` development override is set.
- Normal TLS verifies chain and hostname. The configured `insecure_skip_verify`
  exception requires a CA and skips hostname matching only; do not use it as a
  generic production trust solution.
- The first configured key is active; retained keys and dual-read limits govern
  eligible unwrap behavior. Use explicit versions rather than relying on order-derived ones.

See [Cosmian installation](https://docs.cosmian.com/key_management_system/installation/installation_getting_started/)
for server TLS/auth. The repository's conformance fixtures, not a static old image
version here, define current test pins.

## OpenBao / Vault Transit Adapter

Transit keeps the KEK nonexportable server-side; the gateway submits DEKs for
wrap/unwrap. Aliases select the same adapter. Example setup with authorized `bao`:

```bash
bao secrets enable transit
bao write -f transit/keys/s3gw-dek type=aes256-gcm96
```

```yaml
encryption:
  password: "<existing password>"
  key_manager:
    enabled: true
    provider: openbao
    openbao:
      address: "https://bao.internal:8200"
      transit_path: transit
      key_name: s3gw-dek
      auth:
        method: kubernetes
        role: s3-encryption-gateway
      tls:
        ca_cert: /etc/ssl/bao-ca.pem
```

Auth methods: token (token or `env:`/`file:` token source), AppRole (role ID and
secret-ID/source), Kubernetes (role and projected JWT path). Scope provider policy:

```hcl
path "transit/encrypt/s3gw-dek" { capabilities = ["update"] }
path "transit/decrypt/s3gw-dek" { capabilities = ["update"] }
path "transit/keys/s3gw-dek" { capabilities = ["read"] }
# Required only for gateway-driven rotation:
path "transit/keys/s3gw-dek/rotate" { capabilities = ["update"] }
# Also needed if the role omits the default token policy:
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
```

Do not grant create merely to hide a missing Transit key. Health checks verify
token validity and readable key existence, not just server sys/health.
AppRole/Kubernetes re-authenticate on renewal failure and request 401/403, with
coalescing/backoff; fixed-token lifecycle remains operator-owned. Missing renew
permission can cause recurring re-login despite successful requests. Watch
`gateway_kms_reauth_total` and provider audit without exposing tokens.

Transit self-routes old ciphertext by its `vault:vN:` version. There is no provider
dual-read-window equivalence: preserve old Transit decrypt versions until all
dependent envelopes/objects/manifests/state are migrated. Raising minimum decrypt
version is destructive if dependencies remain. The FIPS-tagged gateway does not
certify the external Transit deployment.

## Memory Adapter

The memory provider uses RFC3394 AES wrap and accepts persistent hex/raw AES key
material from `env:VAR` or `file:PATH` (16/24/32 bytes); **not the base64 decoder
used by self-contained AES**. An empty source generates an ephemeral key which is
lost on restart and must be restricted to disposable tests.

```yaml
encryption:
  password: "<existing password>"
  key_manager:
    enabled: true
    provider: memory
    memory:
      master_key_source: "file:/run/secrets/memory-kek.hex"
```

Generate a persistent 32-byte hex key with `openssl rand -hex 32`, store securely,
and retain it across all replicas/restarts that need existing envelopes. Prefer
versioned self-contained AES for an operator-managed local key lifecycle.

## Production Hardening

Configured decorators apply retry → circuit breaker → optional DEK unwrap cache.
Retry defaults to a bounded 30-second window; breaker/cache default disabled.
Use config/schema for exact fields rather than assuming every provider shares a
health/rotation policy. Cache is sensitive local memory and only caches unwrap
results; it does not grant new writes during provider outage. Key wrapping and
health are separate, and failure statuses depend on the API path.

Retain TLS trust, key backups, provider policy, bounded retries, health metrics,
and tested recovery. Key material/tokens must not appear in logs or persisted
envelopes. Rotation via a shared load-balancer address is unsafe when promotion
state is process-local; operate per replica or use a coordinated fleet deployment.

## Dual-Read Window and Key Rotation

### Pre-rotation checklist

- Inventory active/retained key versions and their dependent objects, MPU manifests,
  Valkey state DEK, metadata key, and backups. Cold/locked objects still matter.
- Back up config and required keys; verify current provider health and old-object reads.
- Choose provider-specific promotion: explicit AES active version, Cosmian key order,
  or Transit server version. Retain old decrypt capability across the fleet.
- Drain/coordinate writers and long-running requests where required; consult the
  [progressive delivery runbook](OPS_DEPLOYMENT.md) and [upgrade constraints](MIGRATION.md).
- Prepare a rollback that can read **both** old and newly written envelopes.

### Rotation procedure

1. Provision the new wrapping key/version without removing old keys.
2. Deploy retained key material/policy to every replica. For AES, keep old
   `active_version` until intended cutover; for Cosmian, reordering keys already
   changes the active writer on restart—do not then assume admin start performs
   the original cutover. Follow one reviewed deployment/promotion strategy.
3. Where the loaded provider implements RotatableKeyManager, call admin
   start/status/commit against each intended replica, or coordinate a fleet
   restart. The [admin reference](RUNBOOK.md#admin-api-reference) defines wire responses.
4. Verify readiness, new object write/read, old object read, and key version with
   read-only `s3eg-cli`/authorized backend inspection. Gateway HEAD intentionally
   hides internal envelope fields; do not use it to prove active key version.
5. Monitor `kms_rotated_reads_total` and crypto/provider errors. Reading an object
   does **not** establish that all cold objects or stored envelopes were rewritten.
6. Re-encrypt verified inventory through the [explicit GET→PUT workflow](MIGRATION.md#standard-re-encryption-get--put)
   if required. A no-op sync or elapsed grace period does not prove migration.
7. Retire old versions only after all required objects, manifests, state, metadata
   and backups can be recovered without them. Record exceptions and earliest
   retirement dates for locked data.

### Rollback and Object Lock

Do not disable/remove a key manager to handle an outage: it cannot turn its old
ciphertext into password-readable objects. Restore connectivity/policy or a
retained compatible provider/config, keeping new keys available too. Explicit
governance bypass is refused at the gateway. Backend lock protects ciphertext
bytes, not the continued availability of decryption keys. Preserve KEKs for the
entire required recovery/retention window; test explicit retention persistence
rather than trusting accepted inline PUT headers.

## Key Manager Interface

The production interface in [`internal/crypto/keymanager.go`](../internal/crypto/keymanager.go)
defines Provider, WrapKey, UnwrapKey, ActiveKeyVersion, HealthCheck, and Close.
Methods are concurrent-safe, honor contexts, return caller-owned DEKs, avoid
logging plaintext, and close idempotently. Metadata is advisory; payload AEAD
ObjectContext binding is the independent location-integrity boundary.

Factories register with `crypto.Register`; `crypto.Open` discovers linked
providers. Typed startup configuration must supply required factory options;
registry presence alone does not invent a YAML schema. Wrap/unwrap envelopes
contain key ID/version/provider/ciphertext, not a string password API. Verify
adapters with the existing conformance suite and race/error/closure tests before
shipping. Do not copy historical GetActiveKey/RotateKey password sketches as the
current interface.

## Troubleshooting

| Symptom | Check / response |
|---|---|
| Provider initialization or readiness fails | Endpoint/TLS/key ID/policy; distinguish unavailable network from rejected credentials |
| Old objects fail after promotion | Retained version/key/password, provider decrypt limits, object metadata; don't strip markers |
| New key unexpected | Loaded config/active AES version or Cosmian order; read-only inspect and new-write round trip |
| High rotated reads | Expected historical-key traffic; not proof of automatic migration or reason to remove keys |
| Memory key lost after restart | Restore original persistent secret; generated key is irrecoverable without backup |
| Transit re-login churn | Default token lookup/renew policy, role TTL, credential source; fixed tokens are operator-owned |
| KMS outage | Restore provider/policy/TLS; optional unwrap cache may serve some reads, no blanket status or write guarantee |

Use the [incident runbook](RUNBOOK.md), [observability](OBSERVABILITY.md), and
[migration recovery](MIGRATION.md). Security recommendations here were checked
against repository code; no external O'Reilly MCP verification was available.
