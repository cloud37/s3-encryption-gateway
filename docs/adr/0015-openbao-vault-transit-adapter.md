# ADR 0015: OpenBao / HashiCorp Vault Transit KeyManager Adapter

**Status:** Accepted (v1.0)

**Context:**

The gateway's `KeyManager` interface wraps/unwraps per-object DEKs against an
external KMS. OpenBao (the MPL-2.0 fork of HashiCorp Vault) and Vault both ship
the **Transit** secrets engine — encryption-as-a-service that encrypts/decrypts
a caller-supplied payload without ever exposing the key (KEK). The gateway
already generates its own random DEK in the engine, so it needs only a
wrap/unwrap service, which Transit provides directly. This is the most widely
deployed secrets backend in cloud-native environments and a natural complement
to the existing Cosmian KMIP and self-contained adapters. Implementation is
tracked by V1.0-KMS-3.

**Decision:**

Implement one adapter, `internal/crypto/keymanager_openbao.go`
(`openBaoTransitManager`), using the official OpenBao Go client
`github.com/openbao/openbao/api/v2` (API-compatible with both OpenBao and Vault
servers). It is registered under four provider names — `openbao`,
`openbao-transit`, `vault`, `vault-transit` — all mapping to the same factory.

- `WrapKey` → `transit/encrypt/<key>` (DEK is base64; **not** `transit/datakey`,
  which would make the server the DEK generator and break the
  input-plaintext→envelope contract).
- `UnwrapKey` → `transit/decrypt/<key>`. **No client-side candidate loop / no
  `dual_read_window`**: Transit self-routes a decrypt to the version embedded in
  the self-describing `vault:vN:<base64>` ciphertext, which is stored verbatim
  in `KeyEnvelope.Ciphertext`.
- `KeyID` is **synthesised** as `vault-transit:<mount>/<key>` (Transit returns no
  canonical key UID) — required because the engine rejects a streaming decrypt
  when the persisted KMS key ID is empty.
- `ActiveKeyVersion` is a live `GET transit/keys/<key>.latest_version`; the
  gateway **follows** the server-owned version rather than holding it in memory.
- `RotatableKeyManager`: `PrepareRotation` returns a deterministic
  `{current, current+1}`; `PromoteActiveVersion` issues the server-side
  `transit/keys/<key>/rotate` RPC and confirms `latest_version` advanced. This
  drives the existing `rotation_state` drain-and-cutover machine and
  `/admin/kms/rotate/*` API. **Note:** the KMS decorators (retry, circuit
  breaker, DEK cache) previously exposed only the `KeyManager` method set, so
  the admin API's `km.(RotatableKeyManager)` assertion failed whenever a
  decorator was enabled — for every rotatable adapter, not just this one. This
  work adds conditional rotatable forwarding to the three decorators
  (`keymanager_decorator_rotation.go`) so rotation survives the decorator stack.
- `HealthCheck` performs two non-crypto reads: `auth/token/lookup-self` (token
  validity — `sys/health` returns 200 with a dead token, so it cannot detect
  expiry; resolves GAP-KMS3-3) **and** `transit/keys/<key>` (the configured key
  exists and is readable; `404 → ErrKeyNotFound`), so a wrong `key_name` or a
  missing key-read policy cannot report a "healthy but broken" data plane.
- Auth methods: `token`, `approle`, `kubernetes`. For login-based methods the
  adapter owns an **in-process** token-renewal goroutine (OpenBao
  `LifetimeWatcher`) that re-logs-in on `DoneCh` (max_ttl / revoke / restart) —
  Transit issues no dynamic leases, so only the auth token needs renewal.
  Construction is fail-closed: a failed initial login returns no manager.

**Alternatives considered:**

- *`transit/datakey`* — rejected: the gateway already generates the DEK; datakey
  diverges from every other adapter's wrap contract.
- *Vault KV v2 to store the wrapped DEK* — rejected: persists the DEK in the
  server's storage, defeating envelope encryption.
- *`github.com/hashicorp/vault/api`* — rejected in favour of the OpenBao client:
  the project targets OpenBao (open source); the OpenBao client is drop-in
  compatible against a Vault server too.
- *Vault Agent / OpenBao Proxy sidecar for auth+renewal* — rejected for v1: the
  project's adapters own their client lifecycle in-process (cf. Cosmian); the
  sidecar remains a valid operator alternative.
- *Mapping `min_decryption_version` to `dual_read_window`* — rejected as a
  category error: the former is a server-side hard-deny retire floor, the latter
  a client-side fallback loop with no Transit analogue.

**Consequences:**

- New dependency `github.com/openbao/openbao/api/v2` (MPL-2.0). MPL is
  file-level copyleft and permits static linking; the gateway's MIT code is
  unaffected as long as OpenBao source files are not modified in place.
- Forgetting token renewal is the highest-risk failure mode: at token
  expiry every encrypt/decrypt returns HTTP 403 (total data-plane outage), and
  the retry/circuit-breaker decorators do **not** mask it (all KMS sentinels,
  including `ErrProviderUnavailable`, are treated as permanent — no retry; 5
  consecutive trip the breaker open for 30s). The renewal goroutine is the only
  line of defence; it is therefore part of the adapter, not deferred.
- Retiring old key versions requires a deliberate operator runbook: rewrap
  stored envelopes (`transit/rewrap`) **before** raising `min_decryption_version`,
  else older DEKs become permanently undecryptable.
- Out-of-band rotation (manual `rotate` or `auto_rotate_period`) bypasses the
  gateway's drain-and-cutover; operators should disable `auto_rotate_period` on
  the gateway key and rotate via the admin API.
- FIPS: the adapter does no local AES (wrapping is server-side) and builds under
  `-tags=fips`; no upstream FIPS-140-validated OpenBao build exists yet
  ([openbao#1409](https://github.com/openbao/openbao/issues/1409)), so the
  backend's FIPS posture depends on the OpenBao deployment.

**Security properties:** tokens and AppRole secret IDs are never logged or
placed into a `KeyEnvelope`; the KEK is non-exportable in the server; TLS 1.2+
with a restricted cipher suite list; the on-encrypt token policy should omit
`create` so a missing/typo'd key is a hard error rather than a silently-created
empty KEK.

**References:**

- `docs/plans/V1.0-KMS-3-plan.md` — implementation plan and verification gaps.
- `internal/crypto/keymanager_cosmian.go` — sibling server-side-wrap adapter.
- OpenBao Transit API: <https://openbao.org/docs/secrets/transit/>
