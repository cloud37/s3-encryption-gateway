# GH-285 — Add Backend TLS Trust Configuration — Implementation Plan

Status: Complete
Owner: Security / Config / Backend
Priority: P1
Labels: `area:security`, `area:config`, `area:backend`

> Scope clarified relative to the imported tracker entry at
> `docs/issues/GH-285.md:1-57`. The maintainer expanded the request to include a
> preferred custom-CA path as well as the requested diagnostic
> `insecure_skip_verify` escape hatch. This plan depends on GH-284's endpoint
> scheme contract.

---

## 1. Context & Current State

`BackendConfig` has endpoint, credentials, provider, `UseSSL`, path-style, type,
and retry settings, but no backend TLS trust block
(`internal/config/config.go:114-133`). Configuration defaults backend transport
to TLS (`internal/config/config.go:1031-1041`), yet validation currently checks
backend credentials/type only (`internal/config/config.go:2078-2106`) and cannot
validate a custom trust source or warn about disabled verification.

The AWS SDK backend client loads default AWS configuration without a custom HTTP
client unless tests inject `WithHTTPTransport` (`internal/s3/client.go:178-207,269-300`). Therefore production uses system trust roots only. The proxy client
constructs its own `http.Transport` with TLS 1.2 minimum, restricted TLS 1.2
cipher suites, and timeouts (`internal/s3/proxy_client.go:47-70`), but likewise
has neither custom roots nor an insecure setting. Implementing only one path
would produce different TLS behavior depending on request mode.

The repository already models nested TLS settings for other clients. For
example, `SinkTLSConfig` contains `ca_file` and `insecure_skip_verify`
(`internal/config/config.go:678-684`), and `ValkeyTLSConfig` exposes the same
shape plus client certificates and minimum version
(`internal/config/config.go:983-991`). The backend requirement is narrower:
server trust only, with no client certificate/mTLS request.

The Helm chart currently renders `BACKEND_USE_SSL` and path-style controls
(`helm/s3-encryption-gateway/templates/deployment.yaml:101-110`); its values and
schema contain no TLS block (`helm/s3-encryption-gateway/values.yaml:211-259`,
`helm/s3-encryption-gateway/values.schema.json:905-919`). Documentation says only
“Use SSL” (`helm/s3-encryption-gateway/README.md:111-122`). The desired secure
path is to append a private issuing CA while retaining hostname verification;
skip-verify is explicit, false by default, and prominently warned as unsafe.

## 2. Design Goals & Non-Goals

### Goals

1. **Private-CA support** — trust a PEM CA file in addition to system roots for
   HTTPS backend connections.
2. **Explicit diagnostic escape hatch** — support
   `backend.tls.insecure_skip_verify` /
   `BACKEND_TLS_INSECURE_SKIP_VERIFY`, default false.
3. **Fail-closed trust loading** — reject unreadable, empty, or malformed CA
   files before serving traffic.
4. **Transport parity** — SDK and proxy backend requests use the same TLS
   configuration builder and security baseline.
5. **Identity verification by default** — custom CA mode retains hostname and
   chain verification; no custom `VerifyPeerCertificate` bypass.
6. **Operational visibility** — emit a clear startup warning when verification
   is disabled, without logging certificate material or credentials.
7. **Complete delivery surface** — YAML, env, example config, Helm values,
   schema, rendering, backend docs, and release notes agree.

### Non-Goals

1. **Backend mTLS/client certificates** — not requested; tracked separately if
   a provider requires client authentication.
2. **Per-provider TLS policies** — one backend connection policy applies to the
   selected backend.
3. **Replacing system roots** — `ca_file` augments the system pool rather than
   removing public roots.
4. **Configurable TLS versions/cipher suites** — retain the existing TLS 1.2
   minimum and cipher policy; this issue controls trust only.
5. **Plain HTTP selection** — GH-284 owns `BACKEND_USE_SSL` and scheme
   precedence; TLS controls are invalid for an effective HTTP endpoint.
6. **Hot reload of transport trust** — clients are constructed at startup;
   changing CA files or flags requires a process restart.

## 3. Target Interface / Semantics / Behaviour

### 3.1 Configuration contract

```go
type BackendConfig struct {
    // existing fields...
    TLS BackendTLSConfig `yaml:"tls"`
}

// BackendTLSConfig controls server authentication for HTTPS backend requests.
//
// Invariants:
//   - Zero value uses system roots and verifies certificate chains and hostnames.
//   - CAFile PEM certificates augment, never replace, system roots.
//   - InsecureSkipVerify disables chain and hostname verification and is unsafe.
//   - Settings are immutable after backend client construction.
type BackendTLSConfig struct {
    CAFile             string `yaml:"ca_file" env:"BACKEND_TLS_CA_FILE"`
    InsecureSkipVerify bool   `yaml:"insecure_skip_verify" env:"BACKEND_TLS_INSECURE_SKIP_VERIFY"`
}
```

```yaml
backend:
  endpoint: private-s3.example.internal:9000
  use_ssl: true
  tls:
    ca_file: /etc/s3eg/backend-ca/ca.pem
    insecure_skip_verify: false
```

| Setting | Default | Semantics |
|---|---|---|
| `backend.tls.ca_file` / `BACKEND_TLS_CA_FILE` | empty | Append PEM certificates to system root pool |
| `backend.tls.insecure_skip_verify` / `BACKEND_TLS_INSECURE_SKIP_VERIFY` | false | HTTPS remains encrypted, but certificate chain and hostname are not authenticated |

Nested YAML follows existing TLS config patterns at
`internal/config/config.go:678-684,983-991`. Custom CA is preferred because it
preserves server identity; insecure mode exists only for development and
diagnosis [1][2].

### 3.2 Validation and warning contract

- Parse `BACKEND_TLS_INSECURE_SKIP_VERIFY` with `strconv.ParseBool`; a present
  empty or malformed value is a startup error.
- `ca_file` must name a readable regular file whose PEM data adds at least one
  certificate to an `x509.CertPool`; otherwise return an error naming the path,
  never PEM contents.
- Determine the effective endpoint scheme using GH-284 semantics. If a backend
  endpoint is effectively HTTP and either TLS option is set, fail validation
  because the settings cannot protect that connection.
- Allow `ca_file` and `insecure_skip_verify` together but emit the insecure
  warning; document that CA trust has no verification effect while skip-verify
  is true. This supports diagnostics without forcing config rewrites.
- Emit one startup warning from `cmd/server/main.go` after successful config
  load and before backend client construction:

```text
backend.tls.insecure_skip_verify is true; backend certificate and hostname verification are disabled — use only for local development or diagnostics
```

Failing on inactive HTTP TLS settings prevents an operator from believing a CA
is protecting a plaintext connection. Allowing both CA and insecure mode makes
temporary diagnosis reversible while retaining a conspicuous warning.

### 3.3 Shared transport builder

```go
// newBackendHTTPTransport builds the production transport for SDK and proxy clients.
//
// Invariants:
//   - Starts from http.DefaultTransport.Clone() to retain proxy and dial defaults.
//   - Clones/creates TLSClientConfig; never mutates global transports.
//   - Enforces TLS >= 1.2 and the repository's existing TLS 1.2 cipher policy.
//   - Appends CAFile certificates to system roots.
//   - Sets InsecureSkipVerify only from explicit configuration.
//   - Returns an error before network I/O for trust-store loading failures.
func newBackendHTTPTransport(cfg config.BackendTLSConfig) (*http.Transport, error)
```

The SDK constructor passes `&http.Client{Transport: transport}` via
`awsconfig.WithHTTPClient`; the proxy constructor uses the same transport and
then applies its existing idle and response-header timeout settings. A cloned
default transport preserves environment proxy behavior and connection defaults,
while a cloned `tls.Config` avoids unsafe shared mutation [1].

Test-only `WithHTTPTransport` remains authoritative: when supplied, it bypasses
production transport construction exactly as today. This preserves fault
injection and prevents wrapping arbitrary test transports.

### 3.4 Helm contract

```yaml
config:
  backend:
    tls:
      caFile:
        value: ""
        valueFrom: {}
      insecureSkipVerify:
        value: "false"
        valueFrom: {}
```

The deployment renders `BACKEND_TLS_CA_FILE` only when direct/valueFrom input is
present and always renders `BACKEND_TLS_INSECURE_SKIP_VERIFY`. Operators mount
the CA through existing `extraVolumes`/`extraVolumeMounts` mechanisms; this plan
does not embed certificate contents in chart values.

## 4. Work Breakdown

### Phase A — Configuration model and validation

- **A1. `internal/config/config.go` (edit):** add `BackendTLSConfig` and
  `BackendConfig.TLS`; document zero-value and security invariants.
- **A2. `internal/config/config.go` (edit):** load
  `BACKEND_TLS_CA_FILE` and strictly parse
  `BACKEND_TLS_INSECURE_SKIP_VERIFY`, returning wrapped variable-specific errors.
- **A3. `internal/config/config.go` (edit):** add backend TLS validation: reject
  TLS settings for an effective HTTP endpoint and validate configured CA files
  through a side-effect-free helper shared with transport construction or a
  single construction-time validation path. Avoid TOCTOU claims: the client
  builder must still handle read/parse failure.
- **A4. `internal/config/config_test.go` (edit):** add
  `TestLoadConfig_BackendTLSEnvOverrides`,
  `TestLoadConfig_BackendTLSInvalidBool_ReturnsError`, and
  `TestConfigValidate_BackendTLSRequiresHTTPS`.

> Phase A depends on GH-284's effective-scheme semantics being available to
> validation without duplicating conflicting URL logic.

### Phase B — Shared TLS transport

- **B1. `internal/s3/backend_transport.go` (new):** implement
  `newBackendHTTPTransport`, system-root cloning, PEM loading, minimum TLS 1.2,
  current cipher/curve policy, and wrapped errors.
- **B2. `internal/s3/backend_transport_test.go` (new):** add
  `TestNewBackendHTTPTransport_DefaultVerification`,
  `TestNewBackendHTTPTransport_CustomCA`,
  `TestNewBackendHTTPTransport_InsecureSkipVerify`, and
  `TestNewBackendHTTPTransport_InvalidCA_ReturnsError`. Use an `httptest` TLS
  server and generated test CA/certificate; never commit a private key fixture.
- **B3. `internal/s3/client.go` (edit):** when `WithHTTPTransport` is absent,
  build the shared transport and inject it through `awsconfig.WithHTTPClient`;
  propagate errors from `GetClientWithCredentials` with context.
- **B4. `internal/s3/client_test.go` (edit):** add
  `TestNewClientFactory_BackendTLSCustomCA` and
  `TestNewClientFactory_BackendTLSUntrustedFails`; exercise an actual signed
  SDK request or HTTP round trip against the TLS fixture.

### Phase C — Proxy parity and startup visibility

- **C1. `internal/s3/proxy_client.go` (edit):** replace the inline transport
  literal at current lines 49-69 with `newBackendHTTPTransport`; retain
  `Timeout: 60s`, `IdleConnTimeout: 90s`, `ResponseHeaderTimeout: 10s`, and
  `MaxIdleConnsPerHost: 10`.
- **C2. `internal/s3/proxy_client_test.go` (edit):** extend
  `TestNewProxyClient_TLSConfig`; add
  `TestNewProxyClient_CustomCA_VerifiesServer`,
  `TestNewProxyClient_UntrustedCertificateFails`, and
  `TestNewProxyClient_InsecureSkipVerify_AllowsUntrustedServer`.
- **C3. `cmd/server/main.go` (edit):** log the one explicit insecure backend TLS
  warning before `NewBackendClient`; do not include endpoint credentials,
  certificate data, or secrets.

> Phases B and C use the scheme contract implemented by GH-284. B1 must land
> before B3 and C1.

### Phase D — Capability-gated Tier 2 TLS fixture

- **D1. `test/provider/capabilities.go` (edit):** add
  `CapBackendTLSFixture` at the next free bit and include it in `capNames`. The
  bit means that `provider.Instance.BackendTLS` contains a usable HTTPS S3
  fixture and CA path; it does not mean generic HTTPS support is unique to that
  provider.
- **D2. `test/provider/provider.go` (edit):** add an optional
  `BackendTLS *TLSFixture` field to `Instance` and define:

  ```go
  type TLSFixture struct {
      Endpoint string
      CAFile   string
  }
  ```

  The fixture contract requires an HTTPS endpoint on a random mapped port, a
  PEM CA file owned by the test temp directory, and cleanup registered by the
  provider. Consumers must not inspect `ProviderName`.
- **D3. `test/provider/minio.go` (edit):** for the local MinIO provider, create
  a test-only CA/server certificate with hostname/SAN matching the mapped
  endpoint, start or configure a TLS-enabled MinIO fixture through
  Testcontainers, write the CA PEM with mode `0600` under `t.TempDir()`, set
  `Instance.BackendTLS`, create the fixture bucket through an HTTP client that
  trusts that CA, and add `CapBackendTLSFixture`. If Docker or the TLS fixture
  cannot start, call `t.Skipf` with the missing fixture; use no fixed host port
  and register container cleanup with `t.Cleanup`.
- **D4. `test/conformance/backend_tls_test.go` (new):** add provider-agnostic
  `testBackendTLSCustomCARoundTrip` and
  `testBackendTLSInsecureSkipVerifyRoundTrip`. Each uses only
  `inst.BackendTLS`, starts the gateway with `harness.WithConfigMutator`, and
  completes encrypted PUT/GET. Add
  `testBackendTLSUntrustedCertificateRejected`, constructing the backend client
  without the CA and asserting TLS verification failure before any successful
  object mutation. Use unique keys and shared cleanup.
- **D5. `test/conformance/suite_test.go` (edit):** register all three cases with
  `provider.CapBackendTLSFixture`. Do not branch on provider names; the existing
  `TestConformance_NoProviderNameLiterals` remains the mechanical guard.

All D-phase tests are Tier 2 and carry only the `conformance` build tag. The TLS
fixture uses Testcontainers and random ports; Docker absence is a clean
fixture-naming `t.Skip`, but final acceptance requires the capable local fixture
to execute rather than skip.

### Phase E — Configuration and Helm delivery surface

- **E1. `config.yaml.example` (edit):** add annotated `backend.tls.ca_file` and
  `insecure_skip_verify` examples, recommend custom CA, and distinguish both
  from plaintext `use_ssl: false`.
- **E2. `helm/s3-encryption-gateway/values.yaml` (edit):** add `config.backend.tls.caFile`
  and `.insecureSkipVerify` config-value objects with secure defaults and mount guidance.
- **E3. `helm/s3-encryption-gateway/values.schema.json` (edit):** add a closed
  `backend.tls` object whose children use `#/$defs/configValue`.
- **E4. `helm/s3-encryption-gateway/templates/deployment.yaml` (edit):** render
  `BACKEND_TLS_CA_FILE` conditionally and
  `BACKEND_TLS_INSECURE_SKIP_VERIFY` consistently via the existing `envVar` helper.
- **E5. `helm/s3-encryption-gateway/tests/ci-values.yaml` (edit):** supply test
  backend TLS values so normal chart rendering exercises both env entries.
- **E6. `helm/s3-encryption-gateway/scripts/test-chart.sh` (edit):** add named
  assertions that direct and `valueFrom` settings render to the two exact env
  names without exposing CA contents.

### Phase F — Operator documentation and release note

- **F1. `docs/BACKENDS.md` (edit):** document verified private-CA setup,
  insecure diagnostic mode, restart requirements, and the security distinction
  from HTTP.
- **F2. `helm/s3-encryption-gateway/README.md` (edit):** add both chart values,
  defaults, CA mount example, and warning against production skip-verify.
- **F3. `CHANGELOG.md` (edit):** under `Unreleased`, announce backend custom CA
  trust and the unsafe diagnostic option.
- **F4. `docs/issues/GH-285.md` (edit):** update status and DoD only after all
  implementation and validation evidence exists.

## 5. Affected Files

### Direct edits

- `internal/config/config.go` — backend TLS model, env loading, and validation.
- `internal/config/config_test.go` — YAML/env/error/security contract tests.
- `internal/s3/client.go` — inject production TLS-aware HTTP transport into AWS SDK.
- `internal/s3/client_test.go` — test SDK private-CA behavior.
- `internal/s3/proxy_client.go` — consume shared transport builder.
- `internal/s3/proxy_client_test.go` — test proxy verification behavior.
- `cmd/server/main.go` — emit insecure-mode startup warning.
- `config.yaml.example` — document backend TLS YAML/env settings.
- `helm/s3-encryption-gateway/values.yaml` — expose chart values.
- `helm/s3-encryption-gateway/values.schema.json` — validate chart values.
- `helm/s3-encryption-gateway/templates/deployment.yaml` — render env variables.
- `helm/s3-encryption-gateway/tests/ci-values.yaml` — exercise rendering.
- `helm/s3-encryption-gateway/scripts/test-chart.sh` — assert env rendering.
- `helm/s3-encryption-gateway/README.md` — document chart usage.
- `docs/BACKENDS.md` — document backend trust and risk semantics.
- `test/provider/capabilities.go` — add the backend TLS fixture capability.
- `test/provider/provider.go` — expose optional TLS fixture metadata.
- `test/provider/minio.go` — provision a TLS-enabled Testcontainers fixture.
- `test/conformance/suite_test.go` — register capability-gated TLS cases.
- `CHANGELOG.md` — release note.
- `docs/issues/GH-285.md` — completion tracking.

### New files

- `internal/s3/backend_transport.go` — shared backend TLS transport construction.
- `internal/s3/backend_transport_test.go` — TLS trust and failure tests.
- `test/conformance/backend_tls_test.go` — provider-agnostic real-backend TLS tests.
- `docs/issues/GH-285.md` — local source record imported from GitHub issue #285.
- `docs/plans/GH-285-plan.md` — this implementation plan.

## 6. Test Strategy

Testing follows `docs/TESTING.md`: config, transport, SDK, and proxy tests are
Tier 1 with no build tag and no Docker; live TLS backend tests are Tier 2 with
only the `conformance` tag and Testcontainers. Every test belongs to exactly
one tier. No Tier 3 load, soak, or chaos test is required because the change
does not target throughput or fault-injection behavior. `-count=1` prevents
cached successes from satisfying focused or broad acceptance gates.

| Layer | Tests |
|---|---|
| Unit — config | `TestLoadConfig_BackendTLSEnvOverrides` — YAML/env precedence for CA and skip-verify; no build tag. |
| Unit — error surface | `TestLoadConfig_BackendTLSInvalidBool_ReturnsError` and `TestConfigValidate_BackendTLSRequiresHTTPS` — malformed bool and inactive HTTP TLS settings fail closed; no build tag. |
| Unit — transport | `TestNewBackendHTTPTransport_DefaultVerification`, `TestNewBackendHTTPTransport_CustomCA`, `TestNewBackendHTTPTransport_InsecureSkipVerify`, `TestNewBackendHTTPTransport_InvalidCA_ReturnsError` — verify roots, hostname checking, explicit bypass, and malformed/missing PEM failure; no build tag. |
| Unit — SDK | `TestNewClientFactory_BackendTLSCustomCA` and `TestNewClientFactory_BackendTLSUntrustedFails` — prove the AWS SDK path uses the configured transport; no build tag. |
| Unit — proxy | `TestNewProxyClient_CustomCA_VerifiesServer`, `TestNewProxyClient_UntrustedCertificateFails`, and `TestNewProxyClient_InsecureSkipVerify_AllowsUntrustedServer` — prove parity; no build tag. |
| Helm | `TestHelmBackendTLSValuesRender` (implemented as named `test-chart.sh` assertions) — direct/valueFrom env rendering and schema rejection of unknown keys; no build tag. |
| Tier 2 — conformance | `TestConformance/<provider>/BackendTLS_CustomCARoundTrip` via `testBackendTLSCustomCARoundTrip` — capability-gated encrypted PUT/GET against a real HTTPS S3 fixture with generated private CA; `conformance` build tag only. |
| Tier 2 — negative | `TestConformance/<provider>/BackendTLS_UntrustedCertificateRejected` via `testBackendTLSUntrustedCertificateRejected` — omit the CA, assert trust failure, and prove no successful object mutation; `conformance` build tag only. |
| Tier 2 — diagnostic mode | `TestConformance/<provider>/BackendTLS_InsecureSkipVerifyRoundTrip` via `testBackendTLSInsecureSkipVerifyRoundTrip` — explicitly enable bypass and prove HTTPS PUT/GET against the otherwise untrusted fixture; `conformance` build tag only. |
| Negative / race | `TestNewBackendHTTPTransport_ConcurrentConstruction` — concurrent builds do not mutate `http.DefaultTransport` or shared root pools; verified under `-race`; no build tag. |

### Validation Matrix

| Command | Purpose | Tier | Owner | Run when |
|---|---|---|---|---|
| `go test -race -count=1 ./internal/config ./internal/s3 -run '^(TestLoadConfig_BackendTLS|TestConfigValidate_BackendTLS|TestNewBackendHTTPTransport_|TestNewClientFactory_BackendTLS|TestNewProxyClient_(CustomCA|Untrusted|InsecureSkipVerify))'` | Fast TLS config/transport regression feedback | 1 | implementation worker | After Phases A-C |
| `helm lint helm/s3-encryption-gateway && helm/s3-encryption-gateway/scripts/test-chart.sh` | Validate Helm schema/template delivery surface | 1 | implementation worker | After Phase E |
| `set -o pipefail; make test 2>&1 \| tee /tmp/opencode/GH-285-make-test.log >/dev/null` | Full unit, race, and aggregate coverage gate | 1 | coordinator | Once after the final worker edit |
| `set -o pipefail; make test-conformance 2>&1 \| tee /tmp/opencode/GH-285-make-test-conformance.log >/dev/null` | Full registered-provider conformance; all four local providers and the capable TLS fixture must execute, while unconfigured external providers may skip | 2 | coordinator | Once after `make test`, with Docker available, after the final worker edit |
| `make test-isolation-check` | Prove Tier 2 TLS setup uses Testcontainers, random ports, and no Compose/backend subprocess dependency | Structural | coordinator | Once after conformance/provider files are final |

### Commands to verify locally

```bash
go test -race -count=1 ./internal/config ./internal/s3 -run '^(TestLoadConfig_BackendTLS|TestConfigValidate_BackendTLS|TestNewBackendHTTPTransport_|TestNewClientFactory_BackendTLS|TestNewProxyClient_(CustomCA|Untrusted|InsecureSkipVerify))'
helm lint helm/s3-encryption-gateway && helm/s3-encryption-gateway/scripts/test-chart.sh
set -o pipefail; make test 2>&1 | tee /tmp/opencode/GH-285-make-test.log >/dev/null
set -o pipefail; make test-conformance 2>&1 | tee /tmp/opencode/GH-285-make-test-conformance.log >/dev/null
make test-isolation-check
```

Before the Tier 2 gate, unset all
`GATEWAY_TEST_SKIP_{MINIO,GARAGE,RUSTFS,SEAWEEDFS}` variables and verify Docker
is available. The coordinator must inspect
`/tmp/opencode/GH-285-make-test-conformance.log` and confirm MinIO, Garage,
RustFS, and SeaweedFS ran, and that the provider advertising
`CapBackendTLSFixture` executed all three `BackendTLS_*` cases. Docker absence
or unavailable TLS setup must still produce a precise `t.Skipf` during local
development, but such a skip is not valid final acceptance evidence. External
providers may skip only when their documented credentials are absent. Tests
must use generated certificates, random mapped ports, unique object keys, and
`t.Cleanup`; no committed private key, Compose dependency, backend subprocess,
or provider-name branch is permitted.

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Insecure mode reaches production unnoticed | Default false, exact explicit setting, prominent startup warning, Helm/docs warning, and DoD verification. |
| Custom CA accidentally replaces public system roots | Start from `x509.SystemCertPool()` and append PEM; test both private and ordinary trust behavior. |
| SDK and proxy enforce different TLS policy | Use one transport builder and end-to-end TLS tests for both paths. |
| Global default transport or cert pool is mutated, causing races/cross-client leakage | Clone `http.DefaultTransport` and each TLS/root pool; add concurrent construction race test. |
| Missing/malformed CA is silently ignored | Require readable regular file and successful `AppendCertsFromPEM`; return a startup/construction error. |
| TLS settings appear active while endpoint is plaintext | Reject non-empty backend TLS settings for an effective HTTP endpoint. |
| Error or warning logs expose PEM or secrets | Log only setting/path context and never file contents, certificate bytes, or credentials. |
| Helm exposes CA content directly in values | Accept a mounted file path; support `valueFrom`; document volume mounting rather than inline PEM. |
| `WithHTTPTransport` tests or callers break | Preserve option precedence and do not wrap caller-supplied round trippers. |
| TLS conformance becomes provider-specific or bypasses the shared matrix | Represent fixture availability with `CapBackendTLSFixture`; test bodies consume only fixture data and never provider names. |
| Docker absence makes TLS conformance appear green through skips | Keep clean `t.Skipf` behavior for developer environments, but require an executed capable local TLS fixture in final acceptance evidence. |

## 8. Definition of Done

- [x] Per `docs/issues/GH-285.md:36-42`, a backend certificate signed by a
      private CA succeeds only when that CA is configured (or explicit insecure
      mode is enabled), in both SDK and proxy paths.
- [x] Default configuration uses system roots with certificate-chain and
      hostname verification enabled.
- [x] Unreadable, non-regular, empty, or certificate-free CA files fail closed
      before backend traffic.
- [x] `BACKEND_TLS_INSECURE_SKIP_VERIFY` is strictly parsed, defaults false, and
      emits the specified startup warning when true.
- [x] TLS trust settings on an effective plaintext HTTP endpoint are rejected.
- [x] The shared transport clones defaults and passes concurrent construction
      tests under the race detector.
- [x] YAML, env variables, example config, Helm values/schema/template, chart
      README, backend guide, and changelog all describe the same contract.
- [x] Helm supports direct and `valueFrom` configuration without embedding CA
      certificate contents in generated defaults.
- [x] The three backend TLS conformance cases are registered through
      `provider.CapBackendTLSFixture`, contain no provider-name branches, use
      unique resources, and clean up containers/files through `t.Cleanup`.
- [x] Added branches in `internal/config` and `internal/s3` achieve at least 85%
      coverage.
- [x] Focused tests, Helm checks, `make test`, and `make test-conformance` pass
      sequentially; MinIO, Garage, RustFS, and SeaweedFS execute rather than
      skip because Docker is unavailable, the TLS-capable fixture executes all
      three new cases, and only unconfigured external providers may skip.
- [x] `make test-isolation-check` passes after provider/conformance files are final.

## 9. Milestones & Estimated Effort

| Phase | Output | Effort |
|---|---|---|
| A | Backend TLS config, strict env loading, and validation | 0.75 d |
| B | Shared hardened transport and SDK integration | 1.25 d |
| C | Proxy parity and startup warning | 0.75 d |
| D | Capability-gated Testcontainers TLS conformance fixture | 1.25 d |
| E | Example and Helm delivery surface | 0.75 d |
| F | Backend/operator documentation and release note | 0.25 d |
| **Total** | | **5.00 d** |

## 10. Follow-ups / Out-of-scope items surfaced during planning

- Backend client-certificate/mTLS support should be a separate issue with key
  loading, secret mounting, rotation, and zeroization requirements.
- Live CA rotation would require atomic client/transport replacement and
  connection draining; this plan deliberately requires process restart.
- Consolidating all repository TLS clients (audit, Valkey, KMS, backend) behind
  one generic TLS builder may be valuable, but risks changing unrelated security
  contracts and is excluded here.

## 11. References

1. Go Authors, *Package crypto/tls* (Go Documentation, 2026) — TLS client
   configuration, `RootCAs`, minimum version, and `InsecureSkipVerify` warning.
   <https://pkg.go.dev/crypto/tls>
2. Go Authors, *Package crypto/x509* (Go Documentation, 2026) — system root pools
   and appending PEM certificates.
   <https://pkg.go.dev/crypto/x509>
3. OWASP Foundation, *Transport Layer Security Cheat Sheet* (OWASP, 2026) —
   certificate validation and secure TLS deployment guidance.
   <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>
4. Amazon Web Services, *Configure HTTP clients* (AWS SDK for Go v2 Developer
   Guide, 2026) — injecting and configuring SDK HTTP transports.
   <https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-http.html>
