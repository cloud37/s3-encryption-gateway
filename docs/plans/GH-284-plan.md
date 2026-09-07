# GH-284 — `BACKEND_USE_SSL=false` Is Ignored — Implementation Plan

Status: Draft
Owner: Config / Backend
Priority: P1
Labels: `area:config`, `area:backend`, `type:bug`

> Scope clarified relative to the imported tracker entry at
> `docs/issues/GH-284.md:1-44`. The maintainer confirmed that the defect is in
> environment-variable loading and that explicit endpoint schemes already act
> as the temporary workaround.

---

## 1. Context & Current State

`BackendConfig.UseSSL` declares both YAML and environment tags
(`internal/config/config.go:114-121`), but this project does not automatically
process `env` tags. `loadFromEnv` manually loads endpoint, credentials, provider,
and `BACKEND_USE_PATH_STYLE` (`internal/config/config.go:1172-1207`) while
omitting `BACKEND_USE_SSL`. Because `LoadConfig` initializes `UseSSL: true`
before applying file and environment sources (`internal/config/config.go:1031-1041,1128-1163`), an environment-only `BACKEND_USE_SSL=false` leaves the
secure default unchanged.

The SDK path compounds that omission: `normalizeEndpoint` always prepends
`https://` to scheme-less values (`internal/s3/client.go:406-418`) and its call
site passes only the endpoint string (`internal/s3/client.go:327-343`). `UseSSL`
currently affects path-style addressing, but not endpoint scheme selection
(`internal/s3/client.go:345-350`). Thus `BACKEND_ENDPOINT=rustfs:9000` is sent to
HTTPS even if the operator asks for plaintext.

The proxy path independently duplicates the same HTTPS-only normalization at
`internal/s3/proxy_client.go:26-45`. Its existing test codifies HTTPS for every
scheme-less endpoint (`internal/s3/proxy_client_test.go:99-113`) without testing
`UseSSL=false`. Both paths must share the same contract to prevent mode-dependent
behavior.

Explicit `http://` endpoints already survive normalization and validation
(`internal/s3/client.go:407-436`) and are the confirmed workaround in
`docs/issues/GH-284.md:12-16`. This behavior remains authoritative: `UseSSL`
supplies only a missing scheme and never rewrites an explicitly configured
`http://` or `https://` URL.

## 2. Design Goals & Non-Goals

### Goals

1. **Environment override correctness** — `BACKEND_USE_SSL=false` overrides the
   default and YAML values; `true` likewise overrides YAML `false`.
2. **Secure default** — when neither YAML nor env specifies `use_ssl`, HTTPS
   remains the default.
3. **Explicit-scheme precedence** — endpoint `http://`/`https://` is never
   rewritten based on `UseSSL`.
4. **Consistent clients** — SDK and proxy paths resolve scheme-less endpoints
   identically.
5. **Strict input** — invalid boolean environment values fail configuration
   loading rather than silently selecting an unintended transport.
6. **Regression proof** — cover the reported RustFS-style scheme-less endpoint
   and all precedence combinations.

### Non-Goals

1. **Certificate trust controls** — custom CAs and insecure verification are
   specified separately in GH-285.
2. **Changing the HTTPS default** — secure defaults remain unchanged.
3. **Rejecting plaintext HTTP** — the maintainer explicitly accepted
   `BACKEND_USE_SSL=false` for local/diagnostic operation.
4. **Changing backend credentials or signing** — endpoint transport selection
   only; SigV4 behavior remains delegated to the AWS SDK.
5. **Forcing path-style mode for explicit HTTP** — `use_path_style` remains an
   independent explicit setting except for the existing `!UseSSL` compatibility
   behavior.

## 3. Target Interface / Semantics / Behaviour

### 3.1 Environment contract

| Input | Result |
|---|---|
| `BACKEND_USE_SSL` unset | Preserve YAML value; preserve default `true` when YAML omitted |
| `BACKEND_USE_SSL=true`, `1`, `t`, `TRUE`, etc. | Set `Backend.UseSSL=true` using `strconv.ParseBool` |
| `BACKEND_USE_SSL=false`, `0`, `f`, `FALSE`, etc. | Set `Backend.UseSSL=false` using `strconv.ParseBool` |
| Any other non-empty value | Return `invalid BACKEND_USE_SSL: ...`; do not start with an ambiguous scheme |

```go
if v, ok := os.LookupEnv("BACKEND_USE_SSL"); ok {
    useSSL, err := strconv.ParseBool(v)
    if err != nil {
        return fmt.Errorf("invalid BACKEND_USE_SSL %q: %w", v, err)
    }
    config.Backend.UseSSL = useSSL
}
```

`LookupEnv` distinguishes an absent variable from a present empty value. A
present empty value is invalid; this avoids silently retaining HTTPS when an
operator intended an override but supplied malformed deployment configuration.

### 3.2 Endpoint scheme contract

```go
// normalizeEndpoint resolves a backend endpoint without changing an explicit
// HTTP(S) scheme.
//
// Invariants:
//   - Explicit http:// and https:// schemes take precedence over useSSL.
//   - A scheme-less endpoint gets https:// when useSSL is true and http:// when false.
//   - Surrounding whitespace and one trailing slash are removed as today.
//   - The function performs no I/O and is safe for concurrent use.
func normalizeEndpoint(endpoint string, useSSL bool) string
```

| Endpoint | `UseSSL` | Effective endpoint |
|---|---:|---|
| `rustfs:9000` | false | `http://rustfs:9000` |
| `rustfs:9000` | true | `https://rustfs:9000` |
| `http://rustfs:9000` | true | `http://rustfs:9000` |
| `https://rustfs:9000` | false | `https://rustfs:9000` |

The explicit URL is treated as the most specific operator instruction, matching
the confirmed workaround and preserving compatibility. `UseSSL` is a defaulting
control for scheme-less endpoints, not a URL rewriter.

### 3.3 Proxy parity

`NewProxyClient` must invoke `normalizeEndpoint(cfg.Endpoint, cfg.UseSSL)` before
`url.Parse` and remove its private hard-coded HTTPS branch. It must continue to
reject an empty endpoint (`internal/s3/proxy_client.go:28-31`) and use the
resolved URL for every forwarded request (`internal/s3/proxy_client.go:75-88`).

## 4. Work Breakdown

### Phase A — Correct environment loading

- **A1. `internal/config/config.go` (edit):** add strict
  `BACKEND_USE_SSL` parsing immediately after `BACKEND_PROVIDER`; return a
  wrapped error naming the variable and invalid value.
- **A2. `internal/config/config_test.go` (edit):** add table-driven
  `TestLoadConfig_BackendUseSSLEnvOverride` cases for unset/default, false over
  default, false over YAML true, true over YAML false, and accepted ParseBool
  spellings. Add `TestLoadConfig_BackendUseSSLInvalid_ReturnsError` for empty
  and malformed present values.

### Phase B — Endpoint normalization contract

- **B1. `internal/s3/client.go` (edit):** change
  `normalizeEndpoint(endpoint string)` to
  `normalizeEndpoint(endpoint string, useSSL bool)` and select the missing
  scheme from `useSSL`; update the SDK call at current line 332.
- **B2. `internal/s3/client_test.go` (edit):** add
  `TestNormalizeEndpoint_UseSSLAndExplicitSchemePrecedence` as a table covering
  the four combinations in §3.2 plus whitespace/trailing slash behavior.
- **B3. `internal/s3/client_test.go` (edit):** add
  `TestNewClientFactory_SchemeLessEndpointHonorsUseSSL` and inspect the
  constructed SDK client's base endpoint (or capture requests through a test
  transport) for both true and false.

### Phase C — Proxy parity

- **C1. `internal/s3/proxy_client.go` (edit):** replace duplicate HTTPS
  normalization with the shared helper, then parse and validate the normalized
  URL before constructing `ProxyClient`.
- **C2. `internal/s3/proxy_client_test.go` (edit):** convert
  `TestNewProxyClient_NoScheme` into
  `TestNewProxyClient_NoSchemeHonorsUseSSL`, covering HTTP and HTTPS, and add
  `TestNewProxyClient_ExplicitSchemeTakesPrecedence`.

> Phase C depends on the helper signature introduced by B1.

### Phase D — Provider-agnostic Tier 2 regression

- **D1. `test/conformance/backend_connection_test.go` (new):** add
  `testBackendSchemeLessHTTPRoundTrip(t *testing.T, inst provider.Instance)`.
  Derive a scheme-less endpoint by parsing `inst.Endpoint`, require its
  effective scheme to be HTTP or skip with the fixture reason, then start the
  gateway with `harness.WithConfigMutator` setting the endpoint to `u.Host`,
  `UseSSL=false`, and path-style mode. Complete an encrypted PUT/GET round trip
  through the gateway. The body must not inspect or branch on provider names.
- **D2. `test/conformance/suite_test.go` (edit):** register
  `{"BackendConnection_SchemeLessHTTP", 0,
  testBackendSchemeLessHTTPRoundTrip}` in the common cases slice so every
  applicable registered provider executes the same contract. Providers whose
  fixture endpoint is not HTTP skip with an explicit fixture-based reason.

This is Tier 2 because it uses Testcontainers-backed providers. It carries only
the `conformance` build tag, uses the shared provider registry, random mapped
ports, unique object keys, and `t.Cleanup` through the existing provider/harness
lifecycle. No provider-name literal or branch is permitted.

### Phase E — Documentation and release tracking

- **E1. `config.yaml.example` (edit):** clarify that `use_ssl` selects the
  scheme only when `backend.endpoint` omits one and that explicit schemes win.
- **E2. `helm/s3-encryption-gateway/README.md` (edit):** apply the same
  precedence language to `config.backend.useSSL`; the chart already renders
  `BACKEND_USE_SSL` at `templates/deployment.yaml:104`.
- **E3. `CHANGELOG.md` (edit):** add the issue #284 regression fix under
  `Unreleased`.
- **E4. `docs/issues/GH-284.md` (edit):** update status and DoD checkboxes only
  after implementation verification.

## 5. Affected Files

### Direct edits

- `internal/config/config.go` — parse `BACKEND_USE_SSL` strictly.
- `internal/config/config_test.go` — verify env precedence and invalid inputs.
- `internal/s3/client.go` — derive a missing endpoint scheme from `UseSSL`.
- `internal/s3/client_test.go` — test SDK endpoint resolution.
- `internal/s3/proxy_client.go` — use the shared scheme contract.
- `internal/s3/proxy_client_test.go` — test proxy endpoint resolution.
- `test/conformance/suite_test.go` — register the provider-agnostic Tier 2 case.
- `config.yaml.example` — document scheme precedence.
- `helm/s3-encryption-gateway/README.md` — clarify Helm-facing behavior.
- `CHANGELOG.md` — record the bug fix.
- `docs/issues/GH-284.md` — track completion evidence.

### New files

- `test/conformance/backend_connection_test.go` — scheme-less HTTP round trip against registered provider fixtures.
- `docs/issues/GH-284.md` — local source record imported from GitHub issue #284.
- `docs/plans/GH-284-plan.md` — this implementation plan.

## 6. Test Strategy

Testing follows `docs/TESTING.md`: configuration/helper tests are Tier 1 with
no build tag and no Docker; the real backend round trip is Tier 2 with only the
`conformance` tag and Testcontainers. Every test lives in exactly one tier. No
Tier 3 load, soak, or chaos test is needed because this change does not alter a
performance or resilience property. `-count=1` in focused and broad commands
prevents cached results from satisfying acceptance.

| Layer | Tests |
|---|---|
| Unit — config | `TestLoadConfig_BackendUseSSLEnvOverride` — env false/true override defaults and opposing YAML values; no build tag. |
| Unit — error surface | `TestLoadConfig_BackendUseSSLInvalid_ReturnsError` — empty/malformed present env values fail with variable-specific errors; no build tag. |
| Unit — helper | `TestNormalizeEndpoint_UseSSLAndExplicitSchemePrecedence` — validates the full matrix and existing trimming; no build tag. |
| Unit — SDK client | `TestNewClientFactory_SchemeLessEndpointHonorsUseSSL` — proves effective request/base endpoint schemes for both booleans; no build tag. |
| Unit — proxy | `TestNewProxyClient_NoSchemeHonorsUseSSL` and `TestNewProxyClient_ExplicitSchemeTakesPrecedence` — prove parity; no build tag. |
| Tier 2 — conformance | `TestConformance/<provider>/BackendConnection_SchemeLessHTTP` via `testBackendSchemeLessHTTPRoundTrip` — for every applicable registered provider, remove the HTTP scheme, set `UseSSL=false`, and prove encrypted PUT/GET through the real backend; `conformance` build tag only. It is provider-agnostic and capability/name branches are forbidden. |
| Negative / race | All Tier 1 additions run under the `-race` invocation in `make test`; no dedicated mutable concurrency state is introduced. |

### Validation Matrix

| Command | Purpose | Tier | Owner | Run when |
|---|---|---|---|---|
| `go test -race -count=1 ./internal/config ./internal/s3 -run '^(TestLoadConfig_BackendUseSSL|TestNormalizeEndpoint_|TestNewClientFactory_SchemeLessEndpoint|TestNewProxyClient_(NoScheme|ExplicitScheme))'` | Fast regression feedback for env and endpoint resolution | 1 | implementation worker | After Phases A-C |
| `set -o pipefail; make test 2>&1 \| tee /tmp/opencode/GH-284-make-test.log >/dev/null` | Full unit, race, and aggregate coverage gate | 1 | coordinator | Once after the final worker edit |
| `set -o pipefail; make test-conformance 2>&1 \| tee /tmp/opencode/GH-284-make-test-conformance.log >/dev/null` | Full registered-provider conformance; execute the new provider-agnostic case and all existing cases on MinIO, Garage, RustFS, and SeaweedFS; unconfigured external providers may skip | 2 | coordinator | Once after `make test`, with Docker available, after the final worker edit |
| `make test-isolation-check` | Prove the new Tier 2 test uses Testcontainers, random ports, and no Compose/backend subprocess dependency | Structural | coordinator | Once after conformance files are final |

### Commands to verify locally

```bash
go test -race -count=1 ./internal/config ./internal/s3 -run '^(TestLoadConfig_BackendUseSSL|TestNormalizeEndpoint_|TestNewClientFactory_SchemeLessEndpoint|TestNewProxyClient_(NoScheme|ExplicitScheme))'
set -o pipefail; make test 2>&1 | tee /tmp/opencode/GH-284-make-test.log >/dev/null
set -o pipefail; make test-conformance 2>&1 | tee /tmp/opencode/GH-284-make-test-conformance.log >/dev/null
make test-isolation-check
```

Before the Tier 2 gate, unset all
`GATEWAY_TEST_SKIP_{MINIO,GARAGE,RUSTFS,SEAWEEDFS}` variables and verify Docker
is available. The coordinator must inspect
`/tmp/opencode/GH-284-make-test-conformance.log` and confirm all four local
provider suites, including `BackendConnection_SchemeLessHTTP`, executed. Docker
unavailability remains a clean fixture-naming `t.Skip` for development, but a
local-provider skip is not final acceptance evidence. External providers may
skip when their documented credentials are absent. Every test-created object
uses `uniqueKey(t)` and provider/harness `t.Cleanup`; no fixed ports, Compose,
or backend subprocesses are allowed.

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Explicit endpoint scheme is unexpectedly rewritten | Encode explicit-scheme precedence in the table-driven helper and both client-path tests. |
| Proxy and SDK paths drift again | Remove proxy-local normalization and call one unexported helper from both constructors. |
| Invalid env input silently retains secure default and hides deployment mistakes | Use `LookupEnv` plus `strconv.ParseBool` and return a startup error for every invalid present value. |
| Existing scheme-less deployments unexpectedly switch to HTTP | Preserve `UseSSL: true` default and add an unset-env regression case. |
| HTTP compatibility relies accidentally on path-style mode | Keep `UsePathStyle` explicit; retain existing `!UseSSL` fallback without deriving it from an explicit URL scheme. |
| Configuration docs imply `use_ssl` overrides explicit URLs | State precedence identically in the example config and Helm README. |
| Conformance coverage becomes tied to RustFS or another provider | Register one provider-agnostic case with capability/fixture-based skips only; the AST guard rejects provider-name literals. |

## 8. Definition of Done

- [x] Per `docs/issues/GH-284.md:25-29`,
      `BACKEND_ENDPOINT=rustfs:9000 BACKEND_USE_SSL=false` resolves to
      `http://rustfs:9000` in SDK and proxy paths.
- [x] `BACKEND_USE_SSL=true` and `false` override opposing YAML values.
- [x] Unset `BACKEND_USE_SSL` retains the existing secure HTTPS default.
- [x] Invalid or explicitly empty `BACKEND_USE_SSL` fails configuration loading
      with a variable-specific error.
- [x] Explicit `http://` and `https://` endpoint schemes take precedence over
      `UseSSL` and are unchanged.
- [x] SDK and proxy constructors use one endpoint-normalization helper.
- [x] `testBackendSchemeLessHTTPRoundTrip` is registered in the common
      conformance case table, contains no provider-name branch, uses unique
      resources, and cleans up through the shared harness/provider lifecycle.
- [x] Example config, Helm README, and `CHANGELOG.md` describe the implemented behavior.
- [x] New code in `internal/config` and `internal/s3` has at least 85% branch
      coverage for the added parsing and normalization branches.
- [x] Focused tests, `make test`, and `make test-conformance` pass sequentially;
      MinIO, Garage, RustFS, and SeaweedFS execute rather than skip because
      Docker is unavailable, while unconfigured external providers may skip.
- [x] `make test-isolation-check` passes after the conformance files are final.

## 9. Milestones & Estimated Effort

| Phase | Output | Effort |
|---|---|---|
| A | Strict environment override with regression tests | 0.50 d |
| B | Shared endpoint scheme semantics for SDK client | 0.50 d |
| C | Proxy parity and tests | 0.25 d |
| D | Provider-agnostic Tier 2 regression | 0.50 d |
| E | Documentation and release note | 0.25 d |
| **Total** | | **2.00 d** |

## 10. Follow-ups / Out-of-scope items surfaced during planning

- GH-285 builds backend CA trust and insecure verification on this plan's
  effective-scheme contract; implement GH-284 first or in the same coordinated PR.
- A broader migration from permissive `v == "true" || v == "1"` parsing to
  strict parsing for all environment booleans should be a separate compatibility
  issue rather than expanding this focused bug fix.

## 11. References

1. Go Authors, *Package strconv* (Go Documentation, 2026) — accepted boolean
   spellings and `ParseBool` error behavior.
   <https://pkg.go.dev/strconv#ParseBool>
2. Go Authors, *Package net/url* (Go Documentation, 2026) — URL parsing and
   explicit scheme representation.
   <https://pkg.go.dev/net/url>
3. Amazon Web Services, *Configure Client Endpoints* (AWS SDK for Go v2
   Developer Guide, 2026) — custom endpoint configuration semantics.
   <https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-endpoints.html>
