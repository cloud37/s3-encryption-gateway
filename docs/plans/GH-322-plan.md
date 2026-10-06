# GH-322 — Gateway-managed bucket CORS for backends without CORS support — Implementation Plan

Status: Draft
Owner: API / Config / Operations
Priority: P1
Labels: `area:api`, `area:cors`, `area:config`

> Scope clarified relative to `docs/issues/GH-322.md:9-45`: the gateway-owned
> store is shared Valkey, not a hidden S3 object. The optional global fallback
> uses **explicit** origins/methods/headers/exposed headers; the optional global
> `allow_credentials` applies to both bucket rules and fallback. Neither is
> enabled by default. Source: GitHub #322 [1].

---

## 1. Context & Current State

Bucket/object OPTIONS routes already exist (`internal/api/handlers.go:359-361`),
but `handleCORSPreflight` calls `handlePassthrough`, not a local CORS evaluator
(`internal/api/handlers.go:4956-4959`). Browser preflights with Origin, requested
method, and no auth material bypass signature authentication narrowly
(`internal/api/auth_middleware.go:40-70,151-165`), while authorization still
checks `proxied_bucket` (`internal/api/authorization.go:63-82`). The forwarding
path clones headers, strips client authentication, signs with backend
credentials, and calls the backend (`internal/api/utils.go:175-252`). With a
backend lacking CORS support, preflight cannot succeed. The existing
passthrough test actually expects backend-generated CORS headers
(`internal/api/handlers_test.go:3080-3115`). GitHub #318 solved only the
credential-free preflight path, not gateway-owned CORS policy [1].

The three bucket CORS handlers currently proxy unmodified
(`internal/api/handlers.go:4796-4809`); documentation also says “Proxy verbatim”
(`docs/S3_API_IMPLEMENTATION.md:186-192`). Existing tests only verify
provider-native bucket CORS when `CapBucketCors` is advertised
(`test/conformance/suite_test.go:380-384`) and separately tolerate backend
preflight failures (`test/conformance/s3_compat_test.go:555-619`). Thus the
backend with no bucket CORS API cannot store rules through this gateway [1][2].

Response headers for encrypted upload parts are written locally
(`internal/api/handlers.go:2947-2949`); proxied responses instead copy backend
headers (`internal/api/utils.go:127-140,344-345`). There is no shared
response-wide CORS step; even a backend-supported preflight cannot ensure
the encrypted upload response exposes ETag. Authentication/authorization
may also terminate before a route handler (`internal/api/auth_middleware.go:192-213`,
`internal/api/authorization.go:83-138`). An outer response middleware must
handle all of these paths without overriding the gateway policy with untrusted
upstream Access-Control-* headers [3].

Valkey is already initialized from `multipart_state.valkey` in the server and
its client pool is shared with the size cache (`cmd/server/main.go:843-885`,
`internal/mpu/state.go:1409-1422`). Unlike expiring MPU state (configured at
`internal/config/config.go:971-992`), CORS is durable bucket configuration:
it must have no TTL and requires Valkey persistence, backups and a single
shared instance across replicas [4]. Authorization already classifies CORS
GET as read and PUT/DELETE as manage (`internal/api/authorization.go:41-46,173-182`),
following ADR 0016 (`docs/adr/0016-per-credential-authorization.md:11-17`).
Unlike the current in-flight MPU state, the new bucket CORS documents can be
mutated via the S3 API after startup. This changes Valkey from a largely
reconstructible/short-lived dependency into the **authoritative durable store
for cross-origin policy**. A file loaded on startup cannot remain canonical
when `PUT/DELETE ?cors` changes policy at runtime; losing Valkey data without
a backup means losing those changes, not just retrying uploads
(`docs/issues/GH-322.md:24-40`).

## 2. Design Goals & Non-Goals

### Goals

1. **Compatible default** — absent/`passthrough` mode preserves current
   backend CORS API, preflight and response behavior, with no Valkey requirement.
2. **Shared bucket policy** — gateway mode stores up to 100 ordered S3 CORS
   rules per bucket in persistent, non-expiring Valkey; writes/deletes are
   immediately visible to all gateway replicas.
3. **Browser preflight** — eligible OPTIONS is answered locally (no backend
   request) only for first matching origin/method/all requested headers;
   otherwise returns 403 with no CORS authorization headers.
4. **Actual response coverage** — matched Origin+HTTP method adds policy
   headers on encrypted, plaintext, proxy, error and multipart responses;
   ETag becomes script-readable only when configured as `ExposeHeader`.
5. **Strict authority** — signed requests still require authentication, bucket
   management respects existing ro/manage grants, and unauthenticated OPTIONS
   still obeys `proxied_bucket`.
6. **Opt-in fallback/credentials** — fallback applies only when the bucket
   has no stored CORS document; explicit methods and headers are required;
   credentials mode echoes the validated origin, never `*`.
7. **Fail closed** — store errors/corrupt records never broaden CORS grants;
   mutation failure is observable, not silently accepted.
8. **Explicit durability contract** — before operators opt into gateway mode,
   release and deployment docs warn that Valkey persistence and recoverable
   backups are essential; verify reset/restore and optional-fallback behavior.

### Non-Goals

1. **Hidden companion S3 object** — excluded by the Valkey source-of-truth
   decision in `docs/issues/GH-322.md:15-24`.
2. **Backend rule import or bidirectional sync** — passthrough and gateway
   policies remain independent; migrations must explicitly PUT CORS through
   the gateway, avoiding divergent sources of truth.
3. **Browser authorization** — CORS is a browser read policy, not an S3 grant;
   actual signed requests retain SigV4/V2 and credential scope checks.
4. **Per-rule credentials extension in S3 XML** — S3 XML has no such element;
   the explicit global opt-in is deployment-level, not a wire-format change.
5. **Dynamic CORS setting reload** — switching mode, fallback or credentials
   requires a coordinated restart; live reload must reject these changes to
   prevent replica policy drift.
6. **Startup file as a competing policy source** — runtime `PUT/DELETE ?cors`
   can diverge from startup files; static templates may be re-applied manually,
   but this plan does not load files or overwrite live Valkey policy on restart.

## 3. Target Interface / Semantics / Behaviour

### 3.1 Configuration and Valkey contract

```go
type Config struct { // existing fields unchanged
    CORS CORSConfig `yaml:"cors"`
}

// CORSConfig is immutable after server construction.
// Invariants: immutable during serving and safe for concurrent reads; mode
// defaults to passthrough; fallback grants nothing without both origins and
// methods; credentials is opt-in and never emits wildcard Allow-Origin;
// gateway mode requires reachable shared Valkey. No KMS or DEKs are used.
type CORSConfig struct {
    Mode             string             `yaml:"mode" env:"CORS_MODE"`
    AllowCredentials bool               `yaml:"allow_credentials" env:"CORS_ALLOW_CREDENTIALS"`
    Fallback         CORSFallbackConfig `yaml:"fallback"`
}
type CORSFallbackConfig struct {
    AllowedOrigins []string `yaml:"allowed_origins"`
    AllowedMethods []string `yaml:"allowed_methods"`
    AllowedHeaders []string `yaml:"allowed_headers"`
    ExposeHeaders  []string `yaml:"expose_headers"`
    MaxAgeSeconds  int      `yaml:"max_age_seconds"`
}
```

```yaml
cors:
  mode: gateway                  # default: passthrough
  allow_credentials: false       # nonstandard opt-in; true echoes the origin
  fallback:                      # optional; only when bucket has no CORS XML
    allowed_origins: ["https://console.example.com"]
    allowed_methods: [GET, HEAD, PUT, POST, DELETE]
    allowed_headers: ["content-type", "x-amz-*"]
    expose_headers: [ETag]
    max_age_seconds: 3600
multipart_state:
  valkey:
    addr: valkey.internal:6379   # required when mode=gateway
```

| Option | Default | Validation / effect |
|---|---|---|
| `cors.mode` / `CORS_MODE` | `passthrough` | Exact `passthrough` or `gateway`, reject other values; empty string from a zero-value `Config` is treated as passthrough. |
| `cors.allow_credentials` / `CORS_ALLOW_CREDENTIALS` | false | Parse env with `strconv.ParseBool`; requires gateway mode; when true emit `Access-Control-Allow-Credentials: true` only for matched origins. |
| `cors.fallback.allowed_origins` | empty | Exact origin or single `*` wildcard per S3 rule; no empty, control chars or `null`; set only in gateway mode. |
| `cors.fallback.allowed_methods` | empty | Explicit subset GET, PUT, POST, DELETE, HEAD; require with nonempty origins. |
| `cors.fallback.allowed_headers` | empty | Case-insensitive HTTP field-name pattern, at most one `*`; empty means no requested headers are allowed. |
| `cors.fallback.expose_headers` | empty | Concrete valid response field names (no `*`); `ETag` must be explicitly listed to expose part ETags. |
| `cors.fallback.max_age_seconds` | 0 | Integer ≥ 0; render only if positive. |

Reject partially populated fallback, fallback/credentials in passthrough mode,
and gateway mode without `multipart_state.valkey.addr`; if Helm deploys its
in-cluster Valkey subchart, the chart auto-wires `VALKEY_ADDR` instead. Helm's
normal environment-based configuration uses `CORS_FALLBACK_*` JSON-array env
values (strict `json.Unmarshal` into `[]string`, no comma splitting), plus
`CORS_FALLBACK_MAX_AGE_SECONDS` (strict decimal integer). The array env names
are `CORS_FALLBACK_ALLOWED_ORIGINS`, `CORS_FALLBACK_ALLOWED_METHODS`,
`CORS_FALLBACK_ALLOWED_HEADERS`, `CORS_FALLBACK_EXPOSE_HEADERS`. Env always
overrides YAML; absent env retains YAML. Helm values use the chart's
`{value,valueFrom}` leaves; the four array leaves use an array as their direct
`value`, rendered via `toJson` (secretRef supplies already encoded JSON).
Because `internal/api` already imports `internal/config` (`internal/api/handlers.go:27`),
put pure pattern validators in `internal/config` and call them from both config
validation and the API XML parser; do not introduce a config→api import cycle.

This keeps the existing Valkey TLS/auth configuration and chart conventions
(`internal/config/config.go:953-1011`, `helm/s3-encryption-gateway/templates/deployment.yaml:295-307`), while requiring persistence because Valkey may otherwise discard policy at restart [4]. Do not reuse `ValkeyDefaultTTLSeconds`. The default `passthrough` mode is effective even for direct zero-value `config.Config{}` constructions (the server need not run `LoadConfig` for default tests).

**Production dependency change:** in gateway mode `bucketcors:v1:<bucket>`
records are the sole durable bucket-CORS authority; persistent Valkey
storage (AOF and/or RDB on retained storage), an independently maintained
backup, and a tested restore procedure are **essential before enabling** the
feature. AOF/RDB alone is not a substitute for a recoverable backup [4]. The
runtime S3 `PUT/DELETE ?cors` API remains writable; no implicit file import,
startup reconciliation or periodic reset/reload of rules is permitted. Operators
may keep IaC XML as a manual recovery artifact, but must re-export/reconcile it
after API edits or restore Valkey from a current backup. CORS key loss is
different from a transient connection failure; only the latter can be resolved
by simply bringing the same Valkey data back online.

### 3.2 S3 XML, store and matching contract

```go
type CORSConfiguration struct {
    XMLName xml.Name   `xml:"CORSConfiguration"`
    Rules   []CORSRule `xml:"CORSRule"`
}
type CORSRule struct {
    ID             string   `xml:"ID,omitempty"`
    AllowedOrigins []string `xml:"AllowedOrigin"`
    AllowedMethods []string `xml:"AllowedMethod"`
    AllowedHeaders []string `xml:"AllowedHeader,omitempty"`
    ExposeHeaders  []string `xml:"ExposeHeader,omitempty"`
    MaxAgeSeconds  *int     `xml:"MaxAgeSeconds,omitempty"`
}

// CORSStore is safe for concurrent use; nil store is never used in gateway
// mode. All operations honor ctx cancellation; no external calls on nil ctx
// (return an error). Missing != unavailable; Put replaces atomically; Delete
// is idempotent; Put validates and copies inputs before storing, Get returns
// caller-owned values; no secrets or DEKs are stored.
type CORSStore interface {
    Get(ctx context.Context, bucket string) (*CORSConfiguration, error)
    Put(ctx context.Context, bucket string, value *CORSConfiguration) error
    Delete(ctx context.Context, bucket string) error
    HealthCheck(ctx context.Context) error
}
var ErrCORSNotFound = errors.New("bucket CORS configuration not found")
var ErrCORSUnavailable = errors.New("bucket CORS configuration store unavailable")
```

`CORSStore` is an internal-package injection seam for `cmd/server` and tests.
Its value types are exported so Go callers outside `internal/api` can
implement the interface; XML helpers remain private and the server does not
construct rule values directly.
`parseCORSXML` decodes/validates the namespace and strict element set. Reject
XML processing instructions (other than the optional XML declaration),
directives, unexpected text, and unknown extension nodes rather than silently
discarding them. Accepted wire data is
canonicalized (no comments survive) before writing it back. Literal `null`
Origin is rejected for browser matching. HTTP header-name patterns use token
characters and one optional `*`; response expose names are concrete tokens.
`marshalCORSXML` explicitly writes the standard S3 default `xmlns` attribute
(do not rely on `encoding/xml` to synthesize one from the root tag). The store
re-parses a Valkey record with the same validator before returning it.

Valkey key: `bucketcors:v1:<bucket>` (validated bucket, no user-provided
arbitrary key). Value: validated canonical S3 XML UTF-8 (including standard
`xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`), max 64 KiB; `SET`
without expiration, `GET`, `DEL` on the existing `redis.UniversalClient`; no
local policy cache. `Get` returns `ErrCORSNotFound` only for `redis.Nil`; store
connection errors/corrupt records return `ErrCORSUnavailable`. A missing key
may use the fallback; a corrupt/unavailable key must **never** use it. No
encryption keys are stored; document Valkey access control/TLS, backup and
persistence. Atomic replacement and no per-replica cache avoid stale policy
windows; availability is traded for fail-closed CORS [4].

**Empty-store recovery semantics:** a restarted Valkey with an empty dataset
returns `redis.Nil`, not an availability error. `GET ?cors` returns 404;
preflight denies with 403 unless an explicit global fallback matches, and
actual responses omit CORS headers unless that fallback matches. Signed S3
operations continue, but browser applications may fail preflight or be unable
to read ETag. Readiness checks can report healthy because `PING` and
`INFO persistence` do not attest to the presence of expected keys. A broad
fallback can unintentionally grant **more browser visibility** than the lost
bucket policies; never auto-enable fallback during recovery. Recover from
backups or explicitly re-apply the desired bucket XML through the API and
retest actual browser paths. Do not claim a restart recreates these rules.

PUT `/{bucket}?cors`: after existing manage authorization, ensure bucket exists
using the request-scoped S3 client and `ListObjects(ctx,bucket,"",MaxKeys:1)`
(pattern at `internal/api/handlers.go:1872-1905`). Bound request to **64 KiB**
with `io.LimitReader(r.Body, 64<<10+1)`; check body length, XML root namespace
`http://s3.amazonaws.com/doc/2006-03-01/` or absent namespace, exact known
elements, complete single document, 1–100 rules, at least one allowed origin
and method per rule, allowed methods GET/PUT/POST/DELETE/HEAD, valid origin
patterns (at most one `*`, scheme `http` or `https`, optional port, no path,
query, fragment or CR/LF; standalone `*` allowed), concrete expose-header names
(no `*`), valid allowed-header patterns and
nonnegative max age. Reject unknown elements and duplicate scalar ID/MaxAge;
return 200 empty body on successful atomic SET. If `Content-MD5` is supplied,
verify base64 MD5 against raw body (S3 compatibility; MD5 only for transport
integrity, never authentication); incorrect -> `BadDigest` 400; malformed ->
`InvalidDigest` 400. GET returns 200 XML with S3 namespace, original rule order
and content-type `application/xml`; missing returns 404 `NoSuchCORSConfiguration`.
DELETE on existing bucket is idempotent (204 empty), regardless of prior key;
no forwarding in gateway mode. Never return fallback as a GET document [2][5].
The existence check uses the same bounded minimal-list probe as `HeadBucket`
(`internal/api/handlers.go:1872-1905`); document that a backend denying
`ListObjects` also prevents gateway-mode bucket CORS management. Do not infer
absence from `AccessDenied` or transient errors.

Matching iterates stored rules in order and selects **first** rule matching
Origin, effective method (`Access-Control-Request-Method` for OPTIONS; `r.Method`
otherwise), and on OPTIONS *every* requested field name. Origin matching is
case-sensitive except scheme/host normalized according to origin grammar;
wildcard `*` matches only within the origin string, not across `/` or multiple
ports; reject malformed/non-unique Origin and malformed ACR headers, including
CR/LF and empty list members. Field names use case-insensitive matching;
`*` matches zero or more characters. If bucket key is missing, evaluate the
configured fallback **as one virtual rule**; if bucket document exists, never
try fallback after a failed rule. Actual requests do not inspect unrelated
request headers (the browser already preflights them). Only actual S3 bucket or
object paths, never root/admin/health/metrics, are eligible. Use the strict
preflight predicate already in `internal/api/auth_middleware.go:40-70` for the
public exception; signed OPTIONS continues through normal auth and can be
evaluated locally after authentication. Rationale: AWS specifies first-rule
selection and all-requested-headers matching [2][5].

### 3.3 Response contract

| Request / condition | Status, body, policy headers |
|---|---|
| Gateway OPTIONS with matching rule | 200, empty body; `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods` (matched allowed methods), `Access-Control-Allow-Headers` (only requested permitted names; omit if none), `Access-Control-Expose-Headers` if set, `Access-Control-Max-Age` if >0, optional `Access-Control-Allow-Credentials: true`; `Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers`. No backend call. |
| Gateway OPTIONS with no rule / method / header match | 403 S3 XML `AccessDenied`; no `Access-Control-*` headers; same three `Vary` tokens. |
| Gateway OPTIONS with malformed Origin / ACR | 400 S3 XML `InvalidArgument`; no `Access-Control-*` headers; same `Vary` tokens (missing Origin/ACR without auth still follows existing auth rejection). |
| Actual request, matching bucket rule/fallback | Existing handler status/body untouched; set Allow-Origin, configured Expose-Headers, optional Allow-Credentials, and append `Vary: Origin`; no Allow-Methods/Allow-Headers/Max-Age. |
| Actual request, no match / no config | Existing status/body untouched; remove any backend-supplied `Access-Control-*` policy headers; append `Vary: Origin` on S3 paths with Origin. For absent Origin strip backend CORS policy headers without a store lookup. |
| Store failure or corrupt record on OPTIONS | 503 S3 XML `ServiceUnavailable`; no Allow-Origin/credentials; Vary as above. |
| Store failure or corrupt record on actual request | Continue authentication and S3 operation (including encrypted writes) but suppress **all** `Access-Control-*` headers and log a structured store error; never substitute fallback or upstream headers. |
| Missing bucket on management GET/PUT/DELETE | 404 S3 XML `NoSuchBucket` (or `TranslateError` equivalent); do not create a ghost CORS record. |
| Invalid/oversized XML | 400 `MalformedXML` / 413 `EntityTooLarge` S3 XML; existing policy remains unchanged. |
| Valkey failure on management GET/PUT/DELETE | 503 S3 XML `ServiceUnavailable`; no successful-looking mutation. |

Allow-Origin is `*` only for a standalone `*` rule with credentials disabled;
otherwise emit the exact validated request Origin (including wildcard pattern
matches). With credentials enabled always emit the concrete origin, never
`*`; `Expose-Headers` must list concrete headers. ETag is **not** exposed by
default: operators set `<ExposeHeader>ETag</ExposeHeader>` or fallback
`expose_headers: [ETag]`. Preserve existing `Vary` fields (do not overwrite),
including cache/encoding. Validate header values before reflection [3].

Implement `CORSMiddleware(cfg config.CORSConfig, store CORSStore, logger
*logrus.Logger) func(http.Handler) http.Handler` in `internal/api/cors_middleware.go`.
Wrap the **whole** functional chain (outside Auth and Authorization but inside
Recovery) so auth errors and locally synthesized object responses are covered;
route OPTIONS to `Handler.handleCORSPreflight` in the normal chain. For actual
responses prefetch one rule (only on Origin-bearing S3 paths), set policy
headers before calling downstream, and wrap `ResponseWriter` to reconcile
  headers immediately before `WriteHeader`/implicit `Write`/`Flush`/`ReadFrom`.
On every gateway-mode **non-OPTIONS** S3 response, even when Origin is absent,
strip upstream `Access-Control-*` so passthrough cannot grant an unrequested
origin; on Origin-bearing requests evaluate the local policy before calling
downstream. On OPTIONS, the local handler alone writes the policy headers; the
wrapper must not remove these but must strip any accidental CORS headers on
early Auth/Authorization errors (detect whether the handler was reached by
using a private request-context marker or pass the policy decision via context).
retain `http.Flusher`, `io.ReaderFrom`, `http.Hijacker`, `http.Pusher` and
`Unwrap` behavior of the underlying writer as in
`internal/api/s3_instrumentation.go:49-93`. Never buffer object payloads.
For unauthenticated OPTIONS let auth/authorization gates execute first; local
handler generates response; middleware must not pre-set success headers on
OPTIONS. Rationale: matching at the edge avoids missing encrypted or
authentication response paths; a response wrapper prevents proxy header
copying from overriding the chosen policy (`internal/api/utils.go:130-140`).

### 3.4 Bucket lifecycle and operational contract

Gateway mode must not let CORS rules leak into a newly created bucket of the
same name. On successful gateway `DeleteBucket`, remove the Valkey key before
returning success. On gateway `CreateBucket`, first use the request-scoped
backend client to check existence: if bucket already exists, preserve its
CORS record and let the existing CreateBucket path return the backend status;
only when the backend unambiguously returns `NoSuchBucket` clear a stale key
**before** forwarding creation. If the existence check is unavailable/ambiguous,
return `ServiceUnavailable` without changing the record. In particular, an
unsuccessful CreateBucket against an existing bucket must not erase live CORS.
For deletion, call `forwardToBackend` and inspect status *before* copying the
backend response; retain the existing record for non-2xx statuses, and after
a 2xx delete remove the CORS key before writing the successful response.
Close the upstream body on every branch. Do not broaden `DeleteBucket`
authorization or treat non-2xx as successful management audit.
If cleanup fails, return `ServiceUnavailable` and log that backend deletion
may already have succeeded; instruct retry/remediation before reusing the
bucket name. The gateway creation path will still refuse recreation until
it can clear the stale key. If recreation outside the gateway races
with deletion, operationally require bucket creation/deletion via the gateway
in gateway mode; document the limitation and test gateway-mediated reuse.
Avoid speculative deletion of rules on failed `DeleteBucket` (a nonempty bucket
must retain its policy). This is deliberate to prevent stale per-name policy
grants, not a change to plaintext object handling.

Do not share the short MPU TTL with CORS. Configure persistent Valkey (AOF/RDB)
and backups; use the same external cluster for all gateway replicas and rollout
both replicas to gateway mode together. Explicitly reject changes to CORS mode,
credentials, and fallback in `ConfigChangeApplier.ApplyConfigChanges` before
other changes, as it currently can reload unrelated settings
(`cmd/server/main.go:106-145`). Existing read/write S3 permissions do not
change; `docs/adr/0016-per-credential-authorization.md:11-17` still controls
bucket management.
The startup persistence inspection is advisory: query `INFO persistence` when
gateway mode is enabled, log a prominent warning if neither AOF nor RDB is
enabled or the result cannot be determined, and continue serving when the
Valkey connection works. Do not treat an enabled AOF/RDB setting as proof of
backup integrity, and do not block startup solely on persistence status.

## 4. Work Breakdown

### Phase A — Configuration and policy specification

- **A1. `internal/config/config.go` (edit):** add `CORSConfig`,
  `CORSFallbackConfig` and `Config.CORS`; defaults, JSON-array env parsing,
  strict mode/bool/int parsing, validation (including Valkey requirement),
  calling pure fallback pattern validators defined in A6.
- **A2. `internal/config/config_test.go` (edit):** table-driven
  `TestLoadConfig_CORSModeAndFallback`, `TestLoadConfig_CORSRejectsInvalidEnv`,
  `TestConfigValidate_CORSRequiresValkey`, `TestConfigValidate_CORSFallback`.
- **A3. `cmd/server/main.go` (edit):** reject CORS settings changes early in
  `ConfigChangeApplier.ApplyConfigChanges` by comparing normalized values;
  then wire shared Valkey client into handler and response middleware in
  Phase D. Do not change MPU TLS configuration silently.
- **A4. `cmd/server/main_test.go` (edit):**
  `TestConfigChangeApplier_RejectsCORSHotReloadBeforeMutation`.
- **A5. `docs/adr/0019-gateway-managed-cors.md` (new):** record source of
  truth, default/pass-through isolation, no-TTL persistence, **essential
  Valkey durability and tested backups**, runtime `?cors` mutations vs
  static-file drift, lost-key/fallback behavior, credentialed-origin policy,
  fail-closed store behavior and lifecycle caveat.
- **A6. `internal/config/cors_validation.go` (new):** implement pure
  `ValidateCORSOriginPattern(pattern string) error`,
  `ValidateCORSHeaderPattern(pattern string) error` and
  `ValidateCORSFieldName(name string) error` so config and XML agree on
  wildcard, CRLF and token grammar without an import cycle.
- **A7. `internal/config/cors_validation_test.go` (new):**
  `TestValidateCORSOriginPattern`, `TestValidateCORSHeaderPattern` and
  `TestValidateCORSFieldName` cover exact/wildcard and invalid inputs.

> Phase B depends on the policy fields and invariants of A1.

### Phase B — Ordered XML parser and shared Valkey store

- **B1. `internal/api/cors_rules.go` (new):** define `CORSConfiguration`,
  `CORSRule`, `parseCORSXML(body []byte) (*CORSConfiguration,error)`,
  `matchCORSRule(cfg *CORSConfiguration, origin, method string, requestedHeaders []string) (*CORSRule,bool)`,
  `writeCORSXML(w http.ResponseWriter, cfg *CORSConfiguration) error`, and typed validation errors; validate
  root/namespace/unknown elements, origin/header patterns, list limits and
  requested-header grammar. Check raw MD5 in handler before parsing.
- **B2. `internal/api/cors_rules_test.go` (new):**
  `TestParseCORSXML_ValidRoundTrip`, `TestParseCORSXML_RejectsMalformedAndOversized`,
  `TestMatchCORSRule_FirstRuleAndAllHeaders`, `TestMatchCORSRule_RejectsOriginInjection`,
  `FuzzParseCORSXML_NoPanic`.
- **B3. `internal/api/cors_store.go` (new):** `CORSStore` and sentinels;
  implement `NewValkeyCORSStore(client redis.UniversalClient) CORSStore`,
  no-TTL `SET`, `GET`, `DEL`, bounded decoded XML, `PING` health check, and
  context propagation. The MPU owner closes the shared client; CORS never does.
- **B4. `internal/api/cors_store_test.go` (new):** use miniredis;
  `TestValkeyCORSStore_ReplicaVisibilityAndNoTTL`,
  `TestValkeyCORSStore_MissingVersusUnavailable`,
  `TestValkeyCORSStore_RejectsCorruptRecord`, and
  `TestValkeyCORSStore_ResetThenRestorePolicy`: emulate a flush, assert
  `ErrCORSNotFound` (not `ErrCORSUnavailable`), restore saved XML via `Put`,
  and verify policy matches again. Do not run `FLUSHALL` against a real store.

```go
func (s *valkeyCORSStore) Put(ctx context.Context, bucket string, value *CORSConfiguration) error {
    if ctx == nil { return fmt.Errorf("%w: nil context", ErrCORSUnavailable) }
    wire, err := marshalCORSXML(value)
    if err != nil { return fmt.Errorf("encode bucket CORS: %w", err) }
    if err := s.client.Set(ctx, corsKey(bucket), wire, 0).Err(); err != nil {
        return fmt.Errorf("%w: set CORS: %w", ErrCORSUnavailable, err)
    }
    return nil
}
```

> Phase C depends on B1/B3; avoid a separate direct Valkey connection.

### Phase C — Management API and preflight

- **C1. `internal/api/handlers.go` (edit):** add `CORSStore` field and
  `WithCORSStore(CORSStore)` injection; branch existing three CORS handlers and
  preflight on gateway mode, leaving passthrough untouched. Use helper
  `checkCORSBucket(ctx,r,bucket) error` with request-scoped client and
  `ListObjects(MaxKeys:1)` for management; bounded body, XML validation, MD5,
  S3 error table and response metrics/audit. In gateway mode no call to
  `forwardToBackend` on OPTIONS or `?cors` operations.
- **C2. `internal/api/cors_handlers_test.go` (new):**
  `TestBucketCORS_ManageGrantAndReadOnly`,
  `TestBucketCORS_ManagementRoundTripAndDelete`,
  `TestBucketCORS_BadDigestAndOversizePreserveOldRule`,
  `TestBucketCORS_NoSuchBucketAndStoreFailure`,
  `TestCORSPreflight_NoBackendRequestAndFirstMatch`,
  `TestCORSPreflight_ForbiddenAndMissingConfig`,
  `TestCORSPreflight_FallbackOnlyOnMissingKey`,
  `TestCORSPreflight_StoreFailureFailClosed`,
  `TestCORSPreflight_ResetChangesToFallback`: after deliberate test-only
  key loss, assert 403 without fallback and fallback-allowed behavior when
  configured, including broader origin exposure than a prior bucket rule.
- **C3. `internal/api/auth_middleware_test.go` (edit):**
  `TestAuthMiddleware_GatewayCORSPreflightStillRejectsPartialAuth`; keep the
  narrow existing exception from `internal/api/auth_middleware.go:40-70`.
- **C4. `internal/api/authorization_test.go` (edit):**
  `TestAuthorizationMiddleware_GatewayCORSScopesAndManagement`; verify
  `proxied_bucket` bypass, ro GET, manage PUT/DELETE and signed OPTIONS.
- **C5. `internal/api/cors_handlers_test.go` (edit):**
  `TestBucketCORS_DefaultPassthroughStillForwards` — passthrough forwards
  management and preflight and copies backend headers as before.

```go
func (h *Handler) handleCORSPreflight(w http.ResponseWriter, r *http.Request) {
    if h.config == nil || h.config.CORS.Mode != "gateway" {
        h.handlePassthrough(w, r, "CORSPreflight", mux.Vars(r)["bucket"], mux.Vars(r)["key"])
        return
    }
    // Load policy, match origin/method/all requested headers, emit S3 XML
    // errors or 200 with preflight headers. Never contact the S3 backend.
    h.handleGatewayCORSPreflight(w, r)
}
```

> Phase D depends on Phase C's shared matcher and handler semantics.

### Phase D — Actual responses, startup wiring and lifecycle

- **D1. `internal/api/cors_middleware.go` (new):** implement the §3.3
  response-wide `CORSMiddleware`, header reconciliation and `Vary` append;
  preserve optional writer interfaces and `Unwrap`; avoid wrapping unrelated
  endpoints. Use only the shared matcher, not a separate origin policy. For
  OPTIONS, set a private mutable per-request decision marker in the context;
  the gateway preflight handler marks it only after valid matching and before
  emitting headers, and the writer retains those headers only on that path.
  Clear upstream CORS headers on auth failure, missing/malformed preflight,
  and failed match.
- **D2. `internal/api/cors_middleware_test.go` (new):**
  `TestCORSMiddleware_EncryptedAndProxyHeaders`,
  `TestCORSMiddleware_UnmatchedOriginStripsUpstream`,
  `TestCORSMiddleware_ErrorAndHEADResponses`,
  `TestCORSMiddleware_CredentialsWildcardEchoAndVary`,
  `TestCORSMiddleware_StreamingOptionalInterfaces`,
  `TestCORSMiddleware_StoreDownNeverFallsBack`,
  `TestCORSMiddleware_NoOriginStripsBackendCORS`.
- **D3. `cmd/server/main.go` (edit):** after MPU Valkey creation at
  `cmd/server/main.go:843-869`, take `(*mpupkg.ValkeyStateStore).Client()`;
  attach `api.NewValkeyCORSStore(client)` to the handler, register a CORS
  readiness probe (reuse the MPU Valkey probe if it already covers the same
  shared client), and wrap HTTP chain after Auth/Authorization and before
  Recovery (`cmd/server/main.go:998-1006`). Gateway mode must fatal on startup
  when Valkey cannot be initialized. Query `INFO persistence` at startup
  **only in gateway mode**; warn prominently if both persistence mechanisms
  are disabled or the check cannot determine their state, but allow startup
  with a working Valkey connection. Never present an enabled persistence
  setting as proof of a recoverable backup. No CORS-specific client close. Guard
  gateway mode against a non-Valkey MPU store test seam instead of silently
  using a nil CORS store.
- **D8. `cmd/server/main_test.go` (edit):**
  `TestGatewayCORS_PersistenceWarningIsAdvisory`: with a test Valkey reporting
  disabled/unknown AOF+RDB, assert prominent warning and successful startup;
  with persistence enabled, assert no false durability guarantee is logged.
- **D4. `internal/api/handlers.go` (edit):** gateway-mode `CreateBucket` and
  `DeleteBucket` lifecycle reconciliation as §3.4; preserve existing auth,
  backend status and audit behavior. For creation call a request-scoped backend
  existence check before any stale-key deletion; do not remove an existing
  bucket's policy when CreateBucket fails. Refactor `handlePassthrough` only as
  needed to observe successful deletion before committing client response.
- **D5. `internal/api/cors_handlers_test.go` (edit):**
  `TestBucketCORS_BucketReuseCannotInheritStaleRules`,
  `TestBucketCORS_FailedDeletePreservesRules`,
  `TestBucketCORS_FailedCreatePreservesExistingRules`.
- **D6. `test/harness/gateway.go` (edit):** mirror production middleware
  order and share Valkey client when gateway mode is selected; fail a test
  setup missing Valkey rather than silently choosing a memory store.
- **D7. `test/harness/options.go` (edit):** add `WithCORSMode(mode string)`
  convenience; reuse `WithValkeyAddr` and `WithConfigMutator` for fallback.

> Phase E depends on A–D; do not change native-CORS conformance tests to
> assume gateway mode by default.

### Phase E — End-to-end tests, Helm and documentation

- **E1. `test/conformance/s3_compat_test.go` (edit):** add
  `testS3Compat_GatewayCORSWithoutBackend`, using
  `provider.StartValkey(context.Background(), t)` as the real Valkey fixture
  (`test/conformance/encrypted_mpu_test.go:25-29`) and gateway-mode harness.
  Inject `WithBackendTransport` rejecting backend
  OPTIONS and `?cors` for the gateway's proxy transport; keep other requests
  routed to the real provider. Also assert bucket existence probes succeed
  through the provider's normal S3 client.
  Use `inst.Bucket` for provider-agnostic PUT/GET/DELETE of the CORS
  subresource, cleaning it in `t.Cleanup`; do **not** delete the shared
  provider fixture bucket. Exercise actual DeleteBucket/recreate lifecycle
  in the Tier 1 mock-backed unit tests. Do not introduce extra provider
  capability requirements just to exercise bucket lifecycle.
  Attach a gateway credential scoped to the test bucket with explicit
  `manage` permission and `rw` object permission; use
  `harness.WithEncryptedMPUForBucket(inst.Bucket)` to exercise encrypted
  multipart responses through the production code path; use signed requests
  (SDK or the harness's signing helper) for the actual upload. Start two gateway
  harness instances against the same Valkey address to verify replica reads.
  PUT/GET/DELETE CORS through gateway, assert no backend CORS/OPTIONS calls,
  presigned/authorized PUT and encrypted UploadPart response
  ETags exposed with `ExposeHeader: ETag`, GET/HEAD/CompleteMultipartUpload
  headers, wrong origin 403, replica GET after PUT, fallback and no-config.
  Preserve existing passthrough tests at lines 555–704.
- **E2. `test/conformance/suite_test.go` (edit):** register the gateway-mode
  test with `CapEncryptedMPU` but **not** `CapBucketCors`, since it asserts
  UploadPart; use local S3 provider plus `provider.StartValkey` fixture, and
  skip only if Docker fixtures are unavailable per `docs/TESTING.md:10-40`.
- **E3. `config.yaml.example` (edit):** annotated mode, JSON-array env names,
  fallback, ETag exposure and bold warning: durable Valkey with retained
  storage and tested backup/restore is required operationally for gateway
  mode; rules mutated via the API are not recreated from this config file.
- **E4. `helm/s3-encryption-gateway/values.yaml` (edit):** `config.cors.mode`,
  `allowCredentials`, `fallback.allowedOrigins/allowedMethods/allowedHeaders/
  exposeHeaders/maxAgeSeconds` as `{value,valueFrom}` leaves; empty fallback
  defaults and `passthrough` mode. Place a prominent durability warning next
  to `config.cors.mode` and next to Valkey subchart values: the development
  subchart is not automatically a proven persistent production policy store.
- **E5. `helm/s3-encryption-gateway/values.schema.json` (edit):** validate
  mode enum, array leaf types, boolean credentials, nonnegative max age, and
  gateway-mode requirement for top-level `valkey.enabled` OR configured external
  `config.multipartState.valkey.addr`; maintain chart schema drift rules.
- **E6. `helm/s3-encryption-gateway/templates/deployment.yaml` (edit):** render
  `CORS_MODE`, `CORS_ALLOW_CREDENTIALS`, `CORS_FALLBACK_*` with correct JSON
  encoding for direct list leaves and secret refs for indirect leaves.
- **E7. `helm/s3-encryption-gateway/templates/validate.yaml` (edit):** guard
  gateway mode without available Valkey, including `valueFrom` address.
- **E8. `helm/s3-encryption-gateway/scripts/test-chart.sh` (edit):**
  `TestChart_GatewayCORSValkeyAndFallback` equivalent Helm render/lint
  assertions (shell named case); test direct and valueFrom leaves and invalid
  mode/missing Valkey through existing script's pattern.
- **E9. `helm/s3-encryption-gateway/README.md` (edit):** values, credentials
  warning, Valkey durability/replica requirements, default passthrough,
  empty-store behavior and backup/restore prerequisites. Correct any
  pre-existing “only two features” or “ephemeral Valkey” wording for
  gateway CORS mode without claiming all installations need persistence.
- **E10. `docs/S3_API_IMPLEMENTATION.md` (edit):** replace unqualified proxy
  claims for T2-04..06 and T2-10 with mode-dependent contract and error table.
- **E11. `README.md` (edit):** minimal operator setup for direct browser upload
  with bucket XML and `<ExposeHeader>ETag</ExposeHeader>`, plus a conspicuous
  pre-enable warning immediately beside the gateway-mode instructions:
  Valkey no longer disposable; loss of keys removes API-managed rules,
  `GET ?cors` -> 404, preflights -> 403 without fallback, readiness may be
  healthy, fallback can widen access, and restore/re-apply is required.
  Qualify the existing “only ephemeral per-upload state” claim at
  `README.md:295` when gateway mode is enabled.
- **E12. `CHANGELOG.md` (edit):** under `v1.0 – Unreleased` highlight GH-322's
  **operational breaking change when opting into gateway mode**: persistent
  shared Valkey and recoverable backup are prerequisites; default passthrough
  needs no new durability guarantee, and API updates are not loaded from files.
- **E13. `docs/OPS_DEPLOYMENT.md` (edit):** in shared-Valkey prerequisite and
  cutover checklist, explicitly distinguish optional/disposable cache data
  from gateway CORS's durable source of truth. Require confirmed persistence
  on retained storage, recent backup and exercised restore before rollout,
  and verify all replicas see the same bucket rules after cutover; warn that
  a healthy connection does not prove rules survived a reset.
- **E14. `docs/RUNBOOK.md` (edit):** add “Gateway CORS Valkey data loss and
  recovery” next to `valkey-down` documenting a detection probe (authorized
  `GET ?cors` for a known-configured bucket), how to distinguish 503 outage
  from 404 reset, stop/review the fallback, restore backup or re-apply known
  XML via authenticated `PUT ?cors`, then verify OPTIONS and actual ETag
  response on each replica; never present an unaudited broad fallback as a
  substitute. When re-applying, use a credential with `manage` bucket grant;
  do not claim static templates include API changes not exported from Valkey.
  Amend `valkey-down` to say recovering an empty instance does **not** restore
  gateway CORS rules.

## 5. Affected Files

### Direct edits

- `docs/issues/GH-322.md` — link this plan and record clarified scope.
- `internal/config/config.go` / `internal/config/config_test.go` — config and tests.
- `internal/api/handlers.go` — CORS handlers, store injection, lifecycle.
- `internal/api/auth_middleware_test.go` / `internal/api/authorization_test.go` — auth regression coverage; production authorization code unchanged.
- `cmd/server/main.go` / `cmd/server/main_test.go` — startup, reload and tests.
- `test/harness/gateway.go` / `test/harness/options.go` — Valkey/middleware harness.
- `test/conformance/s3_compat_test.go` / `test/conformance/suite_test.go` — provider contract.
- `config.yaml.example` — mode and fallback example.
- `helm/s3-encryption-gateway/values.yaml` / `helm/s3-encryption-gateway/values.schema.json` — Helm settings.
- `helm/s3-encryption-gateway/templates/deployment.yaml` / `helm/s3-encryption-gateway/templates/validate.yaml` — env and guard.
- `helm/s3-encryption-gateway/scripts/test-chart.sh` / `helm/s3-encryption-gateway/README.md` — chart tests/docs.
- `docs/S3_API_IMPLEMENTATION.md` / `README.md` / `CHANGELOG.md` — API, quickstart, release notes.
- `docs/OPS_DEPLOYMENT.md` / `docs/RUNBOOK.md` — durable-state prerequisites and lost-policy recovery.

### New files

- `internal/api/cors_rules.go` / `internal/api/cors_rules_test.go` — XML rules and matching.
- `internal/api/cors_store.go` / `internal/api/cors_store_test.go` — Valkey store and sentinel errors.
- `internal/api/cors_handlers_test.go` — handler regression tests.
- `internal/api/cors_middleware.go` / `internal/api/cors_middleware_test.go` — response-wide policy.
- `internal/config/cors_validation.go` / `internal/config/cors_validation_test.go` — pure shared pattern checks.
- `docs/adr/0019-gateway-managed-cors.md` — architecture decision (0018 is the latest existing ADR).

## 6. Test Strategy

| Layer | Tests |
|---|---|
| Unit — config (no tag) | `TestLoadConfig_CORSModeAndFallback`, `TestLoadConfig_CORSRejectsInvalidEnv`, `TestConfigValidate_CORSRequiresValkey`, `TestConfigValidate_CORSFallback`, `TestValidateCORSOriginPattern`, `TestValidateCORSHeaderPattern`, `TestValidateCORSFieldName` — defaults, precedence, strict parsing, pattern validity and dependency. |
| Unit — store (no tag) | `TestValkeyCORSStore_ReplicaVisibilityAndNoTTL`, `TestValkeyCORSStore_MissingVersusUnavailable`, `TestValkeyCORSStore_RejectsCorruptRecord`, `TestValkeyCORSStore_ResetThenRestorePolicy` — atomic persistence, empty-store recovery, key absence and fail-closed failure. |
| Unit — XML/matching (no tag) | `TestParseCORSXML_ValidRoundTrip`, `TestParseCORSXML_RejectsMalformedAndOversized`, `TestMatchCORSRule_FirstRuleAndAllHeaders`, `TestMatchCORSRule_RejectsOriginInjection` — strict schema, order, wildcard and request-header validation. |
| Unit — API (no tag) | `TestBucketCORS_ManageGrantAndReadOnly`, `TestBucketCORS_ManagementRoundTripAndDelete`, `TestBucketCORS_BadDigestAndOversizePreserveOldRule`, `TestBucketCORS_NoSuchBucketAndStoreFailure`, `TestBucketCORS_BucketReuseCannotInheritStaleRules`, `TestBucketCORS_FailedDeletePreservesRules`, `TestBucketCORS_FailedCreatePreservesExistingRules`, `TestBucketCORS_DefaultPassthroughStillForwards` — S3 semantics, authorization and lifecycle. |
| Unit — preflight (no tag) | `TestCORSPreflight_NoBackendRequestAndFirstMatch`, `TestCORSPreflight_ForbiddenAndMissingConfig`, `TestCORSPreflight_FallbackOnlyOnMissingKey`, `TestCORSPreflight_StoreFailureFailClosed`, `TestCORSPreflight_ResetChangesToFallback`, `TestAuthMiddleware_GatewayCORSPreflightStillRejectsPartialAuth`, `TestAuthorizationMiddleware_GatewayCORSScopesAndManagement` — local OPTIONS, empty-store behavior and scoped public exception. |
| Unit — actual responses (no tag) | `TestCORSMiddleware_EncryptedAndProxyHeaders`, `TestCORSMiddleware_UnmatchedOriginStripsUpstream`, `TestCORSMiddleware_ErrorAndHEADResponses`, `TestCORSMiddleware_CredentialsWildcardEchoAndVary`, `TestCORSMiddleware_StreamingOptionalInterfaces`, `TestCORSMiddleware_StoreDownNeverFallsBack`, `TestCORSMiddleware_NoOriginStripsBackendCORS` — ETag, override, streaming, wildcard credentials and errors. |
| Unit — reload/chart (Go: no tag; chart: shell) | `TestConfigChangeApplier_RejectsCORSHotReloadBeforeMutation`, `TestGatewayCORS_PersistenceWarningIsAdvisory`, shell `TestChart_GatewayCORSValkeyAndFallback` — advisory durability warning, startup/render constraints and restart-only changes (chart shell via distinct command). |
| Integration — real provider (tag `conformance`) | `testS3Compat_GatewayCORSWithoutBackend` under `TestConformance/.../S3Compat_GatewayCORSWithoutBackend` — real S3 provider and Valkey fixture with proxy backend CORS calls blocked; signed upload + multipart + replica behavior. Existing tests keep default passthrough. |
| Fuzz (no tag) | `FuzzParseCORSXML_NoPanic` — fuzz body decode; seed with valid/invalid CORS XML. Run normal seed corpus via `make test`; extended fuzz campaign is not a mandatory acceptance gate. |
| Negative / race (no tag) | `TestValkeyCORSStore_ReplicaVisibilityAndNoTTL`, `TestCORSMiddleware_StreamingOptionalInterfaces` — concurrent cross-replica writes/reads and streaming verified in single Tier 1 `make test` race gate. |

Critical new `internal/api` CORS code target ≥ 85% statement/branch-informed
coverage (measure named CORS files with package cover profile; do not run a
second broad coverage suite). Conformance harness tests use
`//go:build conformance`; no HSM or FIPS-specific code is added.

### Validation Matrix

| Command | Purpose | Tier | Owner | Run when |
|---|---|---|---|---|
| `go test -count=1 ./internal/api ./internal/config -run '^(Test.*CORS|Test.*Cors)$'` | Fast named regression feedback, not acceptance | 1 | implementation worker | After API/config edits only |
| `bash helm/s3-encryption-gateway/scripts/test-chart.sh` | Chart rendering/schema including CORS guard (distinct from Go suites) | chart | implementation worker | After final Helm edit |
| `set -o pipefail; make test 2>&1 \| tee /tmp/opencode/GH-322-make-test.log >/dev/null` | Full Tier 1, race and aggregate coverage | 1 | coordinator | Once after last relevant edit; first broad gate |
| `set -o pipefail; make test-conformance 2>&1 \| tee /tmp/opencode/GH-322-make-test-conformance.log >/dev/null` | Real-provider local + configured external conformance | 2 | coordinator | Once after passing `make test`, after last edit |

For non-orchestrated implementation, the person running final validation owns
both broad gates. The final verifier consumes recorded logs unless a relevant
edit occurs after them or results are missing/failed; do not re-run a parallel
full suite. Inspect logs only on failure or for concise evidence.

**Commands to verify locally** (exactly the matrix budget):

```bash
go test -count=1 ./internal/api ./internal/config -run '^(Test.*CORS|Test.*Cors)$'
bash helm/s3-encryption-gateway/scripts/test-chart.sh
set -o pipefail; make test 2>&1 | tee /tmp/opencode/GH-322-make-test.log >/dev/null
set -o pipefail; make test-conformance 2>&1 | tee /tmp/opencode/GH-322-make-test-conformance.log >/dev/null
```

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Valkey without persistence or a recoverable backup loses API-mutated CORS rules on reset; browser uploads break even though readiness can pass | Prominently publish AOF/RDB-on-retained-storage and tested backup/restore as pre-enable requirements; advisory startup warning if persistence disabled/unverifiable; no TTL; detect via authorized GET of a known configured bucket and restore/re-apply. |
| An empty-but-healthy Valkey makes broad fallback apply to formerly restricted buckets | Document fallback as an availability/security tradeoff; exercise reset test against strict bucket rules, check impact before enabling fallback, and verify restored rules on all replicas. |
| Stale rules survive bucket deletion and expose a recreated bucket | Remove policy on successful gateway deletion and before creation, preserve rules on failed deletion; test bucket-name reuse, document out-of-band lifecycle restriction. |
| Backend or middleware copies a permissive CORS header on a denied/unmatched response | Reconcile `Access-Control-*` immediately before writing status/body, stripping upstream headers on every gateway-mode S3 response; exercise errors and streams. |
| Reflecting attacker-controlled Origin or requested header injects response data | Validate exact Origin and HTTP field-name syntax before echo; reject multiple/CRLF/malformed values; wildcard+credentials must echo concrete origin. |
| Valkey outage makes gateway mode silently fall back to broad global policy | Distinguish `ErrCORSNotFound` from `ErrCORSUnavailable`; 503 preflight/management, no CORS authorization headers on actual response; readiness fails. |
| Unexpected S3 API regression for deployments with native CORS | Default passthrough; preserve existing provider CORS and preflight tests and no Valkey dependency in that mode. |
| Rolling or hot reload creates inconsistent CORS decisions across replicas | Reject hot-reload of CORS settings; require coordinated gateway-mode rollout with shared external Valkey and validate Helm wiring. |

## 8. Definition of Done

- [x] Per `docs/issues/GH-322.md:9-45`, default passthrough is unchanged and
  gateway mode requires shared Valkey.
- [x] Gateway `?cors` GET/PUT/DELETE does not forward to backend; GET/PUT and
  DELETE enforce current read/manage bucket authorization, and incorrect or
  missing bucket does not produce a ghost record.
- [x] XML validates size, namespace, rule order/count, patterns and optional
  Content-MD5; invalid PUT leaves prior policy unchanged.
- [x] Matched OPTIONS returns 200 and documented headers without a backend
  request; unmatched/malformed/store-down OPTIONS follows §3.3 error table;
  signed/partial-auth and out-of-scope OPTIONS cannot bypass gates.
- [x] Actual encrypted PUT/UploadPart/CompleteMultipartUpload, GET/HEAD,
  plaintext/passthrough, and error responses apply first-match policy; `ETag`
  readable only when exposed; upstream Access-Control-* cannot override it.
- [x] `allow_credentials` is false by default, applies to both bucket and
  fallback matches when enabled, and never emits `Allow-Origin: *` with
  credentials. Origins/headers are syntax-checked before reflection.
- [x] Fallback requires explicit origins and methods, applies only to a
  genuinely missing per-bucket document, and is never returned by GET `?cors`.
- [x] Valkey CORS records have no TTL and share the existing client; rules are
  visible across replicas; store failure and corruption never broaden access;
  readiness covers connectivity but is not claimed to prove durable state.
- [x] Gateway-mode startup emits a prominent **advisory** warning for disabled
  or unverifiable AOF/RDB persistence and continues with a working Valkey;
  neither startup nor readiness claims backups are recoverable.
- [x] Reset/recovery tests show lost policy yields `NoSuchCORSConfiguration`
  and denied preflight without fallback, may activate broader explicit
  fallback, and policy returns after restoring XML; no use of real `FLUSHALL`.
- [x] README, chart README/values, example config, ADR, deployment guide,
  runbook and release notes explicitly warn **before opting in** that Valkey
  persistence plus tested backup/restore is essential in gateway CORS mode;
  default passthrough does not acquire this durability requirement.
- [x] Operator guidance says runtime `PUT/DELETE ?cors` mutations are not
  reloaded from files, distinguishes transient 503 outage from empty-store
  404/reset, warns readiness may pass after data loss, and includes recovery
  by backup restore or authenticated XML re-application on every replica.
- [x] Successful bucket deletion and new bucket creation cannot inherit stale
  rules; failed deletion and CreateBucket on an existing bucket retain the
  existing policy; out-of-band lifecycle caveat is documented.
- [x] CORS configuration hot reload is rejected without partial mutation;
  Helm gateway mode fails validation without Valkey; replicas must use one
  shared external Valkey for production and rollout together.
- [x] `internal/api` new CORS code coverage ≥ 85% using the Tier 1 coverage
  artifact; no HSM requirement. `docs/adr/0019-gateway-managed-cors.md`,
  `README.md`, `docs/S3_API_IMPLEMENTATION.md`,
  `helm/s3-encryption-gateway/README.md`, `config.yaml.example`,
  `docs/OPS_DEPLOYMENT.md`, `docs/RUNBOOK.md` and `CHANGELOG.md`
  (`v1.0 – Unreleased`) describe the implemented contract.
- [x] Helm chart tests pass; one `make test` and then one
  `make test-conformance` pass with logs at §6 paths after the final edit.

## 9. Milestones & Estimated Effort

| Phase | Output | Effort |
|---|---|---|
| A | Config/validation, reload guard and ADR | 1.0 d |
| B | Strict XML parser/matcher and shared store + reset/restore tests | 2.0 d |
| C | Management handlers, preflight and auth regressions | 2.0 d |
| D | Response-wide middleware, lifecycle and wiring | 2.0 d |
| E | Provider tests, Helm, durability/recovery docs, validation | 2.5 d |
| **Total** | | **9.5 d** |

## 10. Follow-ups / Out-of-scope items surfaced during planning

- Migration tool for importing existing backend bucket CORS configuration into
  Valkey: independent of local policy evaluation, and not safe to infer rules
  from backend preflight responses.
- Support out-of-band bucket lifecycle synchronization or a bucket-identity
  binding if direct backend administration must coexist with gateway-managed
  CORS; this plan explicitly requires gateway-mediated create/delete.

## 11. References

1. Dennis Oderwald, *Gateway-managed bucket CORS feature request #322* (GitHub, 2026) — user scenario and proposal.
    <https://github.com/cloud37/s3-encryption-gateway/issues/322>
2. Amazon Web Services, *PutBucketCors* (AWS, 2026) — 64 KiB XML and first-rule matching contract.
    <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html>
3. MDN Contributors, *Cross-Origin Resource Sharing (CORS)* (MDN, 2026) — preflight, actual response, credentials and `Vary` behavior.
    <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS>
4. Valkey Authors, *Persistence* (Valkey, 2026) — AOF/RDB durability and backup guidance.
    <https://valkey.io/topics/persistence/>
5. Amazon Web Services, *Elements of a CORS configuration* (AWS, 2026) — S3 origin/method/header wildcard rules and 100-rule bound.
    <https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html>
