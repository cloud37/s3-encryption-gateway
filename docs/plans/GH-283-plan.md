# GH-283 — Support AWS CLI CRC64NVME Upload Trailers — Implementation Plan

Status: Verified Complete
Owner: API / Compatibility
Priority: P1
Labels: `area:api`, `area:compatibility`, `type:bug`

> Scope clarified relative to the Summary, Tests, and Definition of Done in
> `docs/issues/GH-283.md`. The local tracker entry was created from the
> maintainer-supplied analysis because no `docs/issues/GH-283.md` existed; this
> plan expands that analysis into a full implementation specification.

---

## 1. Context & Current State

The gateway recognizes trailer-bearing AWS streaming bodies and verifies them
before exposing a seekable body downstream. `verifyAndSpoolAWSBody` parses the
stream into a mode-0600 temporary file, invokes trailer verification, cleans up
on failure, and rewinds on success (`internal/api/verified_aws_body.go:81-148`).
Trailer declarations are deliberately fail-closed: each declared name must be
lowercase, unique, syntactically valid, non-forbidden, and in a checksum allow
list (`internal/api/aws_chunked_trailer.go:24-48`). This pre-storage integrity
boundary must remain intact.

The allow list currently contains only CRC32, CRC32C, SHA-1, and SHA-256
(`internal/api/aws_chunked_trailer.go:37-42`). Its checksum pass seeks to the
start of the verified body, incrementally feeds all four hashers from a 32 KiB
buffer, validates decoded widths and values, and returns
`ErrSignatureMismatch` for malformed or mismatched checksums
(`internal/api/aws_chunked_trailer.go:147-215`). Consequently, the
`x-amz-checksum-crc64nvme` declaration used by current AWS CLI uploads is
rejected at the allow-list check before the body can reach outbound PutObject.
AWS documents CRC64NVME as AWS CLI v2's default upload checksum [1] and S3's
trailing-checksum contract [2].

Unit coverage mirrors the four-algorithm limitation: the positive table builds
values for exactly those algorithms (`internal/api/aws_chunked_reader_test.go:428-459`),
while branch tests enumerate the same four mismatch cases
(`internal/api/sec41_r7_coverage_test.go:243-246`). The implementation already
depends indirectly on `github.com/minio/crc64nvme` v1.1.1
(`go.mod:103`), whose `New` function returns a streaming `hash.Hash64` and whose
`Sum` representation is eight-byte big-endian [3]. Using that implementation
avoids buffering the object or introducing a local polynomial implementation.

The real-tool compatibility runner remains pinned to AWS CLI 2.22.0 in both
AWS CLI runner types (`test/conformance/compat_runners.go:61-92`). Its basic
runner executes `aws s3 cp` for upload and download plus HEAD, LIST, and DELETE
(`test/conformance/compat_runners.go:68-83`), but that old image predates the
reported default CRC64NVME request. The compatibility matrix therefore
certifies only 2.22 (`docs/SDK_COMPATIBILITY.md:24-46`) and incorrectly describes
“all four” trailer checksums (`docs/SDK_COMPATIBILITY.md:126-132`).

Image maintenance is also inconsistent. Garage is explicitly pinned to v2.3.0
(`test/provider/garage.go:73-86`), but RustFS and SeaweedFS use mutable `latest`
tags (`test/provider/rustfs.go:94-106`, `test/provider/seaweedfs.go:108-141`).
Compatibility tools are literal Go strings—AWS CLI, s5cmd, and rclone among
them (`test/conformance/compat_runners.go:61-67,128-168`)—while the current
Renovate configuration contains only a Go toolchain package rule and no custom
manager for Go-source image references (`renovate.json:1-18`). Therefore
Renovate cannot reliably discover these pins, and mutable providers can change
without a reviewable PR. The existing workflow already runs both the full local
provider matrix and the SDK/tool compatibility matrix on every pull request
(`.github/workflows/conformance.yml:58-117`); making image updates explicit
Renovate PRs turns those jobs into the required forward-compatibility gate.

The reporter's latest answer adds a separate observation: root `aws s3 ls`
returns the gateway's generic 502 when `GW_CRED_0_PERMISSIONS=rw` and/or
`GW_CRED_0_BUCKET_PERMISSIONS=create,delete` is explicitly configured [6].
Those values do not override one another in the current model: environment
loading stores object permission and bucket lifecycle grants in separate fields
(`internal/config/config.go:1820-1876`), and validation accepts `rw`, `create`,
and `delete` (`internal/config/config.go:831-861`). ListBuckets explicitly
accepts either `ro` or `rw` and does not inspect `BucketPermissions`
(`internal/api/authorization.go:43-49`, `internal/api/handlers.go:6180-6190`).

The exact reported response text—“The upstream S3 backend returned an
error”—is emitted only when `forwardToBackend` returns an error
(`internal/api/handlers.go:6191-6194`). A backend non-2xx response is proxied,
while unreadable, oversized, or malformed success XML uses the distinct
“invalid response” message (`internal/api/handlers.go:6196-6227`). Therefore
the new evidence indicates a backend request construction, signing, endpoint,
or transport failure correlated with deployment configuration—not an
authorization denial and not AWS-chunked parsing. The handler currently drops
the underlying forwarding error without logging it, so the access log alone
cannot distinguish those causes. An explicitly present empty
`GW_CRED_0_BUCKETS` is another relevant configuration trap: it intentionally
becomes an empty/deny-all scope (`internal/config/config.go:1829-1839`) and
would filter a successful ListBuckets response to an empty list
(`internal/api/handlers.go:6229-6239`), but it should not produce this 502.

## 2. Design Goals & Non-Goals

### Goals

1. **AWS CLI compatibility** — accept the exact default CRC64NVME
   AWS-chunked upload emitted by AWS CLI 2.34.32.
2. **Fail-closed integrity** — reject invalid base64, any decoded width other
   than eight bytes, and checksum mismatches before storage or forwarding.
3. **Streaming computation** — calculate CRC-64/NVME incrementally during the
   existing bounded-buffer spool verification pass, without loading the object
   into memory or adding another body pass.
4. **Regression preservation** — retain the existing strict declaration,
   duplicate, framing, and four-checksum behavior unchanged.
5. **Reproducible compatibility proof** — pin both AWS CLI runners to an
   explicit current version no older than the reported failing 2.34.32 and
   exercise default `aws s3 cp` without disabling checksum calculation.
6. **Accurate documentation** — certify the selected AWS CLI version (at least
   2.34.32) and describe all five checksum trailers accepted by the gateway.
7. **Continuous image currency** — replace mutable tags with explicit release
   pins and make every maintained conformance provider/client image discoverable
   by Renovate's Docker datasource.
8. **PR-gated upgrades** — each Renovate image update is reviewable and must
   pass the existing conformance and compatibility matrix jobs before merge.

### Non-Goals

1. **Additional new AWS checksum families** — SHA-512 and XXHash trailers are
   not required for #283 and need separate dependency, protocol, and test
   assessment.
2. **Multiple Content-Encoding values** — accepting forms such as
   `aws-chunked, gzip` is a distinct parser-policy change; the current exact
   check remains at `internal/api/verified_aws_body.go:73-79`.
3. **V1.0-S3-7: the reported root `aws s3 ls` 502** — ListBuckets has no upload body and
   cannot traverse this verifier. The latest `GW_CRED_0_PERMISSIONS` /
   `GW_CRED_0_BUCKET_PERMISSIONS` correlation does not change that boundary;
   investigate it separately with the complete effective environment and the
   currently unlogged `forwardToBackend` error. Do not change `rw`, `create`,
   or `delete` semantics as part of this checksum fix.
4. **Forwarding client checksum headers to the backend** — this issue verifies
   inbound plaintext integrity; existing outbound PutObject construction is
   unchanged.
5. **Moving image tags** — `latest`, `edge`, `nightly`, and equivalent mutable
   tags are forbidden for maintained test images; Renovate advances explicit
   release pins through PRs instead.
6. **Reviving MinIO image maintenance** — MinIO is retained as a frozen legacy
   baseline because upstream no longer publishes normal community releases; it
   is explicitly excluded from this update policy.

## 3. Target Interface / Semantics / Behaviour

### 3.1 Accepted trailer contract

The existing private function signatures remain unchanged:

```go
func verifyAWSTrailers(
    b *bufio.Reader,
    body *os.File,
    declaration string,
    signing *V4SigningContext,
    mode streamingPayloadMode,
    final [32]byte,
) error

func verifyTrailerChecksums(body *os.File, values map[string]string) error
```

`verifyAWSTrailers` must add `x-amz-checksum-crc64nvme` to the exact lowercase
allow list. All current declaration requirements remain mandatory; support for
CRC64NVME does not permit unknown `x-amz-checksum-*` names.

| Trailer | Decoded width | Calculation | Byte representation | Failure |
|---|---:|---|---|---|
| `x-amz-checksum-crc32` | 4 | IEEE CRC-32 | big-endian | `ErrSignatureMismatch` |
| `x-amz-checksum-crc32c` | 4 | Castagnoli CRC-32C | big-endian | `ErrSignatureMismatch` |
| `x-amz-checksum-crc64nvme` | 8 | CRC-64/NVME | big-endian | `ErrSignatureMismatch` |
| `x-amz-checksum-sha1` | 20 | SHA-1 | digest bytes | `ErrSignatureMismatch` |
| `x-amz-checksum-sha256` | 32 | SHA-256 | digest bytes | `ErrSignatureMismatch` |

The trailer value must use padded standard base64. Decoding failure, decoded
width mismatch, or value mismatch is indistinguishable at the HTTP boundary and
returns the existing checksum-integrity error. This preserves the fail-closed,
low-information error surface used by the four existing algorithms.

### 3.2 CRC64NVME computation

```go
crc64h := crc64nvme.New()

// In the existing body-read loop, for every n > 0:
_, _ = crc64h.Write(buf[:n])

if v, ok := values["x-amz-checksum-crc64nvme"]; ok {
    want, err := base64.StdEncoding.DecodeString(v)
    got := crc64h.Sum(nil) // exactly 8 bytes, big-endian
    if err != nil || len(want) != crc64nvme.Size || !hmac.Equal(want, got) {
        return ErrSignatureMismatch
    }
}
```

The hasher is created once per verification and fed in the same loop as the
existing hashers. `hmac.Equal` retains the existing uniform comparison style;
the checksum is not secret, but using one comparison pattern avoids divergent
validation behavior. The package's documented `Sum` layout is already the
required network representation [3], so no manual byte reversal is permitted.

### 3.3 Dependency and compatibility contract

Move `github.com/minio/crc64nvme v1.1.1` from the indirect require block into
the direct require block because production code will import it. Do not change
the version or hand-edit `go.sum`; run `go mod tidy` after adding the import.

Both `awscliRunner.Image` and `awscliCopyMetadataRunner.Image` must return one
shared, explicit AWS CLI release tag. At implementation time use the newest
published stable tag (currently `amazon/aws-cli:2.36.40`, and never below
2.34.32). The ordinary runner's upload command must remain a plain `aws s3 cp`
with no `--checksum-algorithm` and no
`AWS_REQUEST_CHECKSUM_CALCULATION=WHEN_REQUIRED`, ensuring conformance proves
the CLI's default CRC64NVME path rather than a forced substitute.

### 3.4 Maintained image and Renovate contract

Every maintained Docker image used by conformance or integration fixtures must
have one canonical Go constant per Go package/build-tag boundary, an explicit
versioned release tag, and an adjacent annotation in this form:

```go
// renovate: datasource=docker depName=amazon/aws-cli versioning=docker
const awsCLIImage = "amazon/aws-cli:2.36.40"
```

`renovate.json` must define a `customManagers` regex manager limited to Go test
source paths. It must capture `datasource`, `depName`, optional `versioning`, and
`currentValue` from the annotation plus following constant. Use Renovate's
`docker` datasource and `docker` versioning so prefixes such as `v` and suffixes
such as `-alpine` remain valid [4]. One annotation is the source of truth for
each image within a package; duplicate users in that package reference its
constant rather than carrying independently drifting tags. Versioned tags are
reviewable and reproducible by version, but are not described as immutable
unless a digest is also pinned.

Use standalone `const <name>Image = "repository:tag"` declarations for images
and `const <name>Version = "version"` declarations for embedded packages. The
custom managers must use `managerFilePatterns: ["/^test\\/.*\\.go$/"]` and
these RE2-compatible match shapes (JSON escaping shown):

```json
{
  "customType": "regex",
  "managerFilePatterns": ["/^test\\/.*\\.go$/"],
  "matchStrings": [
    "// renovate: datasource=(?<datasource>\\S+) depName=(?<depName>\\S+) versioning=(?<versioning>\\S+)\\s+const\\s+\\w+Image\\s*=\\s*\"[^\"]+:(?<currentValue>[^\"]+)\""
  ]
}
```

Define a second manager with the same file pattern for embedded package
versions:

```json
{
  "customType": "regex",
  "managerFilePatterns": ["/^test\\/.*\\.go$/"],
  "matchStrings": [
    "// renovate: datasource=(?<datasource>\\S+) depName=(?<depName>\\S+) versioning=(?<versioning>\\S+)\\s+const\\s+\\w+Version\\s*=\\s*\"(?<currentValue>[^\"]+)\""
  ]
}
```

Keeping the image repository outside `currentValue` ensures Renovate replaces
only the tag; the annotation's `depName` remains the Docker lookup name. These
required named captures follow Renovate's custom regex manager contract [4].

The managed image inventory includes AWS CLI, Garage, RustFS, SeaweedFS, s5cmd,
rclone, restic, Python, Valkey, OpenBao, and Cosmian KMS. These images are
exercised by the pull-request conformance suite. The boto3 and
minio-py versions installed into the Python image are independent dependencies;
annotate them for Renovate's `pypi` datasource so testing a current Python base
does not leave stale client libraries hidden inside it. Bootstrap the requested provider pins to the newest published
release tags observed during planning—Garage `v2.4.1`, RustFS
`v1.0.0-rc.5`, and SeaweedFS `4.46`—and let Renovate immediately propose any
newer release available at implementation time. Existing explicit pins for
s5cmd and other maintained tools become managed even when no bump is currently
available.

MinIO server is the sole documented lifecycle exception: retain its existing
frozen `RELEASE.2024-11-07T00-52-20Z` baseline and configure Renovate with
`enabled: false` for `minio/minio` and `quay.io/minio/minio`. This does not
exclude the maintained minio-py client package. Do not retain any MinIO
`latest` references in tests; normalize them to the frozen release so CI
remains reproducible. The example Compose file is documentation rather than a
test fixture and is outside this plan.

Renovate must open separate PRs for maintained dependencies (no aggregate
group; set `groupName: null`) and never automerge them. The repository configuration must assign the
stable labels `dependencies` and `conformance` to these PRs; use those exact
labels rather than inventing issue-style labels whose existence is unknown.
GitHub's existing pull-request workflow runs `conformance-local` and
`compat-matrix` for all four providers
(`.github/workflows/conformance.yml:58-117`); repository administrators must
retain the resulting `Conformance / <provider>` and `Compat Matrix / <provider>`
checks in the `main` branch protection rules. The workflow supplies execution;
branch protection supplies the merge gate and is verified in repository
settings rather than changed in source.

The implementation is not complete merely because annotations exist. Run the
Renovate CLI against the repository with `--platform=local --dry-run=lookup`
and debug logging, then inspect its extracted dependency table. It must resolve
the Docker/PyPI datasource and current value for every inventory entry, show
new-version lookup results, contain no extraction warnings for the custom
managers, and show MinIO server updates as disabled. Renovate's local platform
performs lookup without creating branches [5].

## 4. Work Breakdown

### Phase A — Add CRC64NVME verification

- **A1. `internal/api/aws_chunked_trailer.go` (edit):** import
  `github.com/minio/crc64nvme`; add `x-amz-checksum-crc64nvme` to
  `allowedChecksums`; instantiate `crc64nvme.New()` beside the four existing
  hashers; write every non-empty buffer segment to it in the existing loop; and
  validate the trailer as padded base64 containing exactly
  `crc64nvme.Size == 8` bytes matching `crc64h.Sum(nil)`.
- **A2. `go.mod` (edit):** promote `github.com/minio/crc64nvme v1.1.1` to the
  direct dependency block. Keep `go.sum` unchanged unless `go mod tidy`
  deterministically changes it.

### Phase B — Prove positive and negative checksum behavior

- **B1. `internal/api/aws_chunked_reader_test.go` (edit):** extend
  `TestAWSChunkedVerifier_TrailerChecksums` with a CRC64NVME positive table row
  calculated independently via `crc64nvme.Checksum` and encoded as an explicit
  eight-byte big-endian array. Assert the verified spool yields the original
  body, as for all other algorithms.
- **B2. `internal/api/aws_chunked_reader_test.go` (edit):** add
  `TestAWSChunkedVerifier_CRC64NVMERejectsMalformedAndMismatch`, table-driven
  over invalid base64, decoded lengths of 7 and 9 bytes, and a well-formed
  eight-byte checksum for different content. Every case must assert
  `errors.Is(err, ErrSignatureMismatch)` rather than merely non-nil failure.
- **B3. `internal/api/sec41_r7_coverage_test.go` (edit):** include
  `x-amz-checksum-crc64nvme` in the existing mismatch enumeration in
  `TestSEC41R7TrailerValidationBranches`, preserving branch coverage parity
  across the complete allowed set.

> Phase B depends on the accepted name and verifier introduced in Phase A.

### Phase C — Upgrade real AWS CLI compatibility coverage

- **C1. `test/conformance/compat_runners.go` (edit):** introduce
  an annotated shared `awsCLIImage` constant using the newest stable tag
  (currently `amazon/aws-cli:2.36.40`, minimum 2.34.32) near the runner definitions
  and return it from both AWS CLI runner `Image` methods. Keep the basic
  runner's unqualified `aws s3 cp` command unchanged so it emits its default
  checksum.
- **C2. `test/conformance/compat_runner_test.go` (edit):** add
  `TestAWSCLIRunners_PinCRC64NVMEVersion`, asserting both runner types return
  the shared, explicitly versioned image, its parsed version is at least
  2.34.32, and `awscliRunner.Script` contains no checksum downgrade/disable
  override. This file has no build constraint, so the guard is Tier 1 and must
  run under ordinary `go test ./...` without Docker. The actual upload remains
  the Docker-backed `TestConformance/<provider>/Compat_AWSCLI` registration at
  `test/conformance/suite_test.go:335-337`.

> Phase C can be reviewed independently of Phases A-B, but its conformance test
> is expected to fail until CRC64NVME verification is implemented.

The existing AWS CLI script's `aws s3 ls s3://<bucket>/ --recursive` is
ListObjectsV2, not the reporter's root `aws s3 ls` ListBuckets request
(`test/conformance/compat_runners.go:68-83`). Do not add root ListBuckets to
this CRC64NVME acceptance test: doing so would couple closure of the confirmed
upload fix to an independently failing backend-forwarding path. The separate
follow-up must add its own root-list regression with explicit environment-loaded
credential variants.

### Phase D — Make maintained test images Renovate-managed

- **D1. `test/conformance/compat_runners.go` (edit):** replace literal image
  returns with one annotated constant per maintained image and reuse constants
  across runner variants. Cover AWS CLI, Python, s5cmd, rclone, and restic.
  Replace inline `boto3==1.35.0` and `minio==7.2.0` literals with annotated Go
  constants consumed by the generated shell scripts, using Renovate's `pypi`
  datasource and `pep440` versioning.
- **D2. `test/conformance/rclone_ncdu_benchmark_test.go` (edit):** use the
  shared rclone image pin rather than a separate literal.
- **D3. `test/provider/garage.go` (edit):** define an annotated Garage image
  constant and bootstrap it to `dxflrs/garage:v2.4.1`.
- **D4. `test/provider/rustfs.go` (edit):** replace `latest` and its stale
  comments with an annotated `rustfs/rustfs:v1.0.0-rc.5` constant. Configure
  Renovate to consider prereleases for this dependency while RustFS has no
  stable release line.
- **D5. `test/provider/seaweedfs.go` (edit):** replace `latest` and its stale
  comments with an annotated `chrislusf/seaweedfs:4.46` constant.
- **D6. `test/provider/openbao.go`, `test/provider/cosmian.go`,
  `test/provider/valkey.go`, and `test/provider/minio.go` (edit):** add the same
  annotation contract to existing explicit pins, introduce a Valkey constant,
  and collapse both frozen MinIO server literals into one annotated
  package-local constant whose Renovate package rule is disabled.
- **D7. `test/integration/images.go` (new):** under the existing legacy
  `integration` build tag, define package-wide versioned image constants for
  Azurite and the frozen MinIO server baseline. This is production-free fixture
  configuration, not a new test or tier. The MinIO constant is annotated so it
  is extracted and disabled, proving the exception is effective. Do not include
  Azurite in the Renovate managed inventory in this issue because this legacy
  suite is outside the authoritative Tier 1/2/3 PR matrix.
- **D8. `test/integration/azure_test.go`,
  `test/integration/audit_integration_test.go`, and
  `test/integration/selfcontained_test.go` (edit):** replace all `latest`
  literals with the package-wide constants from D7.
- **D9. `renovate.json` (edit):** add the Go-source regex custom manager and
  package rules that (a) use Docker lookup, (b) keep update PRs separate,
  (c) disable automerge, (d) apply `dependencies` and `conformance` labels,
  (e) allow RustFS prereleases with `ignoreUnstable: false`, (f) explicitly
  disable MinIO server updates, and (g) extract the annotated boto3/minio
  Python package versions.
- **D10. `scripts/check-test-image-pins.sh` (new):** scan `test/**/*.go` and
  fail if a container image uses `latest`/another mutable channel, if a
  maintained image constant lacks the Renovate annotation, if duplicate
  literals bypass the canonical constant within a package, or if the MinIO
  exception differs from the frozen baseline. Parse the declared inventory and
  assert every expected Docker and PyPI dependency has exactly one matching
  Renovate annotation per package; do not merely grep for the word `renovate`.
- **D11. `.github/workflows/conformance.yml` (edit):** run
  `scripts/check-test-image-pins.sh` in the always-on `isolation-check` job.
  Keep `conformance-local` and `compat-matrix` unchanged as mandatory PR jobs;
  Renovate PRs already trigger both at `pull_request`.
- **D12. Renovate extraction/lookup verification (validation only):** run a
  Renovate CLI 44.69.9 locally with `LOG_LEVEL=debug`,
  `--platform=local`, `--dry-run=lookup`, and
  `--repository-cache=reset`; save output to
  `/tmp/opencode/GH-283-renovate-lookup.log`. Confirm every Docker/PyPI
  inventory item is assigned the intended datasource/current value, registry
  lookup succeeds, available updates are reported, and MinIO server updates
  are disabled. This command proves the custom manager actually works; the
  repository guard only prevents annotation/pin drift.

### Phase E — Documentation and tracking

- **E1. `docs/SDK_COMPATIBILITY.md` (edit):** change the matrix and image-policy
  rows from AWS CLI 2.22/2.22.0 to the selected current pin; document that
  maintained images use explicit Renovate-managed pins; change “all four supported checksum
  trailers” to “all five supported checksum trailers”; and list CRC64NVME,
  CRC32, CRC32C, SHA-1, and SHA-256 explicitly.
- **E2. `CHANGELOG.md` (edit):** under `Unreleased` → `Fixed`, record that issue
  #283 restores current AWS CLI upload compatibility by validating default
  CRC64NVME AWS-chunked trailers and adds Renovate-gated image updates.
- **E3. `docs/issues/GH-283.md` (edit):** after implementation and independent
  verification, update status and check only criteria supported by test logs.
- **E4. `docs/TESTING.md` (edit):** update the local-provider image table and
  compatibility-client examples to the selected explicit pins. Preserve the
  tier taxonomy: no Docker-backed test may be described as Tier 1, and the
  legacy `integration`-tagged Azurite fixture must remain explicitly identified
  as outside the PR conformance gate until it is migrated in the follow-up.
  Correct existing drift while touching the table: all four local providers,
  not MinIO alone, run in the PR gate, and the provider-neutral AST guard lives
  in `test/conformance/matrix_guard_test.go`.

## 5. Affected Files

### Direct edits

- `internal/api/aws_chunked_trailer.go` — accept and stream-verify CRC64NVME.
- `internal/api/aws_chunked_reader_test.go` — positive, malformed-width/base64,
  and mismatch regressions.
- `internal/api/sec41_r7_coverage_test.go` — include CRC64NVME in rejection
  branch coverage.
- `go.mod` — promote the CRC64NVME module to a direct dependency.
- `go.sum` — only if changed by `go mod tidy`.
- `test/conformance/compat_runners.go` — centralize and annotate compatibility
  image and embedded Python-client versions.
- `test/conformance/compat_runner_test.go` — guard image and default-checksum
  test semantics.
- `test/conformance/rclone_ncdu_benchmark_test.go` — reuse the package's rclone pin.
- `test/provider/garage.go` — update and annotate the Garage image pin.
- `test/provider/rustfs.go` — replace `latest` with an annotated release pin.
- `test/provider/seaweedfs.go` — replace `latest` with an annotated release pin.
- `test/provider/openbao.go` — annotate the OpenBao image pin.
- `test/provider/cosmian.go` — annotate the Cosmian KMS image pin.
- `test/provider/valkey.go` — centralize and annotate the Valkey image pin.
- `test/provider/minio.go` — centralize the frozen MinIO image baseline and annotate its disabled dependency.
- `test/integration/azure_test.go` — replace Azurite `latest` with a versioned release pin.
- `test/integration/audit_integration_test.go` — use the frozen MinIO server baseline.
- `test/integration/selfcontained_test.go` — use the frozen MinIO server baseline.
- `renovate.json` — extract Docker/PyPI pins and define update policy.
- `.github/workflows/conformance.yml` — enforce the image-pin inventory policy.
- `docs/SDK_COMPATIBILITY.md` — update certified version and checksum list.
- `docs/TESTING.md` — synchronize documented provider pins and accurately state
  which fixtures execute in Tier 2 CI.
- `CHANGELOG.md` — add the issue #283 fix under Unreleased.
- `docs/issues/GH-283.md` — track implementation and verification state.

### New files

- `docs/issues/GH-283.md` — local tracker source imported from issue #283.
- `docs/plans/GH-283-plan.md` — this implementation plan.
- `scripts/check-test-image-pins.sh` — deterministic maintained-dependency policy guard.
- `test/integration/images.go` — package-wide pins for legacy integration fixtures; no test is added outside the Tier 1/2/3 taxonomy.

## 6. Test Strategy

The test placement follows `docs/TESTING.md`: Tier 1 tests have no build tag and
must not start Docker; Tier 2 tests use only the `conformance` build tag, start
providers through Testcontainers, use random mapped ports, and skip with a
fixture-specific `t.Skip` message when Docker is unavailable. Each test belongs
to exactly one tier. Conformance test bodies must remain provider-neutral and
may gate only through capability bits; they must not branch on provider names.

The unit tests exercise the complete wire-level request through
`verifyAndSpoolAWSBody`, not only the hash helper. Conformance then proves that
the pinned real AWS CLI emits a request the gateway accepts against each
registered provider. No benchmark or fuzz target is required: the new hasher
shares an existing bounded-buffer loop, does not alter parser state, and adds no
new input grammar.

| Layer | Tests |
|---|---|
| Unit — positive protocol | `TestAWSChunkedVerifier_TrailerChecksums` — adds CRC64NVME to the existing five-algorithm table and asserts accepted data is rewound and byte-identical; no build tag. |
| Unit — error surface | `TestAWSChunkedVerifier_CRC64NVMERejectsMalformedAndMismatch` — invalid base64, 7-byte, 9-byte, and incorrect 8-byte values all return `ErrSignatureMismatch`; no build tag. |
| Unit — branch parity | `TestSEC41R7TrailerValidationBranches` — CRC64NVME participates in the generic mismatch rejection enumeration; no build tag. |
| Unit — runner contract | `TestAWSCLIRunners_PinCRC64NVMEVersion` — both AWS CLI runners share an explicit version at least 2.34.32 and the basic script does not suppress default integrity protection; no build tag and no Docker. |
| Structural policy | `scripts/check-test-image-pins.sh` — every declared managed Docker/PyPI dependency has the expected Renovate annotation, all test images have versioned non-channel tags, duplicate package-local literals are absent, and MinIO uses only its frozen baseline; deterministic shell check, not a Go test tier. |
| Renovate lookup | Renovate local `lookup` dry-run — resolves each annotated dependency and current value through Docker/PyPI, reports available updates, and confirms the MinIO server exclusion; network required, no PR created. |
| Tier 2 — conformance | `TestConformance/<provider>/Compat_AWSCLI` via `testCompatSmoke_AWSCLI` — the selected AWS CLI version performs default-checksum PutObject, HeadObject, GetObject, ListObjectsV2, and DeleteObject against every provider advertising `CapCLIAWSCLI`; `conformance` build tag and Docker required. The body contains no provider-name branch, and Docker/provider startup failure skips with the missing fixture named. |
| Negative / race | The new unit paths execute under the `-race` run in `make test`; no shared mutable state is introduced. |

The three pre-existing legacy files under `test/integration/` retain their
`integration` build tag in this issue only to replace mutable image references;
this plan adds no test under that tag and does not claim those files as Tier 2
or compatibility evidence. Azurite remains excluded from Renovate updates until
a follow-up migrates its Docker test into the `conformance` tier and PR gate.
The frozen MinIO replacement is a static reproducibility change covered by the
structural policy check; MinIO behavior is already exercised by the registered
Tier 2 provider.

New CRC64NVME branches in `internal/api/aws_chunked_trailer.go` must have 100%
positive and rejection-path coverage; the critical `internal/api` package must
remain at or above 85% statement coverage in the repository's aggregate
coverage report.

### Validation Matrix

| Command | Purpose | Tier | Owner | Run when |
|---|---|---|---|---|
| `go test -race -count=1 ./internal/api -run '^(TestAWSChunkedVerifier_(TrailerChecksums|CRC64NVMERejectsMalformedAndMismatch)|TestSEC41R7TrailerValidationBranches)$'` | Fast protocol and negative-path regression feedback | 1 | implementation worker | After Phases A-B |
| `go test -race -count=1 ./test/conformance -run '^TestAWSCLIRunners_PinCRC64NVMEVersion$'` | Fast Tier 1 image-pin and script-contract feedback without Docker | 1 | implementation worker | After Phase C |
| `bash scripts/check-test-image-pins.sh` | Fast deterministic inventory, annotation, and mutable-tag policy check | Structural | implementation worker | After Phase D |
| `set -o pipefail; LOG_LEVEL=debug npx --yes renovate@44.69.9 --platform=local --dry-run=lookup --repository-cache=reset 2>&1 \| tee /tmp/opencode/GH-283-renovate-lookup.log >/dev/null` | Prove custom-manager extraction, Docker/PyPI lookup, update discovery, and MinIO exclusion with a reproducible Renovate CLI version | dependency lookup | implementation worker | Once after `renovate.json` and annotations are final; network required |
| `set -o pipefail; make test 2>&1 \| tee /tmp/opencode/GH-283-make-test.log >/dev/null` | Full unit, race, and aggregate coverage gate | 1 | coordinator | Once after the final implementation edit |
| `set -o pipefail; make test-conformance-local 2>&1 \| tee /tmp/opencode/GH-283-make-test-conformance-local.log >/dev/null` | PR-equivalent Tier 2 proof across MinIO, Garage, RustFS, and SeaweedFS with the selected AWS CLI and maintained compatibility clients | 2 | coordinator | Once after `make test`, after the final implementation edit, with Docker available |
| `make test-isolation-check` | Run the repository's PR-equivalent structural guard against forbidden Compose/backend subprocess and fixed-port references in its enforced scope | Structural | coordinator | Once after test fixture files are final |

### Commands to verify locally

```bash
go test -race -count=1 ./internal/api -run '^(TestAWSChunkedVerifier_(TrailerChecksums|CRC64NVMERejectsMalformedAndMismatch)|TestSEC41R7TrailerValidationBranches)$'
go test -race -count=1 ./test/conformance -run '^TestAWSCLIRunners_PinCRC64NVMEVersion$'
bash scripts/check-test-image-pins.sh
set -o pipefail; LOG_LEVEL=debug npx --yes renovate@44.69.9 --platform=local --dry-run=lookup --repository-cache=reset 2>&1 | tee /tmp/opencode/GH-283-renovate-lookup.log >/dev/null
set -o pipefail; make test 2>&1 | tee /tmp/opencode/GH-283-make-test.log >/dev/null
set -o pipefail; make test-conformance-local 2>&1 | tee /tmp/opencode/GH-283-make-test-conformance-local.log >/dev/null
make test-isolation-check
```

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Wrong CRC variant or byte order accepts/rejects incompatible values | Use the existing MinIO CRC64NVME package, pin v1.1.1, and construct test expectations as explicit eight-byte big-endian values from `Checksum`; verify with the real AWS CLI. |
| A malformed checksum is treated as an unsupported trailer or generic framing error | Add the name only to the strict allow list, then assert malformed and mismatch cases return `ErrSignatureMismatch` from checksum validation. |
| CRC64 computation adds an extra full-object read or unbounded memory | Feed the hasher inside the existing 32 KiB verification loop; prohibit `io.ReadAll` or a second CRC-only pass. |
| Updating only one AWS CLI runner leaves inconsistent certification | Share one `awsCLIImage` constant and unit-test both runner types. |
| The conformance script accidentally disables the behavior under test | Keep plain `aws s3 cp`; guard against checksum disable/downgrade configuration in the runner test. |
| The separate ListBuckets 502 is incorrectly declared fixed when CRC64NVME uploads pass | Keep root `aws s3 ls` outside GH-283 acceptance, document the distinct path and response origin, and track a dedicated environment-driven reproduction with backend error logging. |
| Promoting an indirect dependency causes unrelated module churn | Keep v1.1.1 and accept only deterministic direct/indirect placement changes from `go mod tidy`; review the module diff. |
| Existing checksum algorithms regress while adding a fifth hasher | Retain the table-driven positive suite and mismatch enumeration for all five, then run both broad gates. |
| A malformed custom-manager regex leaves a pin looking managed while Renovate never updates it | Make the policy script compare an explicit inventory to annotation matches, and require a Renovate local lookup log proving datasource assignment and update lookup. |
| A Python base image is current while boto3 or minio-py remains stale | Manage the image and each installed PyPI package as separate Renovate dependencies. |
| A Renovate PR updates only one duplicate image literal | Reuse one constant within each package/build-tag boundary and have the policy script reject unmanaged duplicate literals. |
| A new provider/client release breaks gateway compatibility | Disable automerge and require the existing four-provider conformance and compatibility jobs on every Renovate PR. |
| Renovate resumes updates for the discontinued MinIO server | Pin every test fixture to `RELEASE.2024-11-07T00-52-20Z`, disable both MinIO image names in package rules, and enforce the exception in the policy script. |

## 8. Definition of Done

- [x] Per the Summary and Tests in `docs/issues/GH-283.md`, AWS CLI 2.34.32 default
      `STREAMING-UNSIGNED-PAYLOAD-TRAILER` uploads with
      `x-amz-checksum-crc64nvme` pass verification and reach normal PutObject
      handling.
- [x] `x-amz-checksum-crc64nvme` is accepted only as an exact lowercase,
      declared trailer name under all existing strict declaration rules.
- [x] CRC-64/NVME is computed in the existing 32 KiB body pass with no
      unbounded buffering and no additional full-object pass.
- [x] Invalid base64, decoded values other than eight bytes, and well-formed
      mismatches fail closed with `ErrSignatureMismatch` before storage.
- [x] Positive and mismatch coverage includes CRC64NVME, CRC32, CRC32C, SHA-1,
      and SHA-256; new CRC64NVME branches are fully covered and
      `internal/api` remains at least 85% covered.
- [x] `github.com/minio/crc64nvme v1.1.1` is a direct dependency and module-file
      changes contain no unrelated upgrades.
- [x] Both AWS CLI compatibility runners share an explicit stable pin at least
      2.34.32, and the basic runner uses the CLI's default upload-checksum
      behavior.
- [x] AWS CLI, Garage, RustFS, SeaweedFS, s5cmd, rclone, restic, Python,
      Valkey, OpenBao, and Cosmian KMS test images have explicit versioned tags
      and Renovate Docker annotations; boto3 and minio-py have separate PyPI
      annotations, and the non-PR-gated Azurite fixture is explicitly pinned
      without claiming continuous compatibility coverage.
- [x] `scripts/check-test-image-pins.sh` passes and rejects mutable image tags,
      missing/duplicate inventory annotations, package-local duplicate image
      literals, and divergence from the frozen MinIO baseline.
- [x] `/tmp/opencode/GH-283-renovate-lookup.log` shows successful extraction
      and lookup for every managed Docker/PyPI dependency, available upgrades
      where present, no custom-manager warnings, and disabled MinIO server
      updates.
- [x] Renovate package rules keep image/client updates separate, disable
      automerge, apply `dependencies` and `conformance` labels, permit RustFS
      release candidates, and exclude only the MinIO server images.
- [x] Every Renovate update PR triggers the existing `conformance-local` and
      `compat-matrix` jobs for MinIO, Garage, RustFS, and SeaweedFS, and the
      resulting provider checks are required by `main` branch protection.
- [x] `make test` passes with evidence in
      `/tmp/opencode/GH-283-make-test.log`.
- [x] `make test-conformance-local` passes with evidence in
      `/tmp/opencode/GH-283-make-test-conformance-local.log`, including the
      registered `Compat_AWSCLI` case for every capable local provider.
- [x] `make test-isolation-check` passes; all new Docker-backed coverage remains
      exclusively in the `conformance` tier and uses Testcontainers with random
      mapped ports. `TestConformance_NoProviderNameLiterals` passes as part of
      `make test-conformance-local`, proving no provider-name branch was
      introduced.
- [x] `docs/TESTING.md` lists the implemented provider pins and does not claim
      that the legacy Azurite `integration` fixture is a PR conformance gate.
- [x] Any conformance failure is classified as gateway regression, fixture
      failure, or documented upstream provider gap; no failure is hidden with a
      provider-name branch or an unjustified capability removal.
- [x] `docs/SDK_COMPATIBILITY.md` certifies the selected AWS CLI pin (at least
      2.34.32), documents Renovate-managed explicit pins, and explicitly lists
      all five accepted checksum trailers.
- [x] `CHANGELOG.md` contains an Unreleased issue #283 entry, and
      `docs/issues/GH-283.md` status/checklists reflect independent verification.
- [x] No changes are made to multi-value `Content-Encoding`, the ListBuckets
      502 path, credential permission semantics, or outbound backend checksum
      semantics; release notes do not claim the root `aws s3 ls` failure is
      fixed by GH-283.

## 9. Milestones & Estimated Effort

| Phase | Output | Effort |
|---|---|---:|
| A | Production CRC64NVME verification and direct dependency | 0.25 d |
| B | Positive, malformed, width, and mismatch unit regressions | 0.50 d |
| C | Current AWS CLI pin and real-client regression guard | 0.25 d |
| D | Maintained image/client inventory, Renovate managers, and CI policy guard | 1.00 d |
| E | Compatibility docs, changelog, and tracker updates | 0.25 d |
| Validation | Focused feedback plus full unit and conformance gates | 0.50 d |
| **Total** | | **2.75 d** |

## 10. Follow-ups / Out-of-scope items surfaced during planning

1. Assess support for `Content-Encoding` lists containing `aws-chunked`
   alongside another coding (for example, `aws-chunked, gzip`) in a separate
   compatibility issue; changing `validAWSContentEncoding` is not needed for
   the AWS CLI 2.34.32 reproduction.
2. Resolve V1.0-S3-7 for the independently reproduced root `aws s3 ls` 502. Its
   regression matrix must load credentials through the actual indexed
   environment path and test: omitted versus explicit `rw`; no bucket grants
   versus `create`, `delete`, and both; absent `GW_CRED_0_BUCKETS` versus an
   explicitly empty value; and a scheme-less RustFS endpoint with
   `BACKEND_USE_SSL=false`. Assert that
   valid `ro`/`rw` reaches ListBuckets, bucket lifecycle grants do not affect
   it, absent scope returns the backend-visible buckets, and explicit empty
   scope returns HTTP 200 with an empty list. Add structured logging of the
   wrapped `forwardToBackend` error before diagnosing transport, signing, or
   endpoint construction. This supersedes the earlier assumption that GH-284
   necessarily accounts for the 502.
3. Evaluate SHA-512 and AWS CLI's XXHash trailer variants separately if client
   telemetry shows demand; #283 adds only the reported default CRC64NVME mode.
4. Evaluate digest pinning as a separate supply-chain hardening change. This
   plan uses versioned release tags so Renovate can advance versions through
   reviewable PRs, but does not claim registry tags are cryptographically
   immutable.
5. Add the `integration`-tagged Azurite test to a pull-request CI job, then add
   its image constant to the Renovate managed inventory. Updating an untested
   integration fixture automatically would not provide the compatibility gate
   required by this issue.

## 11. References

1. Amazon Web Services, *Data Integrity Protections for Amazon S3* (AWS SDKs and Tools Reference Guide, 2026) — identifies CRC64NVME as the AWS CLI v2 default upload checksum.
   <https://docs.aws.amazon.com/sdkref/latest/guide/feature-dataintegrity.html>
2. Amazon Web Services, *Checking object integrity for data uploads in Amazon S3* (Amazon S3 User Guide, 2026) — defines trailing checksum declaration and validation behavior.
   <https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html>
3. MinIO, *Package crc64nvme v1.1.1* (Go Package Documentation, 2025) — documents the streaming `hash.Hash64`, NVME polynomial, eight-byte size, and big-endian `Sum` output.
   <https://pkg.go.dev/github.com/minio/crc64nvme@v1.1.1>
4. Renovate, *Custom Manager Support using Regex* (Renovate Documentation, 2026) — defines required named captures and Docker/PyPI datasource extraction for nonstandard files.
   <https://docs.renovatebot.com/modules/manager/regex/>
5. Renovate, *Local Platform* (Renovate Documentation, 2026) — documents local extraction/lookup dry-runs without branch creation.
   <https://docs.renovatebot.com/modules/platform/local/>
6. zyrakq, *Latest reporter follow-up on issue #283* (GitHub, 2026-09-08) — reports that root ListBuckets returns 502 when explicit object/bucket permission environment values are present.
   <https://github.com/cloud37/s3-encryption-gateway/issues/283#issuecomment-5586454808>
