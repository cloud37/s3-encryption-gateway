# GH-277 — Publish Helm Chart in a Signed OCI Registry — Implementation Plan

Status: Draft
Owner: Release Engineering / Helm
Priority: P2
Labels: `area:helm`, `area:release`, `area:supply-chain`

> Scope clarified relative to the imported tracker entry at
> `docs/issues/GH-277.md:1-44`. This plan follows the maintainer decision to add
> signed GHCR publication without replacing the classic GitHub Pages repository.

---

## 1. Context & Current State

The chart is an application chart named `s3-encryption-gateway`, currently at
version `0.12.0-rc2` (`helm/s3-encryption-gateway/Chart.yaml:1-3,38-39`). The
release workflow runs for changes under `helm/**`, lints and renders the chart
(`.github/workflows/helm.yml:23-50`), then uses chart-releaser to create a GitHub
release and update the classic repository (`.github/workflows/helm.yml:83-115`).
No step logs in to GHCR, invokes `helm push`, or publishes a Helm OCI manifest.

The release job currently has `contents`, `pages`, and OIDC permissions
(`.github/workflows/helm.yml:52-60`). It already installs cosign and performs
keyless signing of the Docker image by digest
(`.github/workflows/helm.yml:260-272`), so the repository has an established
GitHub Actions OIDC signing model. It lacks `packages: write`, which GHCR
publication through `GITHUB_TOKEN` requires. The workflow's version guard skips
release-producing steps when the matching GitHub release already exists
(`.github/workflows/helm.yml:83-98`), and the new OCI publication must use that
same immutable-release decision rather than overwrite a tag independently.

Helm OCI push infers the artifact basename and tag from `Chart.yaml`; pushing
`s3-encryption-gateway-<version>.tgz` to `oci://ghcr.io/cloud37` therefore creates
`ghcr.io/cloud37/s3-encryption-gateway:<version>` [1]. Users then install from
`oci://ghcr.io/cloud37/s3-encryption-gateway --version <version>`, or pin the
manifest digest. GHCR can associate workflow-published packages with this
repository via `GITHUB_TOKEN`, but first publication visibility must be checked:
new packages may initially be private [3].

The chart README documents only general chart configuration and examples, with
no OCI installation or signature verification path (`helm/s3-encryption-gateway/README.md:48-122`). The requested outcome is therefore an additional,
public, digest-addressable distribution channel with verifiable keyless
provenance while retaining the current `index.yaml` channel.

## 2. Design Goals & Non-Goals

### Goals

1. **Dual publication** — every new chart release is available from both the
   existing GitHub Pages repository and `ghcr.io/cloud37/s3-encryption-gateway`.
2. **Immutable version contract** — the OCI tag exactly equals `Chart.yaml`
   `version`, and release reruns do not overwrite an already released version.
3. **Digest-bound signing** — sign the OCI manifest digest, never only a mutable
   tag, with the existing GitHub Actions keyless OIDC identity.
4. **Immediate verification** — the release job verifies the signature using
   issuer and exact workflow-identity constraints before succeeding.
5. **Least privilege** — add only `packages: write`; retain `contents: write`,
   `pages: write`, and `id-token: write` only where already needed.
6. **Usable documentation** — document versioned installation, digest-pinned
   installation, and keyless signature verification.
7. **Public consumption** — anonymous users can pull the chart from GHCR after
   package visibility is configured.

### Non-Goals

1. **Replacing GitHub Pages/chart-releaser** — explicitly excluded by the
   maintainer response and `docs/issues/GH-277.md:10-17`.
2. **Moving container images from Docker Hub to GHCR** — image distribution is
   independent and already implemented at `.github/workflows/helm.yml:179-272`.
3. **GPG `.prov` signing** — this plan standardizes on existing keyless
   Sigstore/cosign identity rather than introduce long-lived signing keys.
4. **Publishing a `latest` chart tag** — Helm chart versions are immutable and
   selected with `--version` or digest; aliases invite tag drift.
5. **Changing chart contents or application behavior** — only release plumbing
   and consumer documentation are in scope.

## 3. Target Interface / Semantics / Behaviour

### 3.1 OCI naming and release contract

| Property | Contract |
|---|---|
| Push target | `oci://ghcr.io/cloud37` |
| Resulting artifact | `ghcr.io/cloud37/s3-encryption-gateway:<chart-version>` |
| Install reference | `oci://ghcr.io/cloud37/s3-encryption-gateway --version <chart-version>` |
| Package source | `helm/s3-encryption-gateway`, after dependency build |
| Version source | `version:` in `helm/s3-encryption-gateway/Chart.yaml` |
| Publication trigger | New chart version on push to `main`/`master`, using existing `already_released == 'false'` guard |
| Classic repository | Published unchanged by chart-releaser |
| OCI mutability | No force/re-push for an existing released version |

Helm derives the OCI basename and tag from chart metadata, so the push target
must stop at the namespace and must not append the chart name or version [1].

### 3.2 Workflow contract

The release job adds `packages: write`, logs in without persisting a separate
registry secret, packages to an isolated directory, captures the digest from
the successful push, and signs the digest-qualified reference:

```yaml
permissions:
  contents: write
  pages: write
  packages: write
  id-token: write

- name: Log in to GHCR for Helm
  run: echo "${{ secrets.GITHUB_TOKEN }}" | helm registry login ghcr.io \
         --username "${{ github.actor }}" --password-stdin

- name: Package and publish OCI chart
  id: oci_chart
  run: |
    mkdir -p /tmp/opencode/helm-oci
    helm package helm/s3-encryption-gateway --destination /tmp/opencode/helm-oci
    helm push "/tmp/opencode/helm-oci/s3-encryption-gateway-${CHART_VERSION}.tgz" \
      oci://ghcr.io/cloud37
    # Resolve and expose the immutable manifest digest as chart_digest.
```

The implementation must obtain the registry-reported or resolved digest and
construct `ghcr.io/cloud37/s3-encryption-gateway@sha256:...`; it must fail if no
digest is available. Token input must not be echoed.

### 3.3 Signature and identity contract

```bash
cosign sign --yes \
  ghcr.io/cloud37/s3-encryption-gateway@sha256:<digest>

cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp \
    '^https://github\.com/cloud37/s3-encryption-gateway/\.github/workflows/helm\.yml@refs/heads/(main|master)$' \
  ghcr.io/cloud37/s3-encryption-gateway@sha256:<digest>
```

Verification is identity-constrained rather than merely checking that some
Sigstore certificate signed the artifact. Signing by digest binds the signature
to immutable content; keyless OIDC avoids a long-lived repository signing key
[2]. The exact identity must be confirmed from the certificate emitted by the
first controlled publication and then fixed to the workflow path/ref contract.

### 3.4 Consumer contract

```bash
helm install my-gateway \
  oci://ghcr.io/cloud37/s3-encryption-gateway \
  --version <version>

helm install my-gateway \
  oci://ghcr.io/cloud37/s3-encryption-gateway@sha256:<digest>
```

The README must also provide the `cosign verify` command above and retain the
classic `helm repo add` instructions. Digest installation is documented as the
strongest artifact-selection mechanism because tags can otherwise be mutable
[1].

## 4. Work Breakdown

### Phase A — Deterministic OCI publication

- **A1. `.github/workflows/helm.yml` (edit):** add `packages: write` to only the
  `release` job. Keep pull-request jobs read-only.
- **A2. `.github/workflows/helm.yml` (edit):** after dependency build and version
  resolution, package the chart once into `/tmp/opencode/helm-oci`, verify the
  archive name/version, authenticate to `ghcr.io` with `GITHUB_TOKEN`, and push
  to `oci://ghcr.io/cloud37` only when `already_released == 'false'`.
- **A3. `.github/workflows/helm.yml` (edit):** resolve the pushed manifest digest
  using Helm output or `crane digest`, validate it against `^sha256:[0-9a-f]{64}$`,
  and expose the digest-qualified reference as a step output. Do not sign a tag.

> A3 depends on the successful OCI push in A2.

### Phase B — Keyless signing and release verification

- **B1. `.github/workflows/helm.yml` (edit):** reuse the installed cosign tool
  after the OCI push and call `cosign sign --yes` on the chart digest reference.
- **B2. `.github/workflows/helm.yml` (edit):** call `cosign verify` with the
  GitHub OIDC issuer and exact repository/workflow/ref identity. Fail the job on
  a missing, invalid, or differently identified signature.
- **B3. `.github/workflows/helm.yml` (edit):** run `helm show chart` (or `helm
  pull`) against the versioned OCI reference and assert chart name/version;
  record the digest in the GitHub job summary for copy/paste consumption.
- **B4. GHCR package settings (operator action, no repository file):** after the
  first publication, confirm package association with this repository and set
  visibility to public. Validate anonymous `helm pull`; never add a PAT solely
  to work around package association.

> Phase B depends on Phase A's digest output. B4 is a one-time repository owner
> action because GHCR package visibility is controlled outside the Git tree.

### Phase C — Documentation and release note

- **C1. `helm/s3-encryption-gateway/README.md` (edit):** add an Installation
  section showing OCI version install, digest-pinned install, constrained cosign
  verification, and the retained classic repository method.
- **C2. `CHANGELOG.md` (edit):** under `Unreleased`, announce signed GHCR chart
  publication and state that GitHub Pages remains supported.
- **C3. `docs/issues/GH-277.md` (edit):** retain the plan link and, after
  implementation verification, update status and DoD checkboxes only from
  evidence.

### Phase D — CI regression guard

- **D1. `.github/workflows/helm-test.yml` (edit):** extend the package test to
  save the `.tgz`, inspect it with `helm show chart`, and assert its name and
  version match `Chart.yaml`. Do not push from pull-request CI.
- **D2. `.github/workflows/helm-test.yml` (edit):** lint the release workflow
  with the repository's chosen action/YAML validation mechanism if one exists;
  otherwise add shell syntax checks for extracted scripts and rely on a
  controlled release dry run for registry-only behavior.

## 5. Affected Files

### Direct edits

- `.github/workflows/helm.yml` — publish, digest-resolve, sign, and verify OCI chart releases.
- `.github/workflows/helm-test.yml` — verify deterministic chart package metadata without publishing.
- `helm/s3-encryption-gateway/README.md` — document both distribution channels and verification.
- `CHANGELOG.md` — announce signed OCI availability.
- `docs/issues/GH-277.md` — track plan and eventual completion evidence.

### New files

- `docs/issues/GH-277.md` — local source record imported from GitHub issue #277.
- `docs/plans/GH-277-plan.md` — this implementation plan.

## 6. Test Strategy

Testing follows `docs/TESTING.md`: every Go test belongs to exactly one tier;
Tier 1 has no build tag or Docker dependency, Tier 2 uses only the
`conformance` tag and Testcontainers, and no Tier 3 test is warranted for this
release-pipeline-only change. `-count=1` in the broad gates prevents cached
successes from satisfying acceptance. Before the Tier 2 gate, unset all
`GATEWAY_TEST_SKIP_{MINIO,GARAGE,RUSTFS,SEAWEEDFS}` variables and ensure Docker
is available. A Docker-unavailable `t.Skip` is correct developer behavior but
is not acceptable final evidence for the four local providers.

| Layer | Tests |
|---|---|
| Static workflow | `TestHelmWorkflow_OCIPublishIsReleaseOnly` — inspect workflow YAML and assert GHCR login/push/sign steps are push-only and the release job alone has `packages: write`/`id-token: write`; no build tag. |
| Chart package | `TestHelmPackage_MetadataMatchesChart` — package locally and assert archive basename, chart name, and version match `Chart.yaml`; no build tag. |
| Release smoke (outside Go tiers) | `TestHelmOCI_PublicPullAndSignature` — after controlled release, anonymously pull/show the exact version and verify the digest-bound keyless signature against issuer and workflow identity. This is a release-workflow assertion, not a Tier 1/2/3 Go test. |
| Regression | Existing Helm lint, schema, render, and script checks in `.github/workflows/helm-test.yml:193-295`; no build tag. |
| Tier 1 — unit regression | Existing `make test` runs all no-build-tag tests once with `-race` and coverage; no new Go behavior requires a new unit test. |
| Tier 2 — conformance regression | Existing `make test-conformance` runs all registered local providers and any configured external providers under the `conformance` build tag; no release-only assertion is added to this tier. Docker absence may produce documented `t.Skip`, but a final acceptance run must execute all four local providers. |
| Structural | Existing `make test-isolation-check` proves Tier 2 remains Testcontainers-only with no Compose, backend subprocess, or fixed-port dependency. |

### Validation Matrix

| Command | Purpose | Tier | Owner | Run when |
|---|---|---|---|---|
| `helm dependency build helm/s3-encryption-gateway && helm lint helm/s3-encryption-gateway && mkdir -p /tmp/opencode/GH-277-chart && helm package helm/s3-encryption-gateway --destination /tmp/opencode/GH-277-chart && helm show chart /tmp/opencode/GH-277-chart/s3-encryption-gateway-*.tgz` | Fast local package/metadata regression feedback without publishing | 1 | implementation worker | After workflow or chart documentation edits |
| `set -o pipefail; make test 2>&1 \| tee /tmp/opencode/GH-277-make-test.log >/dev/null` | Full unit, race, and aggregate coverage gate | 1 | coordinator | Once after the final worker edit |
| `set -o pipefail; make test-conformance 2>&1 \| tee /tmp/opencode/GH-277-make-test-conformance.log >/dev/null` | Full registered-provider conformance gate; all four local providers must execute, while unconfigured external providers may skip | 2 | coordinator | Once after `make test`, with Docker available, after the final worker edit |
| `make test-isolation-check` | Enforce the Docker-only, Testcontainers-based Tier 2 model | Structural | coordinator | Once after conformance completes |
| `helm pull oci://ghcr.io/cloud37/s3-encryption-gateway --version "$VERSION" && cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp '^https://github\.com/cloud37/s3-encryption-gateway/\.github/workflows/helm\.yml@refs/heads/(main\|master)$' "ghcr.io/cloud37/s3-encryption-gateway@$DIGEST"` | Prove public OCI retrieval and repository-bound signature | Release | release owner | Once for the first controlled release and each release thereafter in workflow |

### Commands to verify locally

```bash
helm dependency build helm/s3-encryption-gateway && helm lint helm/s3-encryption-gateway && mkdir -p /tmp/opencode/GH-277-chart && helm package helm/s3-encryption-gateway --destination /tmp/opencode/GH-277-chart && helm show chart /tmp/opencode/GH-277-chart/s3-encryption-gateway-*.tgz
set -o pipefail; make test 2>&1 | tee /tmp/opencode/GH-277-make-test.log >/dev/null
set -o pipefail; make test-conformance 2>&1 | tee /tmp/opencode/GH-277-make-test-conformance.log >/dev/null
make test-isolation-check
helm pull oci://ghcr.io/cloud37/s3-encryption-gateway --version "$VERSION" && cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp '^https://github\.com/cloud37/s3-encryption-gateway/\.github/workflows/helm\.yml@refs/heads/(main|master)$' "ghcr.io/cloud37/s3-encryption-gateway@$DIGEST"
```

Acceptance evidence must record the exit status for every matrix command. The
coordinator must inspect the conformance log summary and confirm subtests for
`minio`, `garage`, `rustfs`, and `seaweedfs` ran; a skipped local provider does
not satisfy the gate. External providers may skip only when their documented
credentials are absent. Do not add Docker-backed release checks to Tier 1.

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Workflow signs a mutable tag rather than released bytes | Resolve, validate, sign, and verify the `sha256:` digest returned for the pushed chart. |
| Signature from an unrelated GitHub workflow is accepted | Verify both Fulcio issuer and exact repository/workflow/ref certificate identity. |
| GHCR package is private after first publication | Add a one-time owner checklist to associate it with the repository, make it public, and prove anonymous pull. |
| Retry overwrites an existing OCI version with different bytes | Reuse the current new-version guard and never use a force/overwrite operation. |
| OCI work breaks the existing chart repository | Keep chart-releaser steps intact and verify both install paths from the same chart version. |
| Token leaks in workflow logs | Pipe `GITHUB_TOKEN` through stdin and never enable shell tracing around login. |
| Packaging twice yields divergent release artifacts | Build dependencies first and use the same checked-out source/version; compare packaged chart metadata and document both channels as equivalent releases. |

## 8. Definition of Done

- [ ] Per `docs/issues/GH-277.md:25-30`, the release job publishes
      `ghcr.io/cloud37/s3-encryption-gateway:<Chart.yaml version>` and preserves
      chart-releaser/GitHub Pages publication.
- [ ] Only the release job has `packages: write`, and GHCR authentication uses
      `GITHUB_TOKEN` via stdin.
- [ ] The OCI chart is signed and verified by immutable digest with the GitHub
      issuer and exact `cloud37/s3-encryption-gateway/.github/workflows/helm.yml`
      workflow identity.
- [ ] The package is repository-associated, public, and anonymously pullable.
- [ ] Existing version tags are never overwritten by release reruns.
- [ ] The README contains versioned OCI install, digest-pinned install, cosign
      verification, and classic repository commands.
- [ ] `CHANGELOG.md` records the additional signed distribution channel.
- [ ] The focused chart package checks, `make test`, and
      `make test-conformance` pass in the prescribed sequence, with MinIO,
      Garage, RustFS, and SeaweedFS actually executed rather than skipped for
      unavailable Docker; unconfigured external providers may skip.
- [ ] `make test-isolation-check` passes, confirming conformance remains within
      the Docker-only Testcontainers model required by `docs/TESTING.md`.

## 9. Milestones & Estimated Effort

| Phase | Output | Effort |
|---|---|---|
| A | Deterministic GHCR chart publication and digest capture | 0.75 d |
| B | Keyless signing, identity verification, and public package validation | 0.75 d |
| C | Consumer documentation and release note | 0.25 d |
| D | Non-publishing CI package regression checks | 0.50 d |
| **Total** | | **2.25 d** |

## 10. Follow-ups / Out-of-scope items surfaced during planning

- Consider publishing container images to GHCR under a separate issue if a
  single-registry distribution strategy is desired; this issue covers charts only.
- Consider SLSA provenance for the chart as a separate enhancement after signed
  OCI publication is stable; the requested trust property is signature identity.

## 11. References

1. Helm Authors, *Use OCI-based registries* (Helm Documentation, 2026) — OCI
   push naming, version tags, installation, and digest pinning semantics.
   <https://helm.sh/docs/topics/registries/>
2. Sigstore Authors, *Signing Containers* (Sigstore Documentation, 2026) —
   digest-addressed keyless signing and identity-constrained verification.
   <https://docs.sigstore.dev/cosign/signing/signing_with_containers/>
3. GitHub, *Working with the Container registry* (GitHub Documentation, 2026)
   — `GITHUB_TOKEN`, package permissions, visibility, and repository association.
   <https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry>
