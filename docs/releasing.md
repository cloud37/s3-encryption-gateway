# Release Checklist

This document describes the steps required to publish a new release of
`s3-encryption-gateway`. The CI pipeline (`.github/workflows/helm.yml`) handles
most automation; this checklist covers the manual preparation steps that
maintainers must complete before releasing a new chart version from `main` or
`master`. The workflow derives the release tag from `Chart.yaml` as
`s3-encryption-gateway-<version>`.

**Workflow review: October 7, 2026.** This checklist is the pre-publication
maintainer gate; a green release job is not proof that reader documentation is
factually current. Do not push a release-triggering version change or dispatch
publication until the checks below have been reviewed for the final merged commit.

## Contents

- [Pre-release checklist](#pre-release-checklist)
- [Documentation structure and freshness gate](#6-pass-the-documentation-release-gate-manual)
- [Publication workflow and gate boundaries](#ci-pipeline)
- [Post-release verification](#post-release)

## Pre-Release Checklist

### 1. Update Artifact Hub Annotations

The `artifacthub.io/changes` annotation in
`helm/s3-encryption-gateway/Chart.yaml` must be updated before each release
to describe what changed in this version.

```yaml
annotations:
  artifacthub.io/changes: |
    - kind: added
      description: Brief description of the new feature
    - kind: fixed
      description: Brief description of the bug fix
```

Valid `kind` values: `added`, `changed`, `deprecated`, `removed`, `fixed`,
`security`.

### 2. Verify Image References

Ensure the `artifacthub.io/images` annotation in `Chart.yaml` reflects the
new version being released:

```yaml
annotations:
  artifacthub.io/images: |
    - name: s3-encryption-gateway
      image: docker.io/cloud37io/s3-encryption-gateway:<new-version>
      whitelisted: true
    - name: s3-encryption-gateway-fips
      image: docker.io/cloud37io/s3-encryption-gateway:<new-version>-fips
      whitelisted: true
```

### 3. Pre-Validate SBOM Locally

Run the SBOM generation locally to verify it produces valid output before
the CI run:

```bash
# Use the intended chart version consistently, not an implicit git-describe tag.
VERSION_TO_RELEASE="<intended chart version>"
make docker-build VERSION="$VERSION_TO_RELEASE" IMAGE_TAG="$VERSION_TO_RELEASE"

# Generate the SBOM
make sbom IMAGE_TAG="$VERSION_TO_RELEASE"

# Parse the output and confirm that it declares SPDX-JSON.
python3 - <<'PY'
import json
with open("sbom.spdx.json", encoding="utf-8") as source:
    document = json.load(source)
assert document.get("spdxVersion", "").startswith("SPDX-"), "Missing SPDX version"
print("SBOM is parseable SPDX-JSON; review its contents and image identity too.")
PY
```

This is a local format sanity check, not full SPDX schema validation or proof
that the SBOM covers every release artifact. Check the selected image/tag/digest
and tooling output separately.

### 4. Update CHANGELOG

Ensure `CHANGELOG.md` has an entry for the new version with all significant
changes documented. The release workflow extracts the matching version section
and publishes it as the GitHub Release notes. The release will fail if the
version entry is missing, empty, or duplicated.

### 5. Verify Chart Version

Confirm the `version` field in `helm/s3-encryption-gateway/Chart.yaml` has
been incremented according to semver and that `appVersion` and image references
match the intended release. The workflow derives the tag as
`s3-encryption-gateway-<version>` and skips the release work if that GitHub
release tag already exists.

### 6. Pass the Documentation Release Gate (Manual)

Review documentation **after all intended branches are merged**, against the
exact commit and version being released. This is a mandatory maintainer review,
not an automated CI job. Start at [the task index](README.md). The consolidated
layout has **18 top-level Markdown files**, including two historical/security
references; it is not 18 separate authoritative operational guides. The count is
a consolidation baseline, not a permanent maximum or proof of quality.

#### Authoritative guide owners

| Topic | Existing owner | Material consolidated here |
|---|---|---|
| S3 feature/operation/options and SDK/backend evidence | [S3 compatibility](S3_API_IMPLEMENTATION.md) | Former S3 operations, request compatibility, SDK compatibility guides |
| Installation, backends, frontend key policies, encryption-policy configuration | [Deployment](DEPLOYMENT.md) | Former backend and policy configuration guides; [frontend policies](DEPLOYMENT.md#frontend-access-key-policies) must remain easy to find |
| Incident response, state/metadata-key recovery, admin HTTP API | [Runbook](RUNBOOK.md) | Former operations and admin API guides |
| Encryption modes, provider/key sources, rotation | [Key management](KMS_COMPATIBILITY.md) | Former encryption-mode and key-rotation guides |
| Upgrade, password-to-KMS migration, explicit re-encryption | [Migration](MIGRATION.md) | Former single-password-to-KMS migration guide |
| Payload formats, object metadata, FIPS | [Encryption design](ENCRYPTION_DESIGN.md) | Former metadata-model and FIPS guides |
| Tests, coverage, exclusions, mutation testing | [Testing](TESTING.md) | Former coverage guide |
| Benchmark evidence, scaling, HPA, memory/disk/Valkey capacity | [Performance](PERFORMANCE.md) | Former scaling guide and encryption-mode benchmarks |
| Contributor/agent workflow and documentation conventions | [Contributor guide](DEVELOPMENT_GUIDE.md) | Former agent guide |

[Architecture](ARCHITECTURE.md), [observability](OBSERVABILITY.md),
[CLI recipes](S3_CLI_TOOLS.md), and [progressive delivery](OPS_DEPLOYMENT.md)
retain their distinct roles. They link to topic owners rather than copy their
full tables. This release checklist owns release preparation, not another copy
of configuration or compatibility documentation.

#### Release-specific accuracy review

- [ ] Compare the final merged change set with the last published release,
  including behavior/configuration/docs changes—not just PR titles or old test reports.
- [ ] Set the compatibility baseline/review date to the intended release in the
  S3 guide and review README, deployment, runbook, roadmap, and migration claims
  together. Move features from “unreleased main” to the correct released version
  only when included in the release candidate. Retain older-version caveats.
- [ ] For a release containing GH-322/GH-356, reconcile CORS mode/durability,
  response-header ownership, and signed Content-Length recovery across those
  owners. Do not leave the new release describing merged work as merely planned,
  or change v0.12.3 history to pretend it already contained these changes.
- [ ] Compare operation inventory, SDK versions, provider test-selection facts,
  defaults, env/Helm fields, CLI commands, and admin endpoints against the pinned
  source/schema/workflows. A route or capability bit is not full compatibility.
- [ ] Preserve explicit frontend authorization versus encryption/backend IAM
  distinctions and restrictive role examples; document changed grants/defaults.
- [ ] Verify upgrade/rollback and key/state/manifest retention prerequisites,
  writable spool/FIPS instructions, and recovery examples. Run relevant example
  checks safely; do not call production mutations just to validate documentation.
- [ ] Ensure the matching changelog, Artifact Hub annotations, Chart.yaml
  version/appVersion, image references, and release checklist agree on what ships.
  Report unrun/skipped tests and known limitations, not blanket certification.

#### Navigation and obsolete-file review

- [ ] Check local links **and heading anchors**, including README/index, chart
  references, examples, schemas, and workflow report text. A file existing does
  not establish that its anchor exists or that its content is current.
- [ ] Every current guide is reachable from the task index or an intentional
  supporting-reference path. Substantial guides have useful contents navigation,
  and important warnings are visible before the relevant steps.
- [ ] No retired guide was recreated by a merged branch, no empty redirect stub
  was added, and no duplicate/orphaned reader-facing guide has become a competing
  authority. Merge unique useful content into its owner before removing an
  explicitly reviewed obsolete file; do not delete unfamiliar/user work by guesswork.
- [ ] Search live references for these retired names: ADMIN_API.md, AGENT.md,
  BACKENDS.md, COVERAGE.md, ENCRYPTION_MODES.md, FIPS.md, KEY_ROTATION_RUNBOOK.md,
  METADATA_MODEL.md, MIGRATION_SINGLE_PASSWORD_TO_KMS.md, OPERATIONS.md,
  POLICY_CONFIGURATION.md, S3_COMPATIBILITY.md, S3_OPERATIONS.md, SCALING.md,
  SDK_COMPATIBILITY.md. Update live links to the owner, not a replacement stub.
- [ ] Keep intentional plans, issues, ADRs, diagrams, integrations, examples,
  security findings, and benchmark evidence. Historical filenames/citations in
  those records or old changelog sections are not obsolete live guides. The
  historical V0.6-SEC-1-IMPLEMENTATION.md and SECURITY_AUDIT.md are reference
  material, not current operational instruction owners.

Useful local checks (read-only; no publishing):

```bash
git status --short --branch
git ls-files -u
git diff --check
git diff --cached --check
git ls-files 'docs/*.md'
bash scripts/test-extract-changelog-section.sh
bash scripts/extract-changelog-section.sh CHANGELOG.md "$VERSION_TO_RELEASE"
```

Use a Markdown-aware checker or deliberate review for link/anchor resolution;
the commands above do not perform it or prove factual freshness. See
[documentation validation](TESTING.md#documentation-validation). Tests/Helm,
security, FIPS, and conformance checks for the intended release commit are
separate required evidence; documentation review does not replace them.

#### Required maintainer sign-off

Record in the release PR or review record: **target version, exact reviewed commit,
review date/reviewer, owners updated, obsolete-file/navigation findings resolved,
validation performed, and remaining limitations**. Missing/outdated guide content,
broken live references, revived superseded files, or unresolved contradictory
claims block sign-off. Re-check after any later merge/version/docs change. Do
not create a new permanent per-release checklist file just to store the sign-off.

This remains a deliberate **manual gate**. The release workflow does not enforce
documentation freshness; no new documentation CI requirement is introduced here.

## CI Pipeline

The [helm.yml workflow](../.github/workflows/helm.yml) runs on relevant Helm/workflow
path changes for push/PR on main/master, or manual dispatch. A docs-only push does
not necessarily trigger it. Publication is restricted to push/dispatch on those
branches after its Helm lint/template job; PR runs do not publish.

For a new GitHub release tag, its current order is:

1. Resolve chart version/tag, build dependencies, and extract the matching
   changelog **before the first publication**. Missing/duplicate/empty version
   entries fail extraction.
2. Package/publish OCI chart to `ghcr.io/cloud37/s3-encryption-gateway-helm`,
   record the digest, then chart-releaser publishes GitHub chart/package/index.
3. Update release notes and mark a hyphen-suffixed version as prerelease.
4. Build/upload gateway, **read-only s3eg-cli**, and **deprecated s3eg-migrate shim**
   for linux/amd64, linux/arm64, darwin/arm64. The shim is not a working migration tool.
5. Build/push standard image for linux/amd64+arm64 and the current `latest` tag;
   build/push FIPS image for linux/amd64 only with `-fips` suffix.
6. Scan the standard image with Trivy HIGH/CRITICAL, ignoring unfixed findings,
   then generate/upload SPDX-JSON SBOM. This step does not scan the FIPS image.
7. Keylessly sign/verify the digest-qualified OCI chart and verify name/version;
   sign/attest the standard image digest with the SBOM. The workflow does not
   separately sign/attest the FIPS image.
8. Copy chart README from origin/main to gh-pages and push that documentation.
   Review this source selection when publishing from master or another release ref.

**Gate boundaries:** chart/image publication occurs before later scan/signature
checks. A late failure can leave partial public artifacts; a failed job is not a
transactional rollback. Review and validate before invoking publication. Separate
[conformance](../.github/workflows/conformance.yml) and security workflows are not
dependencies of this release job; release-triggered conformance runs after the
published event, not as a pre-publication gate. Do not claim this workflow alone
enforces all release-quality requirements.

If the tag already exists, the workflow skips the release work rather than
re-running these publishing steps.

### Required Secrets

The following GitHub Actions secrets must be provisioned in the repository
settings (Settings → Secrets → Actions):

- `DOCKERHUB_USERNAME` — Docker Hub account name (e.g. `cloud37io`)
- `DOCKERHUB_TOKEN` — Docker Hub access token with read/write scope for
  `cloud37io/s3-encryption-gateway`

The job also relies on its provided GITHUB_TOKEN permissions for repository/
Pages/GHCR publishing and OIDC `id-token: write` for keyless cosign. Check registry
ownership/permissions and workflow identity; never put credential values in docs.

## Post-Release

### Verify the Published Release

Confirm the intended tag/commit, versioned charts and image digests, OCI metadata/
signature verification, standard-image SBOM/attestation, binary platforms, and
release notes. Check the applicable CI results and any skips. Verify that links
resolve from the published chart/README location, not just the source repository.
Do not assume gh-pages copies of repository-relative links have the same targets.

If publication failed partway, inventory artifacts and logs before retrying:
the existing-tag check can skip remaining release steps on a second run. Record
and repair missing artifacts deliberately; do not blindly increment a version or
rewrite a public tag. Keep the reader guides aligned with the actual published
release, and the roadmap explicit about work that still did not ship.

### Backfill Existing Releases

The CI workflow updates release notes for new releases. To locally backfill
older releases from their matching `CHANGELOG.md` sections, first preview the
changes:

```bash
bash scripts/backfill-release-notes.sh
```

The preview does not modify GitHub. After reviewing the release list, apply the
updates explicitly:

```bash
bash scripts/backfill-release-notes.sh --apply
```

To update only one release, specify its version:

```bash
bash scripts/backfill-release-notes.sh --version 0.11.8 --apply
```

Use `--limit NUMBER` to restrict the number of releases inspected, or
`--repo OWNER/REPO` for a repository other than the current one. The script
skips unrelated or draft releases and reports releases without a usable
changelog section.

### Artifact Hub

The chart is already registered on Artifact Hub at:
<https://artifacthub.io/packages/helm/s3-encryption-gateway/s3-encryption-gateway>

The Artifact Hub annotations in `Chart.yaml` (category, license, images, changes)
control how the listing is displayed. Update `artifacthub.io/changes` before
each release to describe new features and fixes.
