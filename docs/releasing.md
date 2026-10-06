# Release Checklist

This document describes the steps required to publish a new release of
`s3-encryption-gateway`. The CI pipeline (`.github/workflows/helm.yml`) handles
most automation; this checklist covers the manual preparation steps that
maintainers must complete before releasing a new chart version from `main` or
`master`. The workflow derives the release tag from `Chart.yaml` as
`s3-encryption-gateway-<version>`.

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
# Build the Docker image first
make docker-build

# Generate the SBOM
make sbom

# Verify the SBOM is valid SPDX-JSON
grep -q '"spdxVersion"' sbom.spdx.json && echo "SBOM is valid"
```

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

Before release, review the documentation as a maintained reader and agent
interface; this is a maintainer check, not a CI job. Start at
[`docs/README.md`](README.md), which is the task-oriented index for the 18
top-level reader guides. Each topic should have one authoritative guide, and
the index should route readers to it. Supporting artifacts and historical
records live in their dedicated directories, including `adr/`, `diagrams/`,
`integrations/`, `issues/`, `perf/`, `plans/`, and `security/`; these are
intentional and are not obsolete reader guides merely because they are not in
the top-level guide count.

For this release, verify that:

- The release checklist and reader index reflect the current repository
  structure and released behavior; planned or unreleased work is clearly
  distinguished from what ships.
- Local links and anchors resolve, moved material has live references, and no
  superseded guide, empty redirect stub, or other orphaned reader-facing file
  remains. Update links to the authoritative guide instead of restoring a
  retired filename.
- The documentation does not duplicate a topic owner's instructions or
  contradict the chart, workflow, changelog, or current source. Preserve
  intentional historical/reference records unless they are explicitly being
  retired.
- `git diff --check` passes. See
  [documentation validation](TESTING.md#documentation-validation) for the
  documentation-only review expectations.

Do not add a documentation CI requirement for this gate: it is a deliberate
manual freshness and dead-file review before rendering/publishing the release.

## CI Pipeline

After a push to `main` or `master` with a new chart version, the `helm.yml`
release workflow:

1. If the release tag is new, packages and publishes the Helm chart to GHCR as
   an OCI artifact, then uses `chart-releaser-action` to publish the chart index
   and package to the `gh-pages` branch.
2. Cross-compiles gateway, CLI, and deprecated migration-shim binaries
   (linux/amd64, linux/arm64, darwin/arm64) and uploads them to the GitHub
   release.
3. Builds and pushes a multi-arch (linux/amd64, linux/arm64) Docker image
   to Docker Hub.
4. Builds and pushes a FIPS image (linux/amd64 only) to Docker Hub with
   `-fips` tag suffix.
5. Runs a Trivy HIGH/CRITICAL severity scan of the standard Docker image.
6. Generates an SPDX-JSON SBOM via syft and uploads it to the GitHub release.
7. Signs and verifies the OCI Helm chart, and signs the Docker Hub image digest
   and attaches its SBOM attestation using cosign keyless OIDC signing.
8. Syncs the chart README to the `gh-pages` branch.
9. Updates the GitHub Release notes from the matching `CHANGELOG.md` section
   and links back to the full changelog. A version containing `-` is marked as
   a prerelease on GitHub.

If the tag already exists, the workflow skips the release work rather than
re-running these publishing steps.

### Required Secrets

The following GitHub Actions secrets must be provisioned in the repository
settings (Settings → Secrets → Actions):

- `DOCKERHUB_USERNAME` — Docker Hub account name (e.g. `cloud37io`)
- `DOCKERHUB_TOKEN` — Docker Hub access token with read/write scope for
  `cloud37io/s3-encryption-gateway`

## Post-Release

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
