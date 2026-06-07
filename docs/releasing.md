# Release Checklist

This document describes the steps required to publish a new release of
`s3-encryption-gateway`. The CI pipeline (`.github/workflows/helm.yml`) handles
most automation; this checklist covers the manual preparation steps that
maintainers must complete before tagging a release.

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
changes documented.

### 5. Verify Chart Version

Confirm the `version` field in `helm/s3-encryption-gateway/Chart.yaml` has
been incremented according to semver. The CI pipeline will skip the release
if the version has already been published.

## CI Pipeline

After tagging, the `helm.yml` release workflow:

1. Runs `chart-releaser-action` to publish the Helm chart to the `gh-pages`
   branch (skipped if version already published).
2. Cross-compiles gateway and migrate binaries (linux/amd64, linux/arm64,
   darwin/arm64) and uploads them to the GitHub release.
3. Builds and pushes a multi-arch (linux/amd64, linux/arm64) Docker image
   to Docker Hub.
4. Builds and pushes a FIPS image (linux/amd64 only) to Docker Hub with
   `-fips` tag suffix.
5. Runs Trivy container vulnerability scan (HIGH/CRITICAL severity gate).
6. Generates an SPDX-JSON SBOM via syft and uploads it to the GitHub release.
7. Signs the Docker Hub image digest and attaches the SBOM attestation using
   cosign keyless OIDC signing (Sigstore transparency log).
8. Syncs the chart README to the `gh-pages` branch.

### Required Secrets

The following GitHub Actions secrets must be provisioned in the repository
settings (Settings → Secrets → Actions):

- `DOCKERHUB_USERNAME` — Docker Hub account name (e.g. `cloud37io`)
- `DOCKERHUB_TOKEN` — Docker Hub access token with read/write scope for
  `cloud37io/s3-encryption-gateway`

## Post-Release

### Artifact Hub Registration

If this is the first release with Artifact Hub annotations, register the
Helm repository at [artifacthub.io](https://artifacthub.io):

1. Sign in with a GitHub account.
2. Go to "Add Repository".
3. Repository name: `s3-encryption-gateway`
4. Repository URL: `https://cloud37.github.io/s3-encryption-gateway`
5. Kind: `Helm chart`

It may take 24–48 hours for Artifact Hub to index the chart after
registration.
