//go:build integration

package integration

// Azurite is a legacy integration fixture and is intentionally outside the
// maintained Renovate inventory until this suite is migrated to conformance.
const azuriteImage = "mcr.microsoft.com/azure-storage/azurite:3.33.0"

// renovate: datasource=docker depName=chainguard/minio versioning=docker
const minioImage = "chainguard/minio@sha256:de89cccd6cb19f505bf85c8a36f099414dc7a372c0e16abd2170ebaada9cc99f"
