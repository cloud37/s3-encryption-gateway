//go:build integration

package integration

// Azurite is a legacy integration fixture and is intentionally outside the
// maintained Renovate inventory until this suite is migrated to conformance.
const azuriteImage = "mcr.microsoft.com/azure-storage/azurite:3.33.0"

// renovate: datasource=docker depName=quay.io/minio/minio versioning=docker
const minioImage = "quay.io/minio/minio:RELEASE.2024-11-07T00-52-20Z"
