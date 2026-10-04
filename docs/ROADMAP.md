# Roadmap

**Reviewed October 4, 2026; released compatibility baseline: v0.12.3.**

For current behavior, use [S3 compatibility](S3_API_IMPLEMENTATION.md) and the
[changelog](../CHANGELOG.md). An issue, proposal, or implementation branch is not
evidence that a capability has shipped. No delivery dates are committed below.

## Accepted, Unreleased Work

| Work | Tracking | Current release limitation |
|---|---|---|
| Gateway-managed CORS | [#322](https://github.com/cloud37/s3-encryption-gateway/issues/322) | Backend preflight/passthrough is not complete CORS for gateway-generated encrypted responses |
| Presigned POST Object form uploads | [#353](https://github.com/cloud37/s3-encryption-gateway/issues/353) | Separate from multipart upload; browser support depends on gateway-managed CORS |
| Signed zero Content-Length through reverse proxies | [#356](https://github.com/cloud37/s3-encryption-gateway/issues/356) | Implemented branch fix is not in v0.12.3 |

Follow the linked issues for current implementation/release status. Documented
limitations without an accepted issue are not implicit roadmap commitments.

## Longer-Term Directions

AWS KMS, Azure Key Vault, GCP Cloud KMS, and a Kubernetes Operator remain possible
future work. OpenBao/HashiCorp Vault Transit and local envelope keys are already
supported; see [key management](KMS_COMPATIBILITY.md).

## Historical Planning

Earlier milestone proposals and implementation decisions remain in
[plans](plans/), [issue records](issues/), and [ADRs](adr/). Their relative dates,
unchecked tasks, and historical assumptions are not the current support matrix.
Do not copy those checklists into operational guides. Released changes and upgrade
requirements belong in the changelog and [migration guide](MIGRATION.md).
