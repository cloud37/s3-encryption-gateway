# Roadmap

**Reviewed for `0.13.0-rc1` on November 9, 2026; latest stable release: v0.12.3.**

For current behavior, use [S3 compatibility](S3_API_IMPLEMENTATION.md) and the
[changelog](../CHANGELOG.md). An issue, proposal, or implementation branch is not
evidence that a capability has shipped. No delivery dates are committed below.

## Release-Candidate Validation

| Work | Tracking | Current release limitation |
|---|---|---|
| Gateway-managed CORS | [#322](https://github.com/cloud37/s3-encryption-gateway/issues/322) | Included in `0.13.0-rc1` for opt-in validation; absent from stable v0.12.3 |
| Presigned POST Object form uploads | [#353](https://github.com/cloud37/s3-encryption-gateway/issues/353) | Included in `0.13.0-rc1` for feature-requester/provider validation; browser support depends on gateway-managed CORS |
| Signed zero Content-Length through reverse proxies | [#356](https://github.com/cloud37/s3-encryption-gateway/issues/356) | Included in `0.13.0-rc1`; absent from stable v0.12.3 |

The `0.13.0-rc1` candidate is for validation, not production. Follow the linked
issues for current acceptance status and the [S3 reference](S3_API_IMPLEMENTATION.md)
for the stable v0.12.3 compatibility baseline and candidate scope. An issue,
proposal, or implementation branch is not evidence of stable-release support.

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
