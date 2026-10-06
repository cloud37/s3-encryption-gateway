# Contributor Guide

Use this guide for development workflow and repository conventions. Runtime
configuration belongs in [deployment](DEPLOYMENT.md), test commands and coverage
policy in [testing](TESTING.md), and release procedures in [releasing](releasing.md).

## Contents

- [Build and run locally](#build-and-run-locally)
- [Code ownership and conventions](#code-ownership-and-conventions)
- [Validation and review](#validation-and-review)
- [Explanatory commits](#explanatory-commits)
- [Documentation ownership](#documentation-ownership)

## Build and Run Locally

Requirements: **Go 1.27.1 or later** (see `go.mod`), Git, Make, and Docker for
Testcontainers-backed conformance. Helm/kubectl are needed for chart/deployment work.

```bash
git clone https://github.com/cloud37/s3-encryption-gateway.git
cd s3-encryption-gateway
go mod download
make build VERSION=dev
cp config.yaml.example config.local.yaml
# Edit backend credentials, gateway credentials, encryption, and Valkey settings.
CONFIG_PATH=config.local.yaml ./bin/s3-encryption-gateway-dev
```

Do not run against production buckets or reuse production keys in tests. The
gateway authenticates clients with its own credentials and re-signs backend
requests with a separate backend identity. See the [deployment guide](DEPLOYMENT.md)
for local Docker/Helm setup and the multipart prerequisites. `make cli VERSION=dev`
builds the read-only audit tool; the old migration binary is a deprecation shim.

The repository's Makefile, workflow files, `go.mod`, example configuration, and
Helm schema are the authoritative command/version/schema sources. Do not create
parallel copies of their configuration tables in this guide.

## Code Ownership and Conventions

| Area | Responsibility |
|---|---|
| `cmd/server` | Composition, startup, HTTP listeners, runtime reload wiring |
| `internal/api` | Routing, authentication/authorization, S3 orchestration, response/error projection |
| `internal/config` | Validated configuration, policies, reload constraints |
| `internal/crypto` | Encryption formats, KDFs, key managers, integrity verification |
| `internal/s3` | Backend client boundary, typed inputs, transport, adapters |
| `internal/mpu` | Durable multipart routing, content claims, guarded lifecycle |
| `internal/sizecache` | Advisory plaintext listing-size cache |
| `internal/admin` | Separate bearer-authenticated operational plane |
| `test/harness`, `test/provider`, `test/conformance` | Gateway fixtures and shared provider scenarios |

- Match nearby Go style; format changed Go files with `gofmt` and follow existing
  import grouping. Use descriptive identifiers and small explicit interfaces.
- Propagate contexts through blocking I/O. Wrap typed causes with `%w` and classify
  them with `errors.Is`; avoid string-based classification.
- Validate authentication, scope, metadata, object identity, and crypto inputs
  before side effects. Security boundaries fail closed; advisory caches may fail soft.
- Keep shared metadata, response, error, and multipart contracts in their existing
  owners rather than adding branch-specific duplicates.
- Never log secrets or plaintext. Keep client errors fixed/opaque and diagnostics
  structured internally. Zero owned key bytes when done; Go zeroization is not a
  guarantee that every historical runtime copy has disappeared.
- Treat source/target buckets independently during copy authorization. Backend
  IAM is not a substitute for gateway credential scope.
- AI-assisted contributions follow these same rules. They must inspect current
  source rather than treat historical plans or illustrative interfaces as live APIs.

## Validation and Review

Start with a focused regression asserting the actual handler/client boundary and
absence of unintended backend writes. Prefer table-driven cases; use real HTTP
serialization when wire behavior is the contract. Provider capability selection
and helper-only tests do not certify complete application compatibility.

```bash
go test ./internal/api -run '^TestRouteClassificationParity$' -count=1
git diff --check
```

Then run affected-package tests, race/FIPS checks, and provider conformance as
appropriate. See [TESTING.md](TESTING.md) for canonical commands and coverage;
report focused results separately from broad gates. Performance changes need
matching [baseline/profile evidence](PERFORMANCE.md). Crypto/security-boundary
changes need review of the relevant invariants and failure paths.

Before opening a PR:

- Explain the goal, user-visible behavior, compatibility/rollout impact, and why
  the selected boundary owns the change.
- Preserve unrelated work and keep issue/plan files outside the change unless
  intentionally updating those records.
- Include tests that directly establish the changed contract, not wrappers around
  unrelated tests. State skipped/unrun validation explicitly.
- Update the authoritative reader guide and changelog when behavior changes.
- Check configuration/Helm/reload implications without silently changing defaults.

## Explanatory Commits

Use an operation-oriented Conventional Commit subject, then explain rationale,
scope, boundaries, and validation in the body. Group related changes by responsibility.

```text
docs(s3): consolidate compatibility guidance (GH-357)

Explain the reader problem and why this change belongs here.
Describe the contracts preserved, duplicate material removed, and limitations.

Validation:
- Record focused checks and broad gates separately.
- State what was not exercised.
```

Never claim a feature is released, a provider certified, or a gate passed merely
because a plan checkbox, capability flag, or past report says so.

## Documentation Ownership

[docs/README.md](README.md) is the reader's entry point. Each topic has one owner;
other guides link to the relevant heading instead of copying its tables:

- S3 operations, request options, SDK/backend evidence: [S3 compatibility](S3_API_IMPLEMENTATION.md).
- Runtime configuration, backend setup, credential/encryption policies: [deployment](DEPLOYMENT.md).
- Encryption formats, metadata, FIPS: [encryption design](ENCRYPTION_DESIGN.md).
- Key providers, key sources, rotation: [key management](KMS_COMPATIBILITY.md).
- Upgrade/re-encryption/recovery: [migration](MIGRATION.md).
- Incident response/admin API: [runbook](RUNBOOK.md); signals/dashboard recipes: [observability](OBSERVABILITY.md).
- Tests/coverage: [testing](TESTING.md); benchmarks/scaling: [performance](PERFORMANCE.md).

Update existing guides, add contents links to substantial sections, and repair
live links when moving material. Do not add a new tiny guide or redirect stub for
an existing topic. Plans, issues, ADRs, security findings, and benchmark evidence
are historical/reference records, not the current operational reading path.
