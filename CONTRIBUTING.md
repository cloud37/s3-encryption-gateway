# Contributing to S3 Encryption Gateway

Thank you for your interest in contributing. This project is a transparent S3
proxy that applies envelope encryption to every object — a security-critical
code path where correctness matters more than velocity. Please read this
document before opening a PR.

---

## Before you start

- Check the [open issues](https://github.com/cloud37/s3-encryption-gateway/issues)
  and [roadmap](docs/ROADMAP.md) to understand what is planned and what is
  actively being worked on.
- For significant changes — new adapters, new API behaviour, changes to the
  encryption or key-management path — open an issue first so we can agree on
  the approach before you invest time in an implementation.
- For security vulnerabilities, follow the process in [SECURITY.md](SECURITY.md).
  Do not open a public issue.

---

## Repository orientation

| Path | What lives there |
|---|---|
| `internal/crypto/` | Encryption engine, `KeyManager` interface, all KMS adapters |
| `internal/api/` | S3 proxy handlers, crypto factory wiring |
| `internal/config/` | Configuration structs, validation, env-var loading |
| `test/conformance/` | Tier-2 multi-provider conformance suite (see Testing below) |
| `test/provider/` | Testcontainers-backed provider fixtures (MinIO, Garage, …) |
| `test/integration/` | External-infra and chaos tests (credentials required) |
| `docs/` | Design docs, runbooks, ADRs |
| `docs/adr/` | Architecture Decision Records |
| `docs/plans/` | Implementation plans for tracked issues |
| `docs/issues/` | Issue tracker with Definition of Done checklists |

Notable documents:

- [`docs/TESTING.md`](docs/TESTING.md) — **read this before writing any test**
- [`docs/ENCRYPTION_DESIGN.md`](docs/ENCRYPTION_DESIGN.md) — envelope encryption model
- [`docs/KMS_COMPATIBILITY.md`](docs/KMS_COMPATIBILITY.md) — KMS adapter reference
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — component overview
- [`docs/DEVELOPMENT_GUIDE.md`](docs/DEVELOPMENT_GUIDE.md) — local setup and tooling

---

## Testing

**Read [`docs/TESTING.md`](docs/TESTING.md) in full before writing tests.**

The project enforces a strict three-tier taxonomy. A test belongs in exactly
one tier and must not bleed into another.

```
Tier 1 — Unit          no build tag      go test ./...          every PR
Tier 2 — Conformance   conformance       make test-conformance   every PR
Tier 3 — Soak/Load     soak | load       make test-load          nightly/release
```

One easy point of confusion: `test/integration/` with `//go:build integration`
is reserved for tests that require real external credentials or infrastructure
(cloud providers, hardware KMS, etc.) and is **not** part of the PR gate. If
your test spins up a container locally via Testcontainers, it belongs in
`test/conformance/` under `//go:build conformance`.

The model for a KMS adapter conformance test is
[`test/conformance/kms_test.go`](test/conformance/kms_test.go): it starts a
container via a `provider.Start*` fixture, wires the adapter into
`harness.StartGateway`, and exercises S3 PUT/GET through the full in-process
proxy. That is the path that catches integration bugs; calling the crypto
engine directly misses the S3 layer.

Run the standard gates locally before opening a PR:

```bash
# Tier 1
go test -race ./...

# Tier 2 (requires Docker)
make test-conformance-local
```

---

## Code conventions

- **Go version**: match the version in `go.mod`.
- **Error wrapping**: `fmt.Errorf("component/subcomponent: action: %w", err)`.
  All errors on the `KeyManager` interface must wrap one of the sentinel errors
  defined in `internal/crypto/keymanager.go`.
- **Context propagation**: every call that touches the network must accept and
  honour a `context.Context`; pass it through, do not ignore cancellation.
- **No credential logging**: tokens, passwords, DEK bytes, and secret IDs must
  never appear in log output, error strings, or `KeyEnvelope` fields.
- **DEK zeroization**: plaintext key material must be zeroized after use.
  The caller is responsible for zeroizing slices returned by `UnwrapKey`.
- **Linting**: `go vet ./...` must pass. The CI also runs `golangci-lint`; run
  it locally if you are touching `internal/crypto/` or `internal/api/`.

---

## Adding a new KMS adapter

1. Implement `KeyManager` (and `RotatableKeyManager` if the backend supports
   server-side key rotation) in `internal/crypto/keymanager_<name>.go`.
2. Add a compile-time assertion: `var _ KeyManager = (*yourManager)(nil)`.
3. Register the adapter name(s) via `crypto.Register` — either in an `init()`
   in the new file or in `internal/api/crypto_factory.go`, following the
   existing Cosmian and OpenBao patterns.
4. Add config structs to `internal/config/config.go` and wire env vars in
   `loadFromEnv`. Add validation cases to `Validate()`.
5. Run `ConformanceSuite` against your adapter in a `*_conformance_test.go`
   file (no build tag — this is tier 1).
6. Add a tier-2 conformance test in `test/conformance/` (see Testing above).
7. Update `docs/KMS_COMPATIBILITY.md` and add an ADR in `docs/adr/`.

---

## Architecture Decision Records

Significant design choices are captured as ADRs in `docs/adr/`. If your
contribution changes the encryption model, key-management interface, auth
strategy, or any other load-bearing design decision, add an ADR or update an
existing one. Existing ADRs are the fastest way to understand *why* the code
looks the way it does.

---

## Pull requests

- Keep PRs focused. One feature or fix per PR.
- Reference the relevant issue or plan document in the PR description.
- All tier-1 and tier-2 tests must pass before review.
- The PR description should state what was changed and why, not just what.
- We will not merge PRs that reduce test coverage on the changed packages
  without a documented reason.

---

## Dependency management

The project uses [Renovate](https://docs.renovatebot.com/) for automated
dependency updates. Do not add Dependabot configuration.

---

Questions? Open a discussion or drop a comment on the relevant issue.
