# Coverage Policy

This document describes the coverage gate, exclusion policy, and mutation-testing
configuration for the S3 Encryption Gateway. It is the authoritative reference for
V0.6-QA-2.

## Gate threshold

The project enforces **≥ 75% statement coverage** on every PR and on every push to
`main`. The gate is implemented in `scripts/coverage-gate.sh` and wired into the
`coverage-gate` CI job in `.github/workflows/conformance.yml`.

```
make coverage-gate            # default 75% threshold
make coverage-gate COVERAGE_THRESHOLD=85   # override
make coverage-html            # open HTML report after gate run
```

The FIPS build profile is gated separately:

```
make coverage-fips            # runs with -tags=fips; threshold = 75%
```

## Excluded packages

Packages listed in `scripts/coverage-exclude.txt` are excluded from the measured
set. Every exclusion carries a rationale comment.  The current exclusions are:

| Package | Reason |
|---|---|
| `cmd/server` | `main()` / `init()` require process-level integration testing; the real signal comes from tier-2 conformance and nightly load tests. |
| `internal/debug` | pprof endpoint registration with no testable decision logic; exercised by `internal/admin` integration tests. |
| `test/provider/external.go` | Credential-gated external S3 providers (AWS, Wasabi, B2) — only reachable in nightly external-provider CI runs. |
| `test/provider/cosmian.go` | Requires a live Cosmian KMS container and credentials — covered by nightly KMS conformance run. |
| `test/harness` | In-process gateway harness used exclusively by tier-2 conformance tests (requires Docker / Testcontainers). |
| `test/provider` | S3 provider registration and discovery code; covered by tier-2 conformance CI. |

To add a new exclusion, append to `scripts/coverage-exclude.txt` with a rationale
comment and open a PR for review. Do not exclude packages without a documented
reason.

## Mutation testing

Nightly mutation testing runs via [Gremlins](https://github.com/go-gremlins/gremlins)
on the schedule defined in `.github/workflows/mutation.yml` (03:00 UTC).

Scope:

| Package | Kill-rate target |
|---|---|
| `internal/config` | ≥ 70% |
| `internal/api` | ≥ 70% |
| `internal/s3` | ≥ 70% |
| `internal/middleware` | ≥ 70% |

`internal/crypto` is excluded from mutation testing and covered by fuzz testing
instead (see `make test-fuzz`). The crypto primitives are well-tested by the
conformance suite and property-based tests; mutating them tends to produce
trivially-killed mutations that add noise without signal.

### Running locally

```bash
# Install Gremlins
go install github.com/go-gremlins/gremlins/cmd/gremlins@latest

# Run against a single package
gremlins unleash ./internal/config/...

# Full mutation run (CI-equivalent)
make mutation-report

# Single package
make mutation-report-pkg PKG=./internal/config/...
```

## Regenerating the coverage report

```bash
make coverage-gate        # generates coverage.out
make coverage-html        # opens coverage.html in the default browser
```

The CI artifact `coverage-report.html` is uploaded on every run of the
`coverage-gate` job and is available for 30 days.

## Cross-references

- V0.6-QA-2 plan: `docs/plans/V0.6-QA-2-plan.md`
- CI job: `.github/workflows/conformance.yml` → `coverage-gate`
- Mutation workflow: `.github/workflows/mutation.yml`
- Exclusion list: `scripts/coverage-exclude.txt`
- Performance baselines: `docs/PERFORMANCE.md` (V0.6-QA-1)
