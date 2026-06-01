# Performance

This page is the public face of the V0.6-QA-1 per-provider performance
baseline corpus. The detailed implementation plan lives at
[`docs/plans/V0.6-QA-1-plan.md`](plans/V0.6-QA-1-plan.md); the raw artefacts
(committed, per-milestone) live under [`docs/perf/v0.6-qa-1/`](perf/v0.6-qa-1/).

## 1. Overview

We track two distinct classes of measurement:

1. **Micro-benchmarks** — standard Go `testing.B` functions covering the
   AEAD encryption engine, MPU encrypt/decrypt streaming readers, and
   S3-client retry paths. Run with `benchstat`; 19 tracked functions. These
   are the canonical nightly regression signal for anything crypto- or
   retry-sensitive.
2. **Per-provider macro / soak** — an in-process gateway drives
   `Load_RangeRead` and `Load_Multipart` against one Testcontainers-Go
   backend at a time (MinIO, Garage, RustFS, SeaweedFS), emitting
   structured JSON with p50/p95/p99 latency, throughput in MB/s, heap
   high-water-mark, and total retry count. These answer "does MinIO behave
   the same as Garage under the PERF-1 streaming path?".

We explicitly do *not* chase absolute numbers. CI runners drift; thresholds
are tuned to catch **deltas against the committed baseline for the same
runner class** (`github-ubuntu-latest`). See §6 for the threshold table.

## 2. Methodology

Summary of the canonical invocation — see [plan §3](plans/V0.6-QA-1-plan.md#3-methodology)
for citations and rationale.

### 2.1 Micro

```bash
go test -run='^$' \
        -bench='^Benchmark' \
        -benchmem \
        -benchtime=10s \
        -count=10 \
        -cpu=4 \
        -timeout=30m \
        ./internal/crypto/... ./internal/s3/...
```

- `-count=10` is what `benchstat` needs for a meaningful t-test.
- `-cpu=4` removes GOMAXPROCS drift between runner classes.
- `-race` is **off** — it inflates CPU 2-5× and destroys signal.
- Comparison via `benchstat old.txt new.txt`; regression thresholds in §6.

### 2.2 Macro (per provider)

The soak harness at `test/conformance/load_test.go` runs against one
Testcontainer at a time with the following fixture (plan §3.2):

| Env var | Baseline value |
|---|---|
| `SOAK_WORKERS` | 10 |
| `SOAK_DURATION` | 60s |
| `SOAK_QPS` | 25 |
| `SOAK_OBJECT_SIZE` | 52428800 (50 MiB) |
| `SOAK_CHUNK_SIZE` | 65536 (64 KiB) |
| `SOAK_PART_SIZE` | 10485760 (10 MiB) |
| `SOAK_JSON_OUT` | `<auto>` — toggled by `bench-macro.sh` |

Structured output is appended one JSON object per line (NDJSON) and then
wrapped by `scripts/bench-macro.sh` into the `macro-<provider>.json` schema
(plan §4.2).

### 2.3 Runner class

All committed numbers come from `github-ubuntu-latest` (currently 2 vCPU,
7 GB RAM). Laptops / Apple silicon produce different numbers — the
infrastructure records `GOARCH`/`GOOS` in every header so drift is visible.
Developers comparing laptop deltas should use their own previous run as
the baseline, not the committed one.

## 3. Per-provider baseline table

Committed numbers live in [`docs/perf/v0.6-qa-1/slo-summary.md`](perf/v0.6-qa-1/slo-summary.md).
At initial infrastructure land all values are **TBD**; the first green
nightly `performance-baseline` workflow on `main` will populate them.

### <a name="circuit-breaker-decision-input"></a>Circuit-breaker decision input

[ADR 0010 §B](adr/0010-backend-retry-policy.md#b-circuit-breakers) defers
the circuit-breaker v0.7 decision to "real-world data from V0.6-QA-1
baselines". The SLO annex at
[`docs/perf/v0.6-qa-1/slo-summary.md`](perf/v0.6-qa-1/slo-summary.md) is
that corpus. Until three green nightlies have populated the p99 columns,
the ADR retains the "deferred" state.

## 4. Micro-benchmark highlights

The 19 tracked functions are listed in
[plan §5.3](plans/V0.6-QA-1-plan.md#53-benchmark-inventory-after-qa-1).
The raw baseline lives at
[`docs/perf/v0.6-qa-1/micro-baseline.txt`](perf/v0.6-qa-1/micro-baseline.txt).
For a per-function table (ns/op, MB/s, allocs/op) pull the committed file
into `benchstat`:

```bash
benchstat docs/perf/v0.6-qa-1/micro-baseline.txt
```

## 5. How to regenerate

```bash
# Prereqs: Docker, Go ≥ 1.25, benchstat, jq.
go install golang.org/x/perf/cmd/benchstat@latest

make bench-baseline              # micro + all four macros (~30-40 min on CI)
make bench-micro-baseline        # micro only
make bench-macro-minio           # one provider

# Inspect deltas:
benchstat \
  docs/perf/v0.6-qa-1/micro-baseline.txt \
  /tmp/new.txt
```

The nightly workflow does exactly this; see
[`.github/workflows/performance-baseline.yml`](../.github/workflows/performance-baseline.yml).

Trigger the nightly manually:

```bash
gh workflow run performance-baseline.yml --ref main
gh run watch
```

### 5.1 Updating the baseline after an intentional regression

A PR that knowingly changes performance (e.g. a security hardening that
costs throughput) files the refreshed baseline in the same PR:

```bash
make bench-baseline
git add docs/perf/v0.6-qa-1/
git commit -m "perf: refresh QA-1 baseline after <feature>"
```

Plus a CHANGELOG entry explaining the delta. The nightly then runs green
against the updated baseline.

## 6. Regression thresholds

From [plan §6.1](plans/V0.6-QA-1-plan.md#61-threshold-table):

| Metric class | Tracked statistic | Regress = fail nightly if |
|---|---|---|
| Micro ns/op | `benchstat` geomean p < 0.05 | Δ > +15 % |
| Micro B/op | `benchstat` geomean p < 0.05 | Δ > +20 % |
| Micro allocs/op | — | Δ > 0 (any new allocation) |
| Macro throughput | `throughput_mbps` | Δ < −15 % |
| Macro latency p95 | `latency_ns.p95` | Δ > +20 % |
| Macro latency p99 | `latency_ns.p99` | Δ > +25 % |
| Macro heap HWM | `heap_inuse_max_bytes` | Δ > +25 % |
| Macro errors | `errors` | any non-zero where baseline = 0 |
| Macro retries_total | `retries_total` | Δ > +50 % (WARN only — informational) |

The asymmetric allocs/op threshold is deliberate: a new allocation in
`NewMPUPartEncryptReader`'s hot path silently defeats the PERF-1 streaming
rewrite, so we want it to trip immediately. Other thresholds survive the
~5-20 % per-benchmark standard deviations documented for shared-tenant CI
runners.

## 7. Interpreting a regression alert

When the nightly fails, a `perf-regression`-labelled issue is opened (or
existing one re-commented on). The issue body contains:

1. A link to the failing workflow run (always archives the artefacts:
   `baseline.json`, `new.json`, `compare.txt`).
2. The comparator output (regression list with per-metric deltas).

The triage workflow (plan §3.3 / §9.2):

1. Download the artefacts and `benchstat baseline.txt new.txt`.
2. If the regression is **not** local to a single benchmark, suspect the
   runner class (Go minor-version bump, base image update). Re-run the
   nightly via `gh workflow run performance-baseline.yml`.
3. If the regression persists, run a profile deep-dive: `make
   profile-image` + `/admin/debug/pprof` (V0.6-OBS-1).
4. The fix is one of: (a) revert the suspect commit, (b) fix the
   regression, or (c) deliberately bump the baseline (plan §6.2) with a
   CHANGELOG entry.

## 8. PR advisory comment

Every pull request to `main` gets a **sticky comment** with a benchstat
delta vs the committed micro baseline. The comment runs a quick 3×3 s
micro variant (~6 min) and **never fails the PR** — CI runners are noisy
enough that per-PR gating would produce false-positives. The advisory's
job is to surface obviously catastrophic changes early so authors can
address them or ship the matching baseline refresh.

## 9. Cross-references

- ADR 0010 — Backend Retry Policy — [`docs/adr/0010-backend-retry-policy.md`](adr/0010-backend-retry-policy.md)
- Roadmap "Performance baseline per provider" — [`docs/ROADMAP.md`](ROADMAP.md)
- Plan — [`docs/plans/V0.6-QA-1-plan.md`](plans/V0.6-QA-1-plan.md)
- SLO annex — [`docs/perf/v0.6-qa-1/slo-summary.md`](perf/v0.6-qa-1/slo-summary.md)
- **V1.0-PERF-1 -- Horizontal Scaling Guide** — [`docs/SCALING.md`](SCALING.md).
  Supplements the V0.6-QA-1 baseline with high-concurrency profiling data,
  tuned HPA configuration, empirical sizing tables, and SLO definitions
  for horizontal autoscaling.
