# Performance, Benchmarks, and Scaling

This page is the public face of the V0.6-QA-1 per-provider performance
baseline corpus. The detailed implementation plan lives at
[`docs/plans/V0.6-QA-1-plan.md`](plans/V0.6-QA-1-plan.md); the raw artefacts
(committed, per-milestone) live under [`docs/perf/v0.6-qa-1/`](perf/v0.6-qa-1/).

## 1. Overview

## Contents

- [Benchmark methodology](#2-methodology)
- [Baseline evidence](#3-per-provider-baseline-table)
- [Regeneration and thresholds](#5-how-to-regenerate)
- [Encryption-mode benchmarks](#encryption-mode-benchmarks)
- [Horizontal scaling](#horizontal-scaling)
- [HPA and graceful shutdown](#hpa-and-graceful-shutdown)
- [Valkey and spool capacity](#valkey-and-spool-capacity)

Measurements below are evidence from specified workloads, not performance promises
or universal replica/resource recommendations. Use current toolchain/config/provider
versions and compare like-for-like before deployment sizing.

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
- [Horizontal scaling](#horizontal-scaling): high-concurrency profiling, HPA,
  resource/state/disk accounting and SLOs in this guide.

## Encryption-Mode Benchmarks

Historical `make benchmark-local` results used 5-second runs, four concurrent
workers, and local backends; ranges below exclude the slowest backend bottleneck.
These are workload-specific comparisons, not proof of equivalent KDF security or
current absolute throughput on another deployment. See mode choices in
[key management](KMS_COMPATIBILITY.md#choosing-an-encryption-mode).

| Mode | Chunked PUT 1 MiB (Mbps) | MPU 4×50 MiB (Mbps) | Range 200 KiB, five ranges (Mbps) |
|---|---|---|---|
| PBKDF2 600k | 45–49 | 92–96 | 2.3–2.5 |
| PBKDF2 100k (legacy comparison, not recommended default) | 250–264 | 192–224 | 13.4–13.8 |
| Argon2id t=2/m=19456 KiB/p=1 | 199–209 | 176–208 | 10.3–10.5 |
| AES-GCM local KEK | 2387–3710 | 236–304 | 111–172 |
| RSA-OAEP local KEK | 1705–2266 | 240–292 | 97–111 |
| Cosmian local test KMS | 1949–3010 | 236–288 | 95–141 |

Envelope mode avoids password derivation on ordinary object hot paths. MPU costs,
remote KMS latency, network ceilings, concurrency, and caching change the comparison.
Local KMIP latency is not a guarantee for remote production KMS. Regenerate on your
hardware; keep committed [benchmark evidence](perf/) unchanged as historical data.

## Horizontal Scaling

Replicas share backend/key configuration and Valkey MPU state/size-cache authority;
per-process spools/caches/admin promotion state are not shared. “Stateless HTTP”
does not mean no cross-replica coordination is needed for state versions, key
rollouts, or local admin rotation. Consult [progressive delivery](OPS_DEPLOYMENT.md)
and [migration](MIGRATION.md).

| Bottleneck | Signal | Action to test |
|---|---|---|
| CPU/KDF | CPU saturation and high p99 | Envelope mode if appropriate; scale replicas |
| Memory/buffering | Heap/GC/OOM and simultaneous copy/part load | Account per-part/copy cap × concurrency, not just chunk size |
| Valkey | State operation latency/timeouts, memory pressure | Size persistence/pool/server; don't create isolated per-replica state |
| KMS | Wrap/unwrap failures/latency | Provider quota/auth/TLS; optional sensitive DEK cache |
| Network/backend | Flat throughput, upstream throttling | Measure backend baseline and traffic amplification |
| Spool/disk | 503 SlowDown/admission pressure | Size process aggregate budget and node ephemeral storage |

### Historical sizing evidence

Local workstation spike-profile measurements (100 KiB objects, MinIO, 60 seconds)
reported ~3.1/7.5/15/28 MB/s at 10/25/50/100 clients, with p99 PUT approximately
100/200/370/700 ms. These do not establish that 200m CPU or a fixed replica count
satisfies your current workload. Measure object/part size, KDF/provider, disk,
concurrency, request retries, and backend latency before deriving resources.

## HPA and Graceful Shutdown

The maintained [HPA example](../helm/s3-encryption-gateway/examples/values-hpa-tuned.yaml)
provides CPU/memory targets and asymmetric stabilization; the
[KEDA example](../helm/s3-encryption-gateway/examples/values-keda-example.yaml)
shows custom metrics. Inspect current chart schema rather than copying a second
full values table. KEDA example divisors need kube-state-metrics or a deliberate
alternative. Scale-to-zero is not an automatic recommendation for an always-needed
S3 endpoint.

Choose termination grace from measured p99 longest part/request latency plus
routing propagation and preStop drain time. A nominal 120-second/50-MiB example
is a starting experiment, not guaranteed safety. Completed durable parts can be
retried through another compatible replica; ambiguous reservations may need the
bounded lease to expire. Clients must retry identical content, not replace a claim.

### Load profiles and SLOs

```bash
make test-load-smoke
make test-load-soak
make test-load-spike
make test-load-high-throughput
make bench-load-capture
```

Current named preset parameters live in Makefile: smoke 3 workers/10s/100 KiB;
soak 10/60s/50 MiB/10 MiB parts; spike 50/60s/100 KiB;
high-throughput 5/120s/50 MiB/10 MiB parts. Some labels/comments are historical;
the actual environment and test invocation determine workload.

Capture NDJSON throughput, latency p50/p95/p99, errors, retries, and heap high-water
marks. A throughput_mbps field may describe MB/s in the harness—verify units in
source before conversion. Define availability/latency/throughput SLOs for your
workload; 99.9%/30-day availability allows ~43.2 minutes, not proof CI meets it.
Alert on rate/burn behavior through [observability](OBSERVABILITY.md).

## Valkey and Spool Capacity

State memory is proportional to **concurrent uploads × parts per upload**, plus
metadata/envelope/protocol overhead and size-cache entries. Historical rough input
of 1 KiB/upload + 200 B/part with 2× headroom gives:

```text
estimated bytes = uploads × (1024 + parts × 200) × 2
```

For 1,000×100 parts that is ~40 MiB; 5,000×1,000 ~1.9 GiB;
10,000×10,000 ~37 GiB—not 4 GiB. Current encrypted claims/keys, allocator overhead,
replication/persistence buffers, and permanent size-cache entries require measured
headroom beyond this rough model. Use real state snapshots/load tests and never
apply the old inconsistent sizing examples as limits. TTL expiry can orphan uploads;
keep the wrapped state DEK and backup dependencies separate from disposable records.

Verified spools default to 5 GiB/request and 10 GiB/process aggregate. N replicas
can consume N times the process capacity, subject to shared node/backend limits.
Ephemeral storage must cover the admitted budget; do not put plaintext spools on
unbounded or publicly readable storage. 503 SlowDown is a retryable admission
signal, not a reason to disable payload verification. Also size 64 MiB default
part buffers and 256 MiB legacy copy caps × active concurrency.

### Capacity planning checklist

1. Inventory object/part sizes, concurrency, KDF/key provider, and listing/copy patterns.
2. Measure baseline backend/KMS/state latency and disk/heap peaks.
3. Size shared Valkey persistence and key recovery; account size-cache growth.
4. Size per-replica CPU/memory/spool and node limits; configure HPA/draining.
5. Test spike/soak/long-request/identical-retry behavior and fleet upgrade/rollback.
6. Record workload-specific SLOs and retained benchmark artifacts.
