# V0.6-QA-1 — SLO Annex

Values marked **TBD** are placeholders for providers not yet measured under the
V0.6-QA-1 soak profile. The MinIO column is populated from the V1.0-PERF-1
soak profile run (10 workers, 60 s, 50 MiB objects, MinIO Testcontainer).
Garage, RustFS, and SeaweedFS require the full `performance-baseline`
workflow on `main`.

Last updated: 2026-06-05.
Runner class: local developer workstation (EndeavourOS, AMD64, ~48 GB RAM, Docker via Testcontainers).

## Operation × Provider latency matrix (p95 / p99 in ms)

| Operation | MinIO p95/p99 | Garage p95/p99 | RustFS p95/p99 | SeaweedFS p95/p99 |
|---|---|---|---|---|
| `Load_RangeRead` (50 MiB obj, 64 KiB ranges, 10 workers, 25 QPS) | 231 / 256 | TBD / TBD | TBD / TBD | TBD / TBD |
| `Load_Multipart` (50 MiB obj, 10 MiB parts, 10 workers) | 104 / 115 | TBD / TBD | TBD / TBD | TBD / TBD |

> **V1.0-PERF-1 supplement:** MinIO soak values measured 2026-06-05.
> See `docs/SCALING.md` §3 for spike-profile (50 workers, 100 KiB objects)
> and high-throughput-profile (5 workers, 120 s, 50 MiB objects) latency
> tables derived from `docs/perf/v1.0-perf-1/`.

## Throughput matrix (MB/s)

| Operation | MinIO | Garage | RustFS | SeaweedFS |
|---|---|---|---|---|
| `Load_RangeRead` | 113 | TBD | TBD | TBD |
| `Load_Multipart` | 1500 | TBD | TBD | TBD |

> **V1.0-PERF-1 supplement:** MinIO soak throughput values measured
> 2026-06-05. See `docs/SCALING.md` §3 for a concurrent-client sizing table
> with per-replica throughput estimates from the spike profile.

## V1.0-PERF-1 — Gateway SLOs

Three gateway SLOs defined by [`docs/plans/V1.0-PERF-1-plan.md`](../../plans/V1.0-PERF-1-plan.md)
§3.2, measured over a 30-day rolling window:

| SLO | Indicator | Target | Error budget (30 d) |
|---|---|---|---|
| **Availability** | 1 - (5xx / total) via `http_requests_total{status=~"5.."}` | >= 99.9% | 43.2 min |
| **Latency (p99)** | `http_request_duration_seconds` p99, PutObject <= 1 MiB | <= 500 ms | -- |
| **Throughput** | Aggregate MB/s across replicas | >= 80% of linear | -- |

Rationale and operational playbook: [`docs/SCALING.md`](../../SCALING.md) §7.

## V0.6-QA-1 Consumers

- **ADR 0010** (backend retry policy, circuit-breaker decision input) reads the
  p99 column to decide per-provider fallback cost.
  See [`docs/adr/0010-backend-retry-policy.md`](../../adr/0010-backend-retry-policy.md).
- **V0.6-PERF-2 Q2** (retry policy defaults) reads the p95 column.
- **README Performance section** links here for operator sizing estimates.
- **v0.7 / v1.0 roadmap** uses this as the baseline to beat.

## Regenerating

`make bench-baseline` re-runs the macro soak against every local provider
and overwrites `macro-<provider>.json`. Renumbering this table from those
files is scripted in the docs renderer (see `docs/PERFORMANCE.md`
§"How to regenerate").
