# V1.0-PERF-1 — Load Profile Reference Corpus

This directory contains NDJSON output from the four named load profiles
defined in [`docs/plans/V1.0-PERF-1-plan.md`](../../plans/V1.0-PERF-1-plan.md).

## Files

| File | Profile | Workers | Duration | Object size | Part size |
|---|---|---|---|---|---|
| `smoke.ndjson` | smoke | 3 | 10 s | 100 KiB | 5 MiB |
| `soak.ndjson` | soak | 10 | 60 s | 50 MiB | 10 MiB |
| `spike.ndjson` | spike | 50 | 60 s | 100 KiB | 5 MiB |
| `high-throughput.ndjson` | high-throughput | 5 | 120 s | 50 MiB | 10 MiB |

## NDJSON Schema

Every line is a JSON object with the following fields:

| Field | Type | Description |
|---|---|---|
| `test` | string | `Load_RangeRead` or `Load_Multipart` |
| `throughput_mbps` | float | Aggregate throughput in MB/s |
| `latency_ns.p50` | int | Median latency in nanoseconds |
| `latency_ns.p95` | int | 95th percentile latency in nanoseconds |
| `latency_ns.p99` | int | 99th percentile latency in nanoseconds |
| `errors` | int | Number of failed requests (must be 0) |
| `retries_total` | int | Total S3 client retries across workers |
| `heap_inuse_max_bytes` | int | Peak heap-in-use during the run |
| `cpu_seconds` | float | Approximate total CPU time |

## Runner Class

All profiles were run against the MinIO Testcontainer backend on a
c5.2xlarge-class runner (8 vCPU, 16 GB RAM). Numbers are not directly
comparable across different runner classes.

## Regenerating

```bash
make bench-load-capture
```

Re-runs all four profiles and overwrites the files in this directory.

See also: [`docs/SCALING.md`](../../SCALING.md) §6.
