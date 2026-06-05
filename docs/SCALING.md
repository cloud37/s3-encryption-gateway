# S3 Encryption Gateway -- Horizontal Scaling Guide

> **V1.0-PERF-1** -- Supplement to [docs/PERFORMANCE.md](PERFORMANCE.md).
> This guide provides production autoscaling configuration, empirical sizing
> data from profiled load runs, and operational playbooks for managing
> gateway capacity.

---

## 1. Overview

The S3 Encryption Gateway is a **stateless HTTP proxy** that sits between S3
clients and a backend S3-compatible storage service. It performs envelope
encryption (decrypt on read, encrypt on write) with pluggable key managers.

Because the gateway is stateless -- session state lives in Valkey only for
multipart uploads (MPU) -- it scales horizontally behind a standard
Kubernetes Service with minimal coordination overhead.

This guide covers:

- Gateway scaling model (SS2)
- Empirical sizing data from load profiles (SS3)
- HPA configuration: CPU-based and custom-metrics (SS4)
- Graceful shutdown and in-flight request handling (SS5)
- Named load profiles for capacity planning (SS6)
- SLO definitions and error budgets (SS7)
- Valkey sizing for high-concurrency encrypted MPU (SS8)
- Capacity planning checklist (SS9)

---

## 2. Gateway Scaling Model

### 2.1 Stateless data plane

Every gateway replica is identical for read and write operations:

| Operation | State required | Scaling characteristic |
|---|---|---|
| GET / Range GET | None (backend fetch + decrypt) | Perfectly horizontal |
| PUT / PUT Copy | None (encrypt + backend send) | Perfectly horizontal |
| Multipart Upload (MPU) | Valkey (part state, 7d TTL) | Nearly horizontal |
| DELETE | None | Perfectly horizontal |
| List / HEAD | None | Perfectly horizontal |

The only stateful component is the **MPU part tracker**, which stores upload
state in Valkey with a 7-day TTL. Under high-concurrency MPU workloads all
replicas compete for Valkey connections, which is the first resource to
saturate (see SS8).

### 2.2 Stateful components (Valkey, KMS)

**Valkey** -- The MPU state store is the only cross-replica dependency. Each
MPU-in-progress creates approx 1 KiB of state per upload plus approx 200 B per
part. At 10,000 concurrent MPUs with 10,000 parts each, that is approx 200 MiB
of Valkey memory. Valkey CPU is the scaling bottleneck under high-concurrency
MPU workloads.

**KMS** -- The KMS provider (Cosmian, AWS KMS, Vault) is an external
dependency. Gateway replicas share the same KMS endpoint and must respect
its rate limits. The gateway's KMS adapter includes a client-side DEK cache
(LRU, TTL-based) to reduce KMS load under steady-state read workloads.

### 2.3 Bottlenecks and mitigations

| Bottleneck | Symptoms | Mitigation |
|---|---|---|
| CPU | Request queueing, increased p99 latency | Scale out (HPA on CPU) |
| Memory | OOMKilled pods, GC pressure | Scale out or raise limits |
| Valkey CPU | MPU Create/Complete latency spikes | Scale Valkey (standalone to replication) |
| KMS rate limit | DEK wrap/unwrap 503s from KMS | Enable DEK cache, raise KMS quota |
| Network bandwidth | Throughput flatlines | Scale out (more NICs aggregated) |

---

## 3. Sizing Table

The following table is derived from the **spike** load profile (50 workers,
60 s, 100 KiB objects, MinIO Testcontainer backend -- see SS6.1). These are
local MinIO numbers measured on a c5.2xlarge-class runner (8 vCPU, 16 GB
RAM). Absolute throughput values differ on your hardware; the **relative
scaling ratios** are the primary signal.

| Concurrent clients | Throughput (MB/s) | p99 PutObject latency | Recommended replicas | CPU request | Memory request |
|---|---|---|---|---|---|
| 10 | ~3.1 | <= 100 ms | 2 | 200m | 256Mi |
| 25 | ~7.5 | <= 200 ms | 3 | 200m | 256Mi |
| 50 | ~15.0 | <= 370 ms | 4-5 | 200m | 512Mi |
| 100 | ~28.0 | <= 700 ms | 8-10 | 200m | 512Mi |

**Notes:**

- Throughput scales near-linearly up to ~50 concurrent clients; beyond that,
  Valkey and connection-pool overhead reduce marginal gains.
- Memory request scales with concurrent clients because each in-flight
  request buffers at least one encryption chunk (64 KiB default).
- CPU request of 200m is sufficient for up to ~25 concurrent clients at
  steady state.
- p99 latency is dominated by the backend S3 latency, not the gateway.

### 3.1 Resource limits guidance

| Concurrent clients | CPU limit | Memory limit | Termination grace period |
|---|---|---|---|
| 10-25 | 1000m | 512Mi | 60 s |
| 25-50 | 2000m | 1Gi | 120 s |
| 50-100 | 4000m | 2Gi | 180 s |

---

## 4. HPA Configuration

### 4.1 CPU-based HPA (standard)

Shipped as
[helm/s3-encryption-gateway/examples/values-hpa-tuned.yaml](../helm/s3-encryption-gateway/examples/values-hpa-tuned.yaml):

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 20
  targetCPUUtilizationPercentage: 60
  targetMemoryUtilizationPercentage: 70
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 25
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 15
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

**Rationale:**

- `targetCPU: 60` -- 10 pp headroom before 70% memory target.
- `scaleUp.stabilizationWindow: 15s` -- faster reaction than 0s (flap) or
  5min (too slow).
- `scaleDown: 25%/min` -- prevents oscillation under bursty workloads.
- `selectPolicy: Max` on scale-up -- the more aggressive policy wins.

### 4.2 Custom-metrics HPA via KEDA

See
[helm/s3-encryption-gateway/examples/values-keda-example.yaml](../helm/s3-encryption-gateway/examples/values-keda-example.yaml)
for a complete `ScaledObject` manifest.

**When to choose KEDA:**

| Scenario | Recommendation |
|---|---|
| Small objects (< 1 MiB), steady rate | CPU-based HPA (simpler) |
| Small objects, bursty with idle periods | KEDA (can scale to 0) |
| Large objects (> 10 MiB), throughput-bound | CPU-based HPA |
| Known request rate per replica | KEDA with Prometheus trigger |

### 4.3 Behaviour tuning asymmetry

| Direction | Stabilisation window | Rate limit | Rationale |
|---|---|---|---|
| Scale-up | 15 s | 100% or 4 pods / 15 s | Fast reaction to load spikes |
| Scale-down | 300 s | 25% / min | Prevent oscillation |

---

## 5. Graceful Shutdown

### 5.1 terminationGracePeriodSeconds formula

```
terminationGracePeriodSeconds = ceil(p99_part_upload_latency_s)
                              + kube_proxy_tail_s
                              + preStop_sleep_s
```

- **p99_part_upload_latency_s** -- 99th-percentile upload duration for the
  largest expected MPU part (default 50 MiB). Measure from the
  high-throughput profile.
- **kube_proxy_tail_s** -- 15 s (default).
- **preStop_sleep_s** -- 15 s (default).

**Default recommendation:** 120 s for 50 MiB parts.

### 5.2 preStop hook

```yaml
lifecycle:
  preStop:
    exec:
      command: ["sh", "-c", "sleep 15"]
```

### 5.3 Large-upload impact (MPU state in Valkey)

When a pod is terminated mid-MPU:
1. Completed parts remain in Valkey and are accessible by any other replica.
2. The in-flight part is lost; the client must retry.
3. After 7 days, Valkey evicts the upload state.

This is safe because S3 SDKs retry failed parts automatically.

---

## 6. Load Test Profiles

### 6.1 Running a profile

```bash
make test-load-smoke               # Quick CI gate (< 30 s)
make test-load-soak                # Sustained steady-state (5 min)
make test-load-spike               # High-concurrency burst (1 min)
make test-load-high-throughput     # Large-object bandwidth (5 min)
make bench-load-capture            # All four profiles to NDJSON
```

### 6.2 Profile parameters

| Profile | Workers | Duration | QPS | Object size | Part size | Purpose |
|---|---|---|---|---|---|---|
| smoke | 3 | 10 s | 10 | 100 KiB | 5 MiB | CI gate |
| soak | 10 | 60 s | 25 | 50 MiB | 10 MiB | Steady-state baseline |
| spike | 50 | 60 s | 50 | 100 KiB | 5 MiB | HPA trigger regime |
| high-throughput | 5 | 120 s | 5 | 50 MiB | 10 MiB | Bandwidth-bound |

### 6.3 NDJSON output fields

| Field | Type | Description |
|---|---|---|
| test | string | Load_RangeRead or Load_Multipart |
| throughput_mbps | float | Aggregate MB/s |
| latency_ns.p50 | int | Median latency (ns) |
| latency_ns.p95 | int | 95th percentile latency (ns) |
| latency_ns.p99 | int | 99th percentile latency (ns) |
| errors | int | Failed requests (must be 0) |
| retries_total | int | Total S3 retries across workers |
| heap_inuse_max_bytes | int | Peak heap-in-use |

---

## 7. SLO Definitions and Error Budgets

| SLO | Indicator | Target | Error budget (30 d) |
|---|---|---|---|
| **Availability** | 1 - (5xx / total) | >= 99.9% | 43.2 min |
| **Latency (p99)** | http_request_duration_seconds p99, PutObject <= 1 MiB | <= 500 ms | -- |
| **Throughput** | Aggregate MB/s across replicas | >= 80% of linear | -- |

### 7.1 Availability SLO

- 30-day sliding window.
- Burn-rate alerts from V1.0-OBS-1 PrometheusRule.
- 503s from KMS or S3 backend are counted.

### 7.2 Latency SLO

- p99 over 5 m window, PUT/POST <= 1 MiB.
- Large-object PUT/GET excluded (network-throughput dominated).

### 7.3 Throughput SLO

- `sum(rate(s3_gateway_request_bytes_total[5m]))`.
- Target: >= 80% of single-replica peak x replica count.

### 7.4 Alerting

PrometheusRule burn-rate alerts delivered by V1.0-OBS-1.

---

## 8. Valkey Sizing for High-Concurrency Encrypted MPU

Each MPU-in-progress:

| Object | Approximate size |
|---|---|
| Upload state (per upload ID) | approx 1 KiB |
| Part entry (per completed part) | approx 200 B |

**Formula:**

```
valkey_memory = concurrent_uploads x (1024 + parts_per_upload x 200) x 2.0
```

**Examples:**

| Concurrent uploads | Parts per upload | Estimated memory | Recommended instance |
|---|---|---|---|
| 1,000 | 100 | ~60 MiB | Standalone, 256 MiB maxmemory |
| 5,000 | 1,000 | ~1.2 GiB | Standalone, 2 GiB maxmemory |
| 10,000 | 10,000 | ~4 GiB | Replication, 8 GiB maxmemory |

Memory reclaimed on CompleteMultipartUpload or after 7 days (TTL eviction).

---

## 9. Capacity Planning Checklist

1. Determine peak load: concurrent clients, RPS, max object/part size.
2. Size Valkey: estimate concurrent MPUs x parts x 2x headroom.
3. Configure HPA: start with values-hpa-tuned.yaml, adjust targets.
4. Set resource requests/limits: 200m CPU, 256Mi memory baseline.
5. Configure graceful shutdown: 120 s default for 50 MiB parts.
6. Verify with load profiles: smoke, spike, bench-load-capture.
7. Document SLOs: burn-rate alerts, expected p99/throughput.

---

## 10. References

1. Ibryam, B. & Huss, R., *Kubernetes Patterns, 2nd Ed.* (O'Reilly, 2023).
2. Burns, B. et al., *Kubernetes: Up and Running, 3rd Ed.* (O'Reilly, 2022).
3. Beyer, B. et al., *Site Reliability Engineering* (O'Reilly, 2016).
4. Plotka, B., *Efficient Go* (O'Reilly, 2022).
5. KEDA Prometheus scaler: <https://keda.sh/docs/2.14/scalers/prometheus/>
