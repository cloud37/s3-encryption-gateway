# Roadmap

This roadmap outlines potential future improvements, grouped by milestones and tracks. Timelines are indicative and may shift based on feedback and priorities.

## Milestone v0.4 (Near-term: 1–2 months)

- Security/Crypto
  - Range-optimized decryption hardening
    - Add table-driven tests for Content-Range correctness and partial reads on chunk boundaries.
    - Validate ETag and size reporting for ranged and full responses.
  - Metadata compaction policy
    - Ensure encryption/compression metadata stays within provider limits; add provider profiles.

- S3 Compatibility
  - Expand List operations (delimiter, continuation tokens) parity tests.
  - Multipart stability
    - Fuzz XML parsers for CompleteMultipartUpload.
    - Tests for interop with AWS/MinIO multipart flows.

- Performance
  - Buffer pooling for small reads/writes; eliminate unnecessary allocations.
  - Backpressure & streaming tuning for large objects.

- Observability
  - OpenTelemetry tracing (HTTP + S3 spans), optional sampling.
  - Access log presets (JSON, Common Log Format), redaction of sensitive headers.

- Operations & Helm/K8s
  - Ingress template (optional), PodDisruptionBudget, topologySpreadConstraints.
  - PodMonitor alternative to ServiceMonitor.
  - Extra knobs: extraEnv, extraVolumeMounts, extraVolumes, initContainers, sidecars.

- Config & UX
  - Hot-reload of config (SIGHUP/file watch) for non-crypto knobs.
  - Config schema docs (types, units, env var mapping).

- Testing & Quality
  - E2E matrix: AWS S3, MinIO, Wasabi, Hetzner.
  - Load/regression suite for range + multipart.

- Docs
  - Exported diagrams (SVG) and ADRs for range optimization and multipart decisions.

## Milestone v0.5 (Mid-term: 2–3 months)

- Security/Crypto
  - External KMS integrations (AWS KMS, HashiCorp Vault Transit)
    - Envelope encryption, key version tracking in metadata.
    - Rotation policy and grace windows.

- S3 Compatibility
  - Presigned URL compatibility guide and tests.
  - Object tagging and metadata passthrough refinements.

- Performance
  - Parallel chunk encryption/decryption pipeline (bounded concurrency).
  - AES-NI/ARM crypto acceleration detection with feature flags.

- Observability
  - Metrics cardinality controls and exemplars for traces.
  - Structured audit log sink integrations (Loki/ELK/OpenSearch).

- Operations & Helm/K8s
  - Hardened securityContext presets; restricted PSP/PodSecurity docs.
  - Example NetworkPolicies for common cluster topologies.

- Config & UX
  - Per-bucket/tenant settings (keys, compression, limits) via policy files.

- Testing & Quality
  - Chaos tests: backend throttling/500s, network partitions.
  - Fuzzers for metadata parsing and range math.

- Docs
  - Threat model (STRIDE) and mitigations; security hardening guide.

## Milestone v0.6 (Mid-term: 3–5 months)

- Security/Crypto
  - Pluggable KeyManager interface; HSM-friendly adapters.
  - Optional FIPS-compliant crypto build profile.

- S3 Compatibility
  - Multipart copy support and tests.
  - Object Lock/Retention pass-through guidance and tests.

- Performance
  - Zero-copy streaming paths where feasible; memory usage dashboards.
  - Retry policy customization and exponential backoff tuning.

- Observability
  - pprof endpoints gated behind admin flag; runtime profiling recipes.

- Operations & Helm/K8s
  - ✅ Blue/green and canary examples (V0.6-OPS-1) — see `docs/OPS_DEPLOYMENT.md`.
  - ✅ Helm values validation (schema/JSONSchema) and default overlays (V0.6-OPS-2) — see `docs/plans/V0.6-OPS-2-plan.md`.

- Config & UX
  - Admin API for safe key rotation operations (drain + cutover).

- Testing & Quality
  - ✅ Performance baseline per provider (V0.6-QA-1) — see [`docs/PERFORMANCE.md`](PERFORMANCE.md) and [`docs/plans/V0.6-QA-1-plan.md`](plans/V0.6-QA-1-plan.md).
  - ✅ Coverage gate (≥75%) and mutation testing on critical crypto-free code (V0.6-QA-2) — see [`docs/COVERAGE.md`](COVERAGE.md).

- Docs
  - Migration guide for enabling KMS mode from single-password mode.

## Milestone v1.0 (Long-term)

- Security/Crypto
  - Full KMS production readiness (HA, caching, failure modes).
  - Sensitive data zeroization paths; audit for constant-time comparisons where applicable.

- S3 Compatibility
  - ✅ **V1.0-S3-2**: S3 API Feature Parity — ~35 new operations implemented (all T1/T2/T3 handlers).
  - Broad feature parity: tagging, ACLs, lifecycle headers passthrough.
  - Compatibility certification matrix (SDKs/tools).

- Performance & Scalability
  - Horizontal scale guidance; autoscaling SLOs and tuned HPA.
  - High-throughput benchmarks with published results.

- Observability
  - Turnkey dashboards (Grafana) and alerting rules.

- Operations & Helm/K8s
  - Multi-arch images, SBOMs, provenance (SLSA) for releases.
  - Helm chart published on Artifact Hub with automated checks.

- Ecosystem
  - Additional backends (via shims): GCS, Azure Blob, filesystem (for dev).
  - CLI for local testing and debugging (presign, quick put/get).

## Backlog Ideas

- Metadata encryption/compaction for providers with strict header limits.
- Adaptive compression based on content sampling and size.
- Pluggable authorization layer (optional) for multi-tenant deployments.
- QUIC/HTTP3 support when upstream libs stabilize.
- Cryptographic log integrity for audit trails.
- Optional digital signatures for operation verification.

## Acceptance Criteria Examples

- Range Optimization: 100% pass on table-driven tests for edge ranges; <5% error in time-to-first-byte vs plaintext baseline for chunked.
- KMS Integration: Successful encrypt/decrypt with external KMS, seamless rotation with dual-read window, audited events.
- Helm: Install with Ingress/PDB/topologySpreadConstraints; NetworkPolicy egress/ingress examples; lint passes; values schema present.
- Observability: OTEL traces visible in chosen backend; dashboards provided; metrics cardinality bounded under load.

## Versioning & Releases

- Semantic versioning with changelogs, upgrade notes, and migration guides.
- Release artifacts: images (multi-arch), chart updates, docs site refresh.

