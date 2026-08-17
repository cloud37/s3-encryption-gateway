# ADR 0010 — Backend Retry Policy

**Status:** Accepted  
**Date:** 2026-04-23  
**Deciders:** Engineering  
**Milestone:** v0.6 — V0.6-PERF-2  
**Plan:** `docs/plans/V0.6-PERF-2-plan.md`

---

## Context

The S3 backend client (`internal/s3/client.go`) previously inherited the AWS
SDK Go V2 default retryer (`retry.Standard`) with no customisation:

| SDK default | Value |
|---|---|
| Retry mode | `aws.RetryModeStandard` |
| Max attempts | 3 (1 original + 2 retries) |
| Max backoff | 20 s |
| Backoff algorithm | Exponential, jittered (uniform, half of computed) |
| Retry-token bucket | 500 tokens, 5 per retryable failure |

This created four problems for the gateway's multi-provider deployment model
(MinIO, Garage, AWS, Wasabi, Hetzner, Backblaze B2):

1. **No operator control.** Transient backend overloads had no knobs to tune
   without a code change.
2. **No per-operation differentiation.** `CompleteMultipartUpload` (not
   idempotent post-commit) retried with the same policy as `HeadObject`
   (trivially idempotent).
3. **No observability.** Retries were invisible to Prometheus, OpenTelemetry
   spans, and audit logs.
4. **No budget enforcement.** Retry exhaustion was not surfaced as a clean
   `503` to the calling client.

Additionally, the SDK's `retry.Standard` does not classify HTTP 429
(`SlowDown`) as retryable via HTTP status alone (it requires an `ErrorCode`
match), which breaks against Hetzner and Wasabi backends that return 429
without a matching error code.

## Decision

Replace the SDK default retryer with a custom `aws.RetryerV2` implementation
in `internal/s3/retry.go` that:

1. **Operator-configurable** via a new `BackendRetryConfig` stanza in
   `BackendConfig` (YAML: `backend.retry.*`; env vars:
   `BACKEND_RETRY_MODE`, `BACKEND_RETRY_MAX_ATTEMPTS`, etc.).

2. **Four backoff algorithms** selectable at deploy time:
   - `full` (default) — uniform random in `[0, min(max, initial × 2^n)]`;
     best under unknown-N thundering herd (*DDIA 2E* §8.2).
   - `decorrelated` — `min(max, rand(3×prev) + initial)`; tighter tail
     under high contention.
   - `equal` — deterministic half + random half; simple and predictable.
   - `none` — pure exponential; debug only, unsafe under contention.

3. **Idempotency safeguards** hard-coded as defaults:
   - `CompleteMultipartUpload` → `max_attempts: 1` (non-idempotent
     post-commit; see §1.2 of the plan).
   - `CopyObject` retry gated on `safe_copy_object` (default `true`).

4. **Gateway-specific non-retryable classifier** (§4.4):
   - `context.Canceled` / `context.DeadlineExceeded`
   - All crypto sentinel errors (`ErrInvalidEnvelope`, `ErrUnwrapFailed`,
     `ErrKeyNotFound`, `ErrProviderUnavailable`)
   - Definite 4xx HTTP responses (400, 401, 403, 404, 405, 409, 411, 412,
     413, 415, 416, 422)

5. **Observable** via three new Prometheus metrics:
   - `s3_backend_retries_total{operation, reason, mode}`
   - `s3_backend_attempts_per_request{operation}`
   - `s3_backend_retry_give_ups_total{operation, final_reason}`
   - `s3_backend_retry_backoff_seconds` (histogram)

6. **Audit event** `backend.retry_give_up` emitted when a data-plane write
   operation exhausts all retry attempts. Read-path give-ups are
   counter-only (too chatty under normal backend hiccups).

7. **Context-aware sleep** via `clock.SleepContext` so that request
   cancellation interrupts a sleeping retry without goroutine leaks.

8. **`Retry-After` header honoured** for HTTP 429/503 responses; bounded
   at `2 × MaxBackoff` to prevent unbounded waits.

9. **`adaptive` mode** available for contended backends; wraps
   `retry.NewAdaptiveMode()` which adds a client-side token bucket.

10. **`off` mode** installs `NopRetryer` — exactly one attempt, no metrics;
    intended for debug and conformance-test isolation.

## Consequences

### Positive

- Operators can tune retry behaviour per environment without code changes.
- 429 and 503 responses from all tested backends (AWS, MinIO, Wasabi,
  Hetzner) are classified as retryable without relying on error-code matching.
- `CompleteMultipartUpload` is now safe: a spurious retry after a successful
  commit would return `NoSuchUpload` and confuse the caller; this is now
  prevented.
- Retry latency and bandwidth impact are visible in Prometheus dashboards.

### Negative

- `CompleteMultipartUpload` no longer auto-retries. Callers that relied on
  the SDK retrying on a `500 InternalError` response after a successful
  commit must implement application-level retry. This is also the AWS
  recommendation (*Engineering Resilient Systems on AWS*, ch. 5).
- `adaptive` mode may emit fewer retries than `MaxAttempts` if the internal
  token bucket is drained; documented and warned at startup for aggressive
  per-operation overrides.

## Alternatives Considered

### A: Pure SDK knobs (`WithRetryMaxAttempts`, `WithRetryMode`)

**Rejected.** Insufficient: no per-operation overrides, no classifier
customisation, no Prometheus metrics, and 429 is still not retried
by HTTP status alone.

### <a name="b-circuit-breakers"></a>B: Circuit breakers

**Deferred.** Half-open / open / closed state machines are the natural
complement to retry policy, but introduce considerable state complexity
(shared across replicas). Tracked as a potential v0.7 item; the
evidence base is the V0.6-QA-1 per-provider SLO annex at
[`docs/perf/v0.6-qa-1/slo-summary.md`](../perf/v0.6-qa-1/slo-summary.md)
(methodology in [`docs/PERFORMANCE.md#circuit-breaker-decision-input`](../PERFORMANCE.md#circuit-breaker-decision-input)).
Until the first three green nightlies populate that table's p99 column,
the design question cannot be answered on data; the current evidence is
that retries + exponential backoff with jitter adequately absorb the
transient-503 class of faults the suite exercises today. Reference:
*Designing Distributed Systems, 2nd Ed.* ch. 3.

### C: Hedged / speculative requests

**Incompatible.** The gateway is a single-backend proxy; hedging to
alternative backends requires a backend pool that does not exist.

## Addendum: retries require a rewindable body

A retry replays the request, so the AWS SDK rewinds the body before the second
attempt (`aws/retry/middleware.go`). A body that is not an `io.Seeker` cannot be
rewound, and the SDK fails the operation with `failed to rewind transport stream
for retry, request stream is not seekable` rather than retrying. Every policy
decision above — classification, backoff, `max_attempts` — is therefore
conditional on the caller supplying a seekable body, which this ADR originally
left unstated.

This is not hypothetical: `handlePutObject` streams chunked ciphertext, so the
policy was inert on the main write path until the body was buffered. Callers
satisfy the contract with `s3.NewSeekableBody`, bounded by
`server.max_part_buffer` (see the ADR 0006 addendum and
`docs/plans/V0.6-PERF-1-plan.md` §4.4). The remaining non-rewindable case is a
body of unknown length, which stays single-attempt by design.

Two consequences worth noting when reading the metrics: a give-up recorded
against a non-seekable body never reached the network on its second attempt, and
a seekable body also enables `Content-MD5` and payload signing in
`s3Client.PutObject`, which key off the same type assertion.

## References

1. *Cloud Native Go, 2nd Ed.* (Matthew A. Titmus, O'Reilly 2024), ch. 9
   "Resilience" — retry + backoff + jitter, thundering herd, context
   cancellation patterns.
2. *Designing Data-Intensive Applications, 2nd Ed.* (Kleppmann & Riccomini,
   O'Reilly 2026), §8.2 "Unreliable Networks" and §9.2 "Idempotency" —
   decorrelated jitter proof, idempotency classification.
3. *Engineering Resilient Systems on AWS* (Schwarz, Moran, Bachmeier,
   O'Reilly 2024), ch. 5 "Recoverability Patterns" — adaptive mode
   trade-offs, `CompleteMultipartUpload` retry warning.
4. *Designing Distributed Systems, 2nd Ed.* (Brendan Burns, O'Reilly 2024)
   ch. 3 — circuit breakers and bulkheads (deliberate non-goal).
5. AWS SDK Go V2 `aws/retry` package — `retry.Standard`, `retry.AdaptiveMode`,
   `aws.RetryerV2` interface.
