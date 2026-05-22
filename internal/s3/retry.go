// Package s3 provides the S3 backend client.
// retry.go implements the gateway-specific aws.Retryer for V0.6-PERF-2.
//
// Design rationale: docs/adr/0010-backend-retry-policy.md
// Plan: docs/plans/V0.6-PERF-2-plan.md §Phase C
package s3

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// cryptoRandInt63n returns a cryptographically random int64 in [0, n).
// This replaces math/rand for jitter calculations to avoid gosec G404
// findings and maintain consistency with the rest of the codebase.
// The fallback to time.Now().UnixNano() is only acceptable for jitter
// (not security-sensitive); jitter timing does not require cryptographic
// randomness, but using crypto/rand eliminates predictable sequences.
func cryptoRandInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback: XOR with nanoseconds; acceptable for jitter, not for keys.
		binary.BigEndian.PutUint64(buf[:], uint64(time.Now().UnixNano()))
	}
	return int64(binary.BigEndian.Uint64(buf[:]) % uint64(n)) // #nosec G115 — n is small (maxAttempts ≤ 10), product fits in int64
}

// retryReasonLabel is a closed set of classifier reason labels used as the
// "reason" Prometheus label on s3_backend_retries_total.  Any change to this
// set must also update TestRetry_MetricCardinality.
type retryReasonLabel string

const (
	reasonTimeout     retryReasonLabel = "timeout"
	reasonConnReset   retryReasonLabel = "conn_reset"
	reasonThrottle429 retryReasonLabel = "throttle_429"
	reasonThrottle503 retryReasonLabel = "throttle_503"
	reasonInternal500 retryReasonLabel = "internal_500"
	reasonDNS         retryReasonLabel = "dns"
	reasonTLS         retryReasonLabel = "tls"
	reasonSDKGeneric  retryReasonLabel = "sdk_generic"
	reasonNonRetry    retryReasonLabel = "non_retryable"
)

// AllReasonLabels enumerates the closed set of reason labels.  Referenced by
// TestRetry_MetricCardinality to enforce cardinality bounds.
var AllReasonLabels = []retryReasonLabel{
	reasonTimeout,
	reasonConnReset,
	reasonThrottle429,
	reasonThrottle503,
	reasonInternal500,
	reasonDNS,
	reasonTLS,
	reasonSDKGeneric,
	reasonNonRetry,
}

// clock abstracts time.Now and context-aware sleep for testability.
type clock interface {
	Now() time.Time
	SleepContext(ctx context.Context, d time.Duration) error
}

// realClock is the production clock implementation.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) SleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// backoffCalculator computes the next retry delay for a given attempt number
// and previous delay (used by the decorrelated-jitter algorithm).
type backoffCalculator interface {
	Next(attempt int, prev time.Duration) time.Duration
}

// fullJitter implements the "full jitter" algorithm:
//
//	delay = rand.Int63n(min(maxBackoff, initialBackoff * 2^attempt))
//
// Reference: AWS Architecture Blog, DDIA 2E §8.2.
type fullJitter struct {
	initial time.Duration
	max     time.Duration
}

func (j *fullJitter) Next(attempt int, _ time.Duration) time.Duration {
	cap := j.cap(attempt)
	delay := time.Duration(cryptoRandInt63n(int64(cap) + 1))
	return delay
}

func (j *fullJitter) cap(attempt int) time.Duration {
	exp := j.initial
	for i := 0; i < attempt; i++ {
		exp *= 2
		if exp > j.max || exp <= 0 {
			return j.max
		}
	}
	if exp > j.max {
		return j.max
	}
	return exp
}

// decorrelatedJitter implements the "decorrelated jitter" algorithm:
//
//	delay = min(maxBackoff, rand.Int63n(3*prev) + initialBackoff)
//
// Reference: AWS Architecture Blog, DDIA 2E §8.2.  Tighter tail under high
// contention than full jitter.
type decorrelatedJitter struct {
	initial time.Duration
	max     time.Duration
}

func (j *decorrelatedJitter) Next(_ int, prev time.Duration) time.Duration {
	if prev <= 0 {
		prev = j.initial
	}
	window := int64(3 * prev)
	if window < 0 {
		window = int64(j.max)
	}
	delay := time.Duration(cryptoRandInt63n(window+1)) + j.initial
	if delay > j.max {
		return j.max
	}
	return delay
}

// equalJitter implements the "equal jitter" algorithm:
//
//	delay = cap/2 + rand.Int63n(cap/2)
type equalJitter struct {
	initial time.Duration
	max     time.Duration
}

func (j *equalJitter) Next(attempt int, _ time.Duration) time.Duration {
	cap := j.initial
	for i := 0; i < attempt; i++ {
		cap *= 2
		if cap > j.max || cap <= 0 {
			cap = j.max
			break
		}
	}
	if cap > j.max {
		cap = j.max
	}
	half := cap / 2
	delay := half
	if half > 0 {
		delay += time.Duration(cryptoRandInt63n(int64(half) + 1))
	}
	return delay
}

// noJitter returns pure exponential backoff with no random component.
// Debug only; the validator emits a warning for this choice.
type noJitter struct {
	initial time.Duration
	max     time.Duration
}

func (j *noJitter) Next(attempt int, _ time.Duration) time.Duration {
	d := j.initial
	for i := 0; i < attempt; i++ {
		d *= 2
		if d > j.max || d <= 0 {
			return j.max
		}
	}
	if d > j.max {
		return j.max
	}
	return d
}

// newBackoffCalculator constructs a backoffCalculator from the jitter string.
func newBackoffCalculator(jitter string, initial, max time.Duration) backoffCalculator {
	switch jitter {
	case "decorrelated":
		return &decorrelatedJitter{initial: initial, max: max}
	case "equal":
		return &equalJitter{initial: initial, max: max}
	case "none":
		return &noJitter{initial: initial, max: max}
	default: // "full" and anything else normalised away
		return &fullJitter{initial: initial, max: max}
	}
}

// classify returns the reason label for err. The bool indicates whether
// err is retryable according to gateway policy.
//
// Safety invariant (§4.4): crypto errors, context cancellation, and specific
// 4xx HTTP status codes are never retryable.
func classify(op string, err error) (retryReasonLabel, bool) {
	if err == nil {
		return reasonNonRetry, false
	}

	// --- hard non-retryable classes ---

	// Context cancellation/deadline: the caller owns the deadline.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return reasonNonRetry, false
	}

	// Crypto errors: never retry; these are final failures.
	if errors.Is(err, crypto.ErrInvalidEnvelope) ||
		errors.Is(err, crypto.ErrUnwrapFailed) ||
		errors.Is(err, crypto.ErrKeyNotFound) ||
		errors.Is(err, crypto.ErrProviderUnavailable) {
		return reasonNonRetry, false
	}

	// Definite 4xx HTTP responses (not transient).
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		code := respErr.HTTPStatusCode()
		switch code {
		case http.StatusBadRequest,          // 400
			http.StatusUnauthorized,         // 401
			http.StatusForbidden,            // 403
			http.StatusNotFound,             // 404
			http.StatusMethodNotAllowed,     // 405
			http.StatusConflict,             // 409
			http.StatusLengthRequired,       // 411
			http.StatusPreconditionFailed,   // 412
			http.StatusRequestEntityTooLarge, // 413
			http.StatusUnsupportedMediaType, // 415
			http.StatusRequestedRangeNotSatisfiable, // 416
			http.StatusUnprocessableEntity: // 422
			return reasonNonRetry, false
		case http.StatusTooManyRequests: // 429
			return reasonThrottle429, true
		case http.StatusServiceUnavailable: // 503
			return reasonThrottle503, true
		case http.StatusInternalServerError: // 500
			return reasonInternal500, true
		case http.StatusBadGateway, // 502
			http.StatusGatewayTimeout: // 504
			return reasonThrottle503, true
		case http.StatusRequestTimeout: // 408
			return reasonTimeout, true
		}
	}

	// --- network-level errors ---

	// Check for ECONNRESET / ECONNREFUSED.
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return reasonConnReset, true
	}

	// DNS temporary failures.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.Temporary() {
		return reasonDNS, true
	}

	// Network op errors that are temporary.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Temporary() || opErr.Timeout() {
			return reasonConnReset, true
		}
	}

	// Timeout interface.
	type timeouter interface{ Timeout() bool }
	var te timeouter
	if errors.As(err, &te) && te.Timeout() {
		return reasonTimeout, true
	}

	// Delegate to SDK-retryable heuristic for remaining cases.
	inner := retry.NewStandard()
	if inner.IsErrorRetryable(err) {
		return reasonSDKGeneric, true
	}

	return reasonNonRetry, false
}

// OnAttemptFn is called after each failed attempt (before sleeping).
// attempt is 1-indexed (first retry = 1).  reason is from classify().
type OnAttemptFn func(op string, attempt int, reason string, delay time.Duration)

// OnGiveUpFn is called when all attempts are exhausted.
type OnGiveUpFn func(op string, attempts int, reason string, err error)

// retryer implements aws.RetryerV2 with gateway-specific policy.
// It wraps an inner aws.Retryer (typically retry.Standard or AdaptiveMode)
// for the token-bucket and basic classification, and layers:
//   - gateway-specific non-retryable overrides (crypto errors, 4xx)
//   - per-operation MaxAttempts overrides
//   - configurable jitter backoff algorithms
//   - context-aware sleep
//   - per-attempt and give-up callbacks (used by the metrics sink)
//
// Attempt tracking: the SDK retry middleware calls GetAttemptToken before each
// attempt (including the first) and GetRetryToken before each retry (i.e.
// attempt ≥ 2).  We count GetRetryToken calls to know how many retries were
// issued, and emit the give-up + attempts-per-request metrics from the release
// closure of the initial token (via GetAttemptToken), which is called after
// every attempt including the final one.
type retryer struct {
	inner      aws.Retryer
	cfg        config.BackendRetryConfig
	op         string // set per-operation via clone
	backoff    backoffCalculator
	clk        clock
	onAttempt  OnAttemptFn
	onGiveUp   OnGiveUpFn
	prevDelay  time.Duration // used by decorrelated jitter
	mu         sync.Mutex
	retries    int32 // atomic: counts GetRetryToken calls (= retries, not initial attempt)
}

// newRetryer builds a retryer from the supplied config.
func newRetryer(cfg config.BackendRetryConfig, clk clock, onAttempt OnAttemptFn, onGiveUp OnGiveUpFn) *retryer {
	var inner aws.Retryer
	switch cfg.Mode {
	case "adaptive":
		inner = retry.NewAdaptiveMode()
	default: // "standard" and normalized values
		inner = retry.NewStandard(func(o *retry.StandardOptions) {
			o.MaxAttempts = cfg.MaxAttempts
		})
	}

	if clk == nil {
		clk = realClock{}
	}

	bo := newBackoffCalculator(cfg.Jitter, cfg.InitialBackoff, cfg.MaxBackoff)

	return &retryer{
		inner:     inner,
		cfg:       cfg,
		backoff:   bo,
		clk:       clk,
		onAttempt: onAttempt,
		onGiveUp:  onGiveUp,
	}
}

// clone creates a per-operation copy that carries the operation name.
// Using clone ensures the prevDelay state (decorrelated jitter) does not leak
// between independent operations.  We construct a fresh struct (not a value
// copy) to avoid copying the embedded sync.Mutex.
func (r *retryer) clone(op string) *retryer {
	return &retryer{
		inner:     r.inner,
		cfg:       r.cfg,
		op:        op,
		backoff:   r.backoff,
		clk:       r.clk,
		onAttempt: r.onAttempt,
		onGiveUp:  r.onGiveUp,
		// prevDelay starts at zero (intentional; per-operation state).
	}
}

// MaxAttempts returns the effective max attempts for the current operation.
func (r *retryer) MaxAttempts() int {
	if r.cfg.PerOperation != nil {
		if n, ok := r.cfg.PerOperation[r.op]; ok {
			return n
		}
	}
	// CompleteMultipartUpload is non-idempotent post-commit; default to 1.
	if r.op == "CompleteMultipartUpload" {
		return 1
	}
	return r.cfg.MaxAttempts
}

// IsErrorRetryable returns true only if the error is retryable under gateway
// policy.  It layers gateway-specific opt-outs on top of the SDK's classifier.
func (r *retryer) IsErrorRetryable(err error) bool {
	// Hard non-retryable opt-outs (§4.4).
	_, retryable := classify(r.op, err)
	if !retryable {
		return false
	}

	// CopyObject is gated on SafeCopyObject.
	if r.op == "CopyObject" && (r.cfg.SafeCopyObject == nil || !*r.cfg.SafeCopyObject) {
		return false
	}

	// Our classify already determined this is retryable.  We do NOT further
	// delegate to inner.IsErrorRetryable because the inner SDK retryer may
	// not classify all HTTP status codes we want to retry (e.g. 429 is not in
	// the SDK's DefaultRetryableHTTPStatusCodes, but IS retryable per our policy
	// and DDIA 2E §8.2).  Token-bucket checks happen via GetRetryToken, not here.
	return true
}

// RetryDelay returns the context-aware delay to sleep before the next attempt.
// It implements the jitter algorithm selected at construction.
func (r *retryer) RetryDelay(attempt int, opErr error) (time.Duration, error) {
	r.mu.Lock()
	delay := r.backoff.Next(attempt, r.prevDelay)
	r.prevDelay = delay
	r.mu.Unlock()

	// Honour Retry-After header if present and larger than computed delay.
	if ra := retryAfterSeconds(opErr); ra > 0 {
		raDelay := time.Duration(ra) * time.Second
		if raDelay > delay {
			// Cap at 2× MaxBackoff to prevent unbounded waits.
			if raDelay > r.cfg.MaxBackoff*2 {
				raDelay = r.cfg.MaxBackoff * 2
			}
			delay = raDelay
		}
	}

	reason, _ := classify(r.op, opErr)
	if r.onAttempt != nil {
		r.onAttempt(r.op, attempt, string(reason), delay)
	}

	return delay, nil
}

// GetRetryToken delegates to the inner retryer's token bucket, and counts the
// number of retries issued for this logical operation.  The count is used by
// GetAttemptToken's release to compute total attempts.
func (r *retryer) GetRetryToken(ctx context.Context, opErr error) (func(error) error, error) {
	atomic.AddInt32(&r.retries, 1)
	return r.inner.GetRetryToken(ctx, opErr)
}

// GetInitialToken delegates to the inner retryer.
// The returned release function is instrumented to emit give-up and
// attempts-per-request metrics when the operation concludes with an error
// (i.e. all retries were exhausted or the error was non-retryable).
func (r *retryer) GetInitialToken() func(error) error {
	innerRelease := r.inner.GetInitialToken()
	return r.makeTrackedRelease(innerRelease)
}

// GetAttemptToken returns the send token from the inner retryer (RetryerV2).
// The returned release function is instrumented identically to GetInitialToken.
func (r *retryer) GetAttemptToken(ctx context.Context) (func(error) error, error) {
	var innerRelease func(error) error
	if v2, ok := r.inner.(interface {
		GetAttemptToken(context.Context) (func(error) error, error)
	}); ok {
		var err error
		innerRelease, err = v2.GetAttemptToken(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		innerRelease = r.inner.GetInitialToken()
	}
	return r.makeTrackedRelease(innerRelease), nil
}

// makeTrackedRelease wraps an inner release function so that after every
// operation that involved at least one retry attempt:
//   - emit s3_backend_attempts_per_request histogram (total attempts) always
//   - emit s3_backend_retry_give_ups_total (give-up counter) only when the
//     operation fails after exhausting retries
//
// Non-retried operations (successful first attempt, or immediately-rejected
// non-retryable errors) do not emit the give-up counter.  The attempts
// histogram is emitted whenever retries occurred, regardless of outcome,
// per the plan §Phase E description.
//
// The release is called once per logical operation (not once per retry).
func (r *retryer) makeTrackedRelease(inner func(error) error) func(error) error {
	return func(opErr error) error {
		result := inner(opErr)
		totalRetries := int(atomic.LoadInt32(&r.retries))
		if totalRetries == 0 {
			// No retries: skip all attempt-tracking metrics.
			return result
		}
		totalAttempts := totalRetries + 1 // first attempt + retries

		if opErr != nil {
			// Operation failed after retries: emit give-up counter.
			// onGiveUp also calls RecordBackendAttemptsPerRequest.
			reason, _ := classify(r.op, opErr)
			if r.onGiveUp != nil {
				r.onGiveUp(r.op, totalAttempts, string(reason), opErr)
			}
		} else {
			// Operation succeeded after retries: emit attempts histogram only
			// (no give-up).  The onAttemptSuccess callback is not available in
			// the current design, so we emit via onGiveUp with nil err and
			// "sdk_generic" reason as a harmless sentinel — the metrics sink
			// interprets this as an attempts observation with no give-up counter.
			// Simpler: call onGiveUp with a nil error; the sink must tolerate this.
			if r.onGiveUp != nil {
				r.onGiveUp(r.op, totalAttempts, string(reasonSDKGeneric), nil)
			}
		}
		return result
	}
}

// retryAfterSeconds extracts the Retry-After value in seconds from a response
// error, or returns 0 if not present.
func retryAfterSeconds(err error) int64 {
	if err == nil {
		return 0
	}
	var respErr *smithyhttp.ResponseError
	if !errors.As(err, &respErr) {
		return 0
	}
	header := respErr.Response.Header.Get("Retry-After")
	if header == "" {
		return 0
	}
	// Retry-After can be a number of seconds or an HTTP-date; we only handle
	// the numeric form (the S3 / MinIO / Wasabi convention).
	n, err2 := strconv.ParseInt(strings.TrimSpace(header), 10, 64)
	if err2 != nil || n < 0 {
		return 0
	}
	return n
}

// retryerFactory is a per-ClientFactory singleton that constructs a fresh
// per-operation retryer for each `WithRetryer` call.  Using a factory ensures
// `prevDelay` state (decorrelated jitter) is per-operation, not per-client.
type retryerFactory struct {
	cfg       config.BackendRetryConfig
	clk       clock
	onAttempt OnAttemptFn
	onGiveUp  OnGiveUpFn
}

func newRetryerFactory(cfg config.BackendRetryConfig, clk clock, onAttempt OnAttemptFn, onGiveUp OnGiveUpFn) *retryerFactory {
	if clk == nil {
		clk = realClock{}
	}
	return &retryerFactory{
		cfg:       cfg,
		clk:       clk,
		onAttempt: onAttempt,
		onGiveUp:  onGiveUp,
	}
}

// Build returns a new retryer suitable for a single logical S3 operation.
// The op argument is the SDK operation name (e.g. "PutObject").
func (f *retryerFactory) Build(op string) aws.RetryerV2 {
	r := newRetryer(f.cfg, f.clk, f.onAttempt, f.onGiveUp)
	return r.clone(op)
}

// newNopRetryerV2 wraps aws.NopRetryer to implement the RetryerV2 interface
// (adds GetAttemptToken).
func newNopRetryerV2() aws.RetryerV2 {
	return &nopRetryerV2{}
}

type nopRetryerV2 struct{ aws.NopRetryer }

func (n *nopRetryerV2) GetAttemptToken(_ context.Context) (func(error) error, error) {
	return func(error) error { return nil }, nil
}

// operationNameFromCtx extracts the SDK operation name from the middleware
// context.  Returns "" if unavailable (e.g. in unit tests).
func operationNameFromCtx(ctx context.Context) string {
	// The SDK stores the operation name under smithymiddleware.OperationName key.
	// We avoid importing the middleware package here to keep the dependency slim;
	// the factory's WithRetryer wrapper is called per-client, not per-operation,
	// so this function is only used in tests.
	type opNameKey struct{}
	v, _ := ctx.Value(opNameKey{}).(string)
	return v
}

// withOperationName returns a context with the given operation name set.
// Used in tests to simulate the SDK middleware context.
func withOperationName(ctx context.Context, op string) context.Context {
	type opNameKey struct{}
	return context.WithValue(ctx, opNameKey{}, op)
}

// metricsSink converts retryer callbacks into Metrics calls.
// Defined in retry.go so it lives next to the retryer; wired in client.go.
type metricsSink struct {
	m interface {
		RecordBackendRetry(op, reason string)
		RecordBackendAttemptsPerRequest(op string, attempts int)
		RecordBackendRetryGiveUp(op, reason string)
		RecordBackendRetryBackoff(delay time.Duration)
	}
}

func (s *metricsSink) onAttempt(op string, attempt int, reason string, delay time.Duration) {
	if s == nil || s.m == nil {
		return
	}
	s.m.RecordBackendRetry(op, reason)
	s.m.RecordBackendRetryBackoff(delay)
}

func (s *metricsSink) onGiveUp(op string, attempts int, reason string, err error) {
	if s == nil || s.m == nil {
		return
	}
	s.m.RecordBackendAttemptsPerRequest(op, attempts)
	// Only emit the give-up counter when the operation actually failed.
	// A nil error means the operation succeeded after retries (attempts > 1 but
	// no give-up); we still want to track the attempt count but not count this
	// as a give-up event.
	if err != nil {
		s.m.RecordBackendRetryGiveUp(op, reason)
	}
}

// Ensure retryer implements aws.RetryerV2.
var _ aws.RetryerV2 = (*retryer)(nil)

// Ensure nopRetryerV2 implements aws.RetryerV2.
var _ aws.RetryerV2 = (*nopRetryerV2)(nil)

// Ensure fmt.Stringer for reason labels (useful in tests).
func (r retryReasonLabel) String() string { return string(r) }

// ValidationWarnings checks for non-fatal but inadvisable configuration
// combinations (e.g. mode=adaptive + aggressive per-op overrides).  It returns
// a slice of human-readable warnings suitable for logging at startup.
func ValidationWarnings(cfg config.BackendRetryConfig) []string {
	var ws []string
	if cfg.Jitter == "none" {
		ws = append(ws, "backend.retry.jitter=none disables jitter; this is unsafe under contention and is for debug use only")
	}
	if cfg.Mode == "adaptive" {
		for op, n := range cfg.PerOperation {
			if n > cfg.MaxAttempts {
				ws = append(ws, fmt.Sprintf("backend.retry.mode=adaptive with per_operation[%s]=%d > max_attempts=%d: adaptive mode may emit fewer retries than per_operation specifies", op, n, cfg.MaxAttempts))
			}
		}
	}
	return ws
}
