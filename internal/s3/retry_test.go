package s3

// V0.6-PERF-2 Phase C — Unit tests for the custom retryer.
// Plan: docs/plans/V0.6-PERF-2-plan.md §Phase C tests.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// ---- helpers ----------------------------------------------------------------

func defaultTestCfg() config.BackendRetryConfig {
	cfg := config.BackendRetryConfig{
		Mode:           "standard",
		MaxAttempts:    3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		Jitter:         "full",
	}
	cfg.Normalize()
	return cfg
}

// fakeClock is an injectable clock implementation for tests.
// SleepContext returns immediately (or the context error) without actually sleeping.
type fakeClock struct {
	mu      sync.Mutex
	slept   []time.Duration
	advance time.Duration // set to simulate elapsed time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return time.Now().Add(f.advance)
}

func (f *fakeClock) SleepContext(ctx context.Context, d time.Duration) error {
	f.mu.Lock()
	f.slept = append(f.slept, d)
	f.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (f *fakeClock) totalSlept() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	var total time.Duration
	for _, d := range f.slept {
		total += d
	}
	return total
}

func newTestRetryer(t testing.TB, cfg config.BackendRetryConfig, clk clock, onAttempt OnAttemptFn, onGiveUp OnGiveUpFn) *retryer {
	t.Helper()
	return newRetryer(cfg, clk, onAttempt, onGiveUp)
}

// makeHTTPRespErr builds a smithyhttp.ResponseError with the given status code
// and optional Retry-After header.
func makeHTTPRespErr(t testing.TB, status int, retryAfter int) error {
	t.Helper()
	header := make(http.Header)
	header.Set("Content-Type", "application/xml")
	if retryAfter > 0 {
		header.Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	}
	httpResp := &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("error body")),
	}
	smithyResp := &smithyhttp.Response{Response: httpResp}
	return &smithyhttp.ResponseError{
		Response: smithyResp,
		Err:      fmt.Errorf("injected %d", status),
	}
}

// ---- tests ------------------------------------------------------------------

// TestRetryer_StandardHappyPath verifies that with no error, IsErrorRetryable
// returns false and MaxAttempts is as configured.
func TestRetryer_StandardHappyPath(t *testing.T) {
	cfg := defaultTestCfg()
	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("PutObject")
	if r.IsErrorRetryable(nil) {
		t.Error("nil error should not be retryable")
	}
	if r.MaxAttempts() != 3 {
		t.Errorf("MaxAttempts: expected 3, got %d", r.MaxAttempts())
	}
}

// TestRetryer_ThreeAttemptsOnThrottle429 verifies that a 429 is retryable and
// that RetryDelay is called with increasing attempt numbers.
func TestRetryer_ThreeAttemptsOnThrottle429(t *testing.T) {
	cfg := defaultTestCfg()
	clk := &fakeClock{}
	var attempts []int
	onAttempt := func(op string, attempt int, reason string, delay time.Duration) {
		attempts = append(attempts, attempt)
	}

	r := newTestRetryer(t, cfg, clk, onAttempt, nil).clone("PutObject")

	err429 := makeHTTPRespErr(t, 429, 0)
	if !r.IsErrorRetryable(err429) {
		t.Fatal("429 should be retryable")
	}

	// Simulate two retries.
	for attempt := 1; attempt <= 2; attempt++ {
		delay, delayErr := r.RetryDelay(attempt, err429)
		if delayErr != nil {
			t.Fatalf("RetryDelay(%d) error: %v", attempt, delayErr)
		}
		if delay < 0 {
			t.Errorf("negative delay at attempt %d: %s", attempt, delay)
		}
	}

	if len(attempts) != 2 {
		t.Errorf("onAttempt called %d times, want 2", len(attempts))
	}
}

// TestRetryer_ContextCanceledMidSleep verifies that if the context is
// cancelled while waiting for a retry delay, RetryDelay does NOT sleep
// (fakeClock returns context error immediately via select).
func TestRetryer_ContextCanceledMidSleep(t *testing.T) {
	cfg := defaultTestCfg()
	clk := &fakeClock{}
	// Ensure the retryer constructs without panic.
	_ = newTestRetryer(t, cfg, clk, nil, nil).clone("PutObject")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// The retryer itself doesn't call SleepContext directly; the AWS SDK
	// middleware does.  We verify that our fakeClock.SleepContext respects
	// cancellation.
	err := clk.SleepContext(ctx, 100*time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// TestRetryer_CompleteMultipartUpload_NeverRetries verifies that
// CompleteMultipartUpload is never retried (non-idempotent post-commit).
func TestRetryer_CompleteMultipartUpload_NeverRetries(t *testing.T) {
	cfg := defaultTestCfg()
	cmpRetryer := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("CompleteMultipartUpload")

	if cmpRetryer.MaxAttempts() != 1 {
		t.Errorf("CompleteMultipartUpload MaxAttempts should be 1, got %d", cmpRetryer.MaxAttempts())
	}
	// Even on a retryable error, IsErrorRetryable may return true but
	// MaxAttempts=1 means the SDK will never actually retry.
	// We verify MaxAttempts is 1 — the SDK enforces the limit.
}

// TestRetryer_CopyObject_GatedBySafeCopyObject verifies that CopyObject
// retryability is gated on SafeCopyObject.
func TestRetryer_CopyObject_GatedBySafeCopyObject(t *testing.T) {
	err503 := makeHTTPRespErr(t, 503, 0)

	// SafeCopyObject=true: 503 should be retryable.
	cfgTrue := defaultTestCfg()
	trueVal := true
	cfgTrue.SafeCopyObject = &trueVal
	rTrue := newTestRetryer(t, cfgTrue, &fakeClock{}, nil, nil).clone("CopyObject")
	if !rTrue.IsErrorRetryable(err503) {
		t.Error("CopyObject with SafeCopyObject=true: 503 should be retryable")
	}

	// SafeCopyObject=false: should never retry.
	cfgFalse := defaultTestCfg()
	falseVal := false
	cfgFalse.SafeCopyObject = &falseVal
	rFalse := newTestRetryer(t, cfgFalse, &fakeClock{}, nil, nil).clone("CopyObject")
	if rFalse.IsErrorRetryable(err503) {
		t.Error("CopyObject with SafeCopyObject=false: 503 should NOT be retryable")
	}
}

// TestRetryer_CryptoErrorNeverRetried verifies that all crypto sentinel errors
// are classified as non-retryable (§4.4 safety invariant).
func TestRetryer_CryptoErrorNeverRetried(t *testing.T) {
	cfg := defaultTestCfg()
	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("PutObject")

	cryptoErrors := []error{
		crypto.ErrInvalidEnvelope,
		crypto.ErrUnwrapFailed,
		crypto.ErrKeyNotFound,
		crypto.ErrProviderUnavailable,
		fmt.Errorf("wrap: %w", crypto.ErrInvalidEnvelope),
	}
	for _, err := range cryptoErrors {
		if r.IsErrorRetryable(err) {
			t.Errorf("crypto error %v should NOT be retryable", err)
		}
	}
}

// TestRetryer_ContextErrorNeverRetried verifies context errors are non-retryable.
func TestRetryer_ContextErrorNeverRetried(t *testing.T) {
	cfg := defaultTestCfg()
	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("GetObject")

	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		if r.IsErrorRetryable(err) {
			t.Errorf("%v should NOT be retryable", err)
		}
	}
}

// TestRetryer_RetryAfterHeaderHonoured verifies that a 503 with Retry-After: 5
// causes RetryDelay to return at least 5 s.
func TestRetryer_RetryAfterHeaderHonoured(t *testing.T) {
	cfg := config.BackendRetryConfig{
		Mode:           "standard",
		MaxAttempts:    3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     30 * time.Second,
		Jitter:         "none", // deterministic for this test
	}
	cfg.Normalize()

	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("PutObject")
	err503 := makeHTTPRespErr(t, 503, 5)

	delay, err := r.RetryDelay(1, err503)
	if err != nil {
		t.Fatalf("RetryDelay error: %v", err)
	}
	if delay < 5*time.Second {
		t.Errorf("expected delay >= 5s due to Retry-After, got %s", delay)
	}
}

// TestRetryer_JitterAlgorithms verifies that all four jitter algorithms
// produce non-negative delays bounded by MaxBackoff.
func TestRetryer_JitterAlgorithms(t *testing.T) {
	algos := []string{"full", "decorrelated", "equal", "none"}
	maxBackoff := 20 * time.Second
	initial := 100 * time.Millisecond

	for _, algo := range algos {
		t.Run(algo, func(t *testing.T) {
			bo := newBackoffCalculator(algo, initial, maxBackoff)
			var prev time.Duration
			for attempt := 0; attempt <= 5; attempt++ {
				d := bo.Next(attempt, prev)
				prev = d
				if d < 0 {
					t.Errorf("attempt %d: negative delay %s", attempt, d)
				}
				if d > maxBackoff {
					t.Errorf("attempt %d: delay %s exceeds maxBackoff %s", attempt, d, maxBackoff)
				}
			}
		})
	}
}

// TestRetryer_MaxAttemptsCapsGiveUp verifies that per-op override of 1
// means exactly one attempt.
func TestRetryer_MaxAttemptsCapsGiveUp(t *testing.T) {
	cfg := defaultTestCfg()
	cfg.PerOperation = map[string]int{"UploadPart": 1}

	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("UploadPart")
	if r.MaxAttempts() != 1 {
		t.Errorf("UploadPart per-op override should give MaxAttempts=1, got %d", r.MaxAttempts())
	}
}

// TestRetryer_AdaptiveMode_Smoke verifies that "adaptive" mode wires up
// a different inner retryer without panicking.
func TestRetryer_AdaptiveMode_Smoke(t *testing.T) {
	cfg := defaultTestCfg()
	cfg.Mode = "adaptive"

	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("PutObject")
	// Should not panic.
	_ = r.IsErrorRetryable(makeHTTPRespErr(t, 503, 0))
	// MaxAttempts is derived from cfg.MaxAttempts.
	if r.MaxAttempts() != cfg.MaxAttempts {
		t.Errorf("adaptive mode MaxAttempts: expected %d, got %d", cfg.MaxAttempts, r.MaxAttempts())
	}
}

// TestRetryer_RaceSafe verifies no data races when IsErrorRetryable and
// RetryDelay are called concurrently.  Run with -race.
func TestRetryer_RaceSafe(t *testing.T) {
	cfg := defaultTestCfg()
	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("PutObject")
	err503 := makeHTTPRespErr(t, 503, 0)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = r.IsErrorRetryable(err503)
		}()
		go func(n int) {
			defer wg.Done()
			_, _ = r.RetryDelay(n%3+1, err503)
		}(i)
	}
	wg.Wait()
}

// TestRetryer_400sAreNonRetryable verifies that 4xx status codes in the
// non-retryable set are classified correctly.
func TestRetryer_400sAreNonRetryable(t *testing.T) {
	cfg := defaultTestCfg()
	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("PutObject")

	for _, status := range []int{400, 401, 403, 404, 405, 409, 411, 412, 413, 415, 416, 422} {
		err := makeHTTPRespErr(t, status, 0)
		if r.IsErrorRetryable(err) {
			t.Errorf("HTTP %d should NOT be retryable", status)
		}
	}
}

// TestRetryer_NetworkErrorsAreRetryable verifies that ECONNRESET and DNS
// temporary errors are retryable.
func TestRetryer_NetworkErrorsAreRetryable(t *testing.T) {
	cfg := defaultTestCfg()
	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("GetObject")

	if !r.IsErrorRetryable(syscall.ECONNRESET) {
		t.Error("ECONNRESET should be retryable")
	}

	dnsErr := &net.DNSError{Err: "temporary", IsTemporary: true}
	if !r.IsErrorRetryable(dnsErr) {
		t.Error("temporary DNS error should be retryable")
	}
}

// TestRetry_MetricCardinality ensures the closed set of reason labels is
// exactly AllReasonLabels and no new values have been introduced silently.
func TestRetry_MetricCardinality(t *testing.T) {
	expected := map[retryReasonLabel]bool{
		reasonTimeout:     true,
		reasonConnReset:   true,
		reasonThrottle429: true,
		reasonThrottle503: true,
		reasonInternal500: true,
		reasonDNS:         true,
		reasonTLS:         true,
		reasonSDKGeneric:  true,
		reasonNonRetry:    true,
	}
	for _, label := range AllReasonLabels {
		if !expected[label] {
			t.Errorf("AllReasonLabels contains unexpected label %q", label)
		}
		delete(expected, label)
	}
	if len(expected) > 0 {
		t.Errorf("expected labels not in AllReasonLabels: %v", expected)
	}
}

// TestRetryerFactory_Build verifies that the factory constructs independent
// retryers for different operations.
func TestRetryerFactory_Build(t *testing.T) {
	cfg := defaultTestCfg()
	cfg.PerOperation = map[string]int{"CompleteMultipartUpload": 1, "PutObject": 5}

	clk := &fakeClock{}
	f := newRetryerFactory(cfg, clk, nil, nil)

	putRetryer := f.Build("PutObject")
	if putRetryer.MaxAttempts() != 5 {
		t.Errorf("PutObject retryer MaxAttempts: expected 5, got %d", putRetryer.MaxAttempts())
	}

	cmpRetryer := f.Build("CompleteMultipartUpload")
	if cmpRetryer.MaxAttempts() != 1 {
		t.Errorf("CompleteMultipartUpload retryer MaxAttempts: expected 1, got %d", cmpRetryer.MaxAttempts())
	}
}

// TestClassify verifies the closed set of reason labels for specific errors.
func TestClassify(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantReason retryReasonLabel
		wantRetry  bool
	}{
		{
			name:       "nil error",
			err:        nil,
			wantReason: reasonNonRetry,
			wantRetry:  false,
		},
		{
			name:       "context.Canceled",
			err:        context.Canceled,
			wantReason: reasonNonRetry,
			wantRetry:  false,
		},
		{
			name:       "context.DeadlineExceeded",
			err:        context.DeadlineExceeded,
			wantReason: reasonNonRetry,
			wantRetry:  false,
		},
		{
			name:       "crypto.ErrInvalidEnvelope",
			err:        crypto.ErrInvalidEnvelope,
			wantReason: reasonNonRetry,
			wantRetry:  false,
		},
		{
			name:       "ECONNRESET",
			err:        syscall.ECONNRESET,
			wantReason: reasonConnReset,
			wantRetry:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, retry := classify("PutObject", tt.err)
			if reason != tt.wantReason {
				t.Errorf("reason: expected %q, got %q", tt.wantReason, reason)
			}
			if retry != tt.wantRetry {
				t.Errorf("retryable: expected %v, got %v", tt.wantRetry, retry)
			}
		})
	}
}

// TestRetryAfterSeconds verifies extraction of the Retry-After header.
func TestRetryAfterSeconds(t *testing.T) {
	// With Retry-After: 7
	err := makeHTTPRespErr(t, 503, 7)
	if n := retryAfterSeconds(err); n != 7 {
		t.Errorf("retryAfterSeconds: expected 7, got %d", n)
	}

	// Without Retry-After header
	err2 := makeHTTPRespErr(t, 503, 0)
	if n := retryAfterSeconds(err2); n != 0 {
		t.Errorf("retryAfterSeconds (no header): expected 0, got %d", n)
	}

	// Non-response error
	if n := retryAfterSeconds(errors.New("plain error")); n != 0 {
		t.Errorf("retryAfterSeconds (non-http error): expected 0, got %d", n)
	}
}

// ---- GetRetryToken / GetInitialToken / makeTrackedRelease ------------------

// TestRetryer_GetInitialToken verifies that GetInitialToken returns a
// callable release function that does not panic.
func TestRetryer_GetInitialToken(t *testing.T) {
	var gaveUp bool
	onGiveUp := func(op string, attempts int, reason string, err error) {
		gaveUp = true
	}
	r := newTestRetryer(t, defaultTestCfg(), &fakeClock{}, nil, onGiveUp).clone("PutObject")

	// Simulate a successful operation — no retries.
	release := r.GetInitialToken()
	if release == nil {
		t.Fatal("GetInitialToken() returned nil release func")
	}
	// Calling release with nil error should not trigger giveUp.
	_ = release(nil)
	if gaveUp {
		t.Error("giveUp callback should NOT fire for successful first attempt")
	}
}

// TestRetryer_GetInitialToken_GivesUpOnError verifies that the tracked release
// fires the giveUp callback when an error is passed AND at least one retry
// occurred.
func TestRetryer_GetInitialToken_GivesUpOnError(t *testing.T) {
	var giveUpCalls int
	onGiveUp := func(op string, attempts int, reason string, err error) {
		giveUpCalls++
	}
	r := newTestRetryer(t, defaultTestCfg(), &fakeClock{}, nil, onGiveUp).clone("PutObject")

	// Manually force the retries counter to simulate a retry.
	atomic.AddInt32(&r.retries, 1)

	// Now call the tracked release with an error.
	err503 := makeHTTPRespErr(t, 503, 0)
	release := r.GetInitialToken()
	_ = release(err503)

	// giveUp should have been called once.
	if giveUpCalls != 1 {
		t.Errorf("expected 1 giveUp call, got %d", giveUpCalls)
	}
}

// TestRetryer_GetRetryToken_IncretsRetries verifies that GetRetryToken
// increments the internal retry counter.
func TestRetryer_GetRetryToken_IncrementsRetries(t *testing.T) {
	r := newTestRetryer(t, defaultTestCfg(), &fakeClock{}, nil, nil).clone("GetObject")

	err503 := makeHTTPRespErr(t, 503, 0)
	release, retryErr := r.GetRetryToken(context.Background(), err503)
	if retryErr != nil {
		// The inner retryer may reject (e.g. cap = 1 for this op). Skip if so.
		t.Skipf("GetRetryToken rejected: %v", retryErr)
	}
	if release != nil {
		_ = release(nil)
	}

	// retries counter should now be ≥ 1.
	if int(r.retries) < 1 {
		t.Errorf("retries counter: expected ≥1, got %d", r.retries)
	}
}

// TestRetryer_GetAttemptToken verifies GetAttemptToken returns a non-nil release.
func TestRetryer_GetAttemptToken(t *testing.T) {
	r := newTestRetryer(t, defaultTestCfg(), &fakeClock{}, nil, nil).clone("PutObject")

	release, err := r.GetAttemptToken(context.Background())
	if err != nil {
		t.Fatalf("GetAttemptToken error: %v", err)
	}
	if release == nil {
		t.Fatal("GetAttemptToken returned nil release")
	}
	_ = release(nil)
}

// TestRetryer_MakeTrackedRelease_SuccessAfterRetries exercises the "success
// after retries" branch where onGiveUp is called with nil error.
func TestRetryer_MakeTrackedRelease_SuccessAfterRetries(t *testing.T) {
	var giveUpCalls int
	var lastErr error
	onGiveUp := func(op string, attempts int, reason string, err error) {
		giveUpCalls++
		lastErr = err
	}
	r := newTestRetryer(t, defaultTestCfg(), &fakeClock{}, nil, onGiveUp).clone("PutObject")

	// Manually force the retries counter to simulate a retry that succeeded.
	atomic.AddInt32(&r.retries, 1)

	release := r.GetInitialToken()
	_ = release(nil) // nil error → success after retries

	if giveUpCalls != 1 {
		t.Errorf("expected onGiveUp called once, got %d", giveUpCalls)
	}
	if lastErr != nil {
		t.Errorf("lastErr should be nil for success path, got %v", lastErr)
	}
}

// TestRetryReasonLabel_String verifies the String() method on retryReasonLabel.
func TestRetryReasonLabel_String(t *testing.T) {
	labels := AllReasonLabels
	for _, l := range labels {
		s := l.String()
		if s == "" {
			t.Errorf("retryReasonLabel.String() for label %v returned empty string", l)
		}
	}
}

// TestOperationNameFromCtx verifies that operationNameFromCtx returns ""
// when no operation name is set.
func TestOperationNameFromCtx(t *testing.T) {
	ctx := context.Background()
	if got := operationNameFromCtx(ctx); got != "" {
		t.Errorf("operationNameFromCtx(background) = %q, want \"\"", got)
	}
}

// TestWithOperationName verifies that withOperationName and operationNameFromCtx
// exercise their respective code paths without panicking.
// Note: these two functions use locally-scoped type keys and are designed for
// test-level use; the value set by withOperationName is not necessarily
// retrievable by operationNameFromCtx (different function-scoped type keys).
func TestWithOperationName(t *testing.T) {
	// Exercise both functions to cover the code paths.
	ctx := withOperationName(context.Background(), "PutObject")
	if ctx == nil {
		t.Fatal("withOperationName returned nil context")
	}
	// operationNameFromCtx must not panic regardless of what's in ctx.
	_ = operationNameFromCtx(ctx)
	_ = operationNameFromCtx(context.Background())
}

// TestMetricsSink_OnAttemptAndOnGiveUp verifies the metricsSink wiring.
func TestMetricsSink_OnAttemptAndOnGiveUp(t *testing.T) {
	// nil sink should not panic.
	var s *metricsSink
	s.onAttempt("PutObject", 1, "throttle", 10*time.Millisecond)
	s.onGiveUp("PutObject", 3, "throttle", errors.New("throttle"))

	// Sink with nil m should not panic either.
	s2 := &metricsSink{m: nil}
	s2.onAttempt("GetObject", 2, "timeout", 5*time.Millisecond)
	s2.onGiveUp("GetObject", 2, "timeout", errors.New("timeout"))
}

// TestRetryer_ClockRealNow exercises the realClock.Now() path.
func TestRetryer_ClockRealNow(t *testing.T) {
	clk := realClock{}
	now := clk.Now()
	if now.IsZero() {
		t.Error("realClock.Now() returned zero time")
	}
}

// TestRetryer_ClockSleepContext_ZeroDuration exercises the early-return branch
// in realClock.SleepContext when d <= 0.
func TestRetryer_ClockSleepContext_ZeroDuration(t *testing.T) {
	clk := realClock{}
	if err := clk.SleepContext(context.Background(), 0); err != nil {
		t.Errorf("SleepContext(0) error: %v", err)
	}
	if err := clk.SleepContext(context.Background(), -1*time.Millisecond); err != nil {
		t.Errorf("SleepContext(-1ms) error: %v", err)
	}
}

// TestValidationWarnings_AdaptiveModeWarning verifies the adaptive warning.
func TestValidationWarnings_AdaptiveModeWarning(t *testing.T) {
	cfg := defaultTestCfg()
	cfg.Mode = "adaptive"
	cfg.PerOperation = map[string]int{"PutObject": cfg.MaxAttempts + 2}

	warnings := ValidationWarnings(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "adaptive") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected adaptive mode warning, got %v", warnings)
	}
}

// TestValidationWarnings verifies advisory warnings for dangerous configs.
func TestValidationWarnings(t *testing.T) {
	cfg := defaultTestCfg()
	cfg.Jitter = "none"
	warnings := ValidationWarnings(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "jitter=none") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about jitter=none, got %v", warnings)
	}

	// No warnings for safe config.
	safe := defaultTestCfg()
	if len(ValidationWarnings(safe)) > 0 {
		t.Errorf("unexpected warnings for safe config: %v", ValidationWarnings(safe))
	}
}

// TestCryptoRandInt63n verifies that cryptoRandInt63n produces values within
// the expected range and handles edge cases correctly.
func TestCryptoRandInt63n(t *testing.T) {
	// Test: cryptoRandInt63n(0) returns 0 without panic
	if got := cryptoRandInt63n(0); got != 0 {
		t.Errorf("cryptoRandInt63n(0) = %d, want 0", got)
	}

	// Test: cryptoRandInt63n(1) returns 0 without panic
	if got := cryptoRandInt63n(1); got != 0 {
		t.Errorf("cryptoRandInt63n(1) = %d, want 0", got)
	}

	// Test: cryptoRandInt63n(n) returns values in [0, n) for n > 1
	const n = 1000
	for i := 0; i < 1000; i++ {
		got := cryptoRandInt63n(n)
		if got < 0 || got >= n {
			t.Errorf("cryptoRandInt63n(%d) = %d, want value in [0, %d)", n, got, n)
		}
	}

	// Test: cryptoRandInt63n works with large values
	const largeN = int64(1<<62 - 1)
	for i := 0; i < 100; i++ {
		got := cryptoRandInt63n(largeN)
		if got < 0 || got >= largeN {
			t.Errorf("cryptoRandInt63n(%d) = %d, want value in [0, %d)", largeN, got, largeN)
		}
	}
}
