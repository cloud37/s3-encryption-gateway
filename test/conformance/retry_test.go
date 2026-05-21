//go:build conformance

package conformance

// Retry policy conformance tests — V0.6-PERF-2.
//
// These tests exercise the gateway's S3 backend retry policy end-to-end:
//   - Prometheus metrics are asserted via gw.Metrics (isolated registry)
//   - The backend is a ToxicServer (in-process) — no Docker required
//   - Cap = 0: every registered provider runs all tests
//
// Test names use the PERF2_ prefix for easy filtering:
//
//	go test -tags=conformance ./test/conformance/ -run TestConformance/.*/PERF2_

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus/testutil"

	internalconfig "github.com/kenchrcum/s3-encryption-gateway/internal/config"
	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// ── backend helpers ───────────────────────────────────────────────────────────

// startRetryGateway starts a gateway pointed at the given toxicServer with a
// fast retry policy (1 ms initial backoff, no jitter) for test speed.
// The default max_attempts=3 is preserved so retry-count assertions are stable.
func startRetryGateway(t *testing.T, toxic *toxicServer) *harness.Gateway {
	t.Helper()
	return startRetryGatewayAt(t, toxic.URL())
}

// startRetryGatewayAt is like startRetryGateway but accepts a plain URL string
// (for retryAfterServer which does not expose a toxicServer).
func startRetryGatewayAt(t *testing.T, backendURL string) *harness.Gateway {
	t.Helper()
	inst := provider.Instance{
		Endpoint:     backendURL,
		Region:       "us-east-1",
		AccessKey:    "retry-access",
		SecretKey:    "retry-secret",
		Bucket:       "retry-bucket",
		ProviderName: "retry-chaos",
	}
	return harness.StartGateway(t, inst,
		harness.WithConfigMutator(func(cfg *internalconfig.Config) {
			cfg.Backend.UsePathStyle = true
			cfg.Backend.UseSSL = false
			// Speed up: keep 3 max attempts but use very small backoff.
			cfg.Backend.Retry.InitialBackoff = 1e6  // 1 ms in nanoseconds
			cfg.Backend.Retry.MaxBackoff = 10e6     // 10 ms
			cfg.Backend.Retry.Jitter = "none"       // deterministic
		}),
	)
}

// retryMetricSeries returns the total number of time-series registered for a
// given metric name in the gateway's isolated registry.  Returns 0 if absent.
func retryMetricSeries(t *testing.T, gw *harness.Gateway, metricName string) int {
	t.Helper()
	return testutil.CollectAndCount(gw.Metrics, metricName)
}

// retryHistogramSamples returns the observation count for a histogram metric.
func retryHistogramSamples(t *testing.T, gw *harness.Gateway, metricName string) uint64 {
	t.Helper()
	mfs, err := gw.Metrics.Gather()
	if err != nil {
		t.Fatalf("Metrics.Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			if h := m.GetHistogram(); h != nil {
				return h.GetSampleCount()
			}
		}
	}
	return 0
}

// retryCounterHasLabel returns true if any time-series of metricName has the
// given label key=value and a counter value > 0.
func retryCounterHasLabel(t *testing.T, gw *harness.Gateway, metricName, labelKey, labelValue string) bool {
	t.Helper()
	mfs, err := gw.Metrics.Gather()
	if err != nil {
		t.Fatalf("Metrics.Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == labelKey && lp.GetValue() == labelValue {
					if c := m.GetCounter(); c != nil && c.GetValue() > 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

// gatherMetricNames returns all metric names present in the gateway registry.
func gatherMetricNames(t *testing.T, gw *harness.Gateway) map[string]bool {
	t.Helper()
	mfs, err := gw.Metrics.Gather()
	if err != nil {
		t.Fatalf("Metrics.Gather: %v", err)
	}
	out := make(map[string]bool, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = true
	}
	return out
}

// putObject issues a plain PUT to the gateway and returns the response.
func putToGateway(t *testing.T, gw *harness.Gateway, bucket, key string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut,
		fmt.Sprintf("%s/%s/%s", gw.URL, bucket, key),
		bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build PUT request: %v", err)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("PUT %s/%s: %v", bucket, key, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// getFromGateway issues a plain GET to the gateway and discards the body.
func getFromGateway(t *testing.T, gw *harness.Gateway, bucket, key string) *http.Response {
	t.Helper()
	resp, err := gw.HTTPClient().Get(
		fmt.Sprintf("%s/%s/%s", gw.URL, bucket, key))
	if err != nil {
		t.Fatalf("GET %s/%s: %v", bucket, key, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// ── retryAfterServer ─────────────────────────────────────────────────────────

// retryAfterServer is a minimal httptest.Server that injects a 503 + Retry-After
// header for the first `failN` requests, then returns 200 PUT responses.
type retryAfterServer struct {
	srv    *httptest.Server
	failN  int
	mu     sync.Mutex
	called int32 // atomic
}

func newRetryAfterServer(failN int) *retryAfterServer {
	s := &retryAfterServer{failN: failN}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *retryAfterServer) Close() { s.srv.Close() }
func (s *retryAfterServer) URL() string { return s.srv.URL }
func (s *retryAfterServer) requests() int { return int(atomic.LoadInt32(&s.called)) }

func (s *retryAfterServer) handle(w http.ResponseWriter, r *http.Request) {
	n := int(atomic.AddInt32(&s.called, 1))
	if n <= s.failN {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Retry-After", "0") // 0 s — retry immediately
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `<Error><Code>ServiceUnavailable</Code><Message>retry after</Message></Error>`)
		return
	}
	w.Header().Set("ETag", `"ra-etag"`)
	w.WriteHeader(http.StatusOK)
}

// ── Tests ────────────────────────────────────────────────────────────────────

// testRetry_TransientBackend503_MetricEmitted verifies that a transient 503
// causes the gateway to retry and emit s3_backend_retries_total.
// This is the headline conformance gate for V0.6-PERF-2.
func testRetry_TransientBackend503_MetricEmitted(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()
	gw := startRetryGateway(t, backend)

	backend.reset()
	backend.setBehavior(0, 2, http.StatusServiceUnavailable) // 2 failures then succeed

	resp := putToGateway(t, gw, "retry-bucket", "503-metric-key", []byte("data"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after retries, got %d", resp.StatusCode)
	}
	if n := backend.totalRequests(); n < 3 {
		t.Errorf("expected ≥3 backend requests (2 retries + 1 success), got %d", n)
	}

	// s3_backend_retries_total must have at least one time-series recorded.
	if retryMetricSeries(t, gw, "s3_backend_retries_total") == 0 {
		t.Error("s3_backend_retries_total: no series after 503 retries; retry metrics not wired")
	}
}

// testRetry_TransientBackend429_MetricEmitted verifies that HTTP 429 (SlowDown)
// is classified as retryable and s3_backend_retries_total is emitted.
func testRetry_TransientBackend429_MetricEmitted(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()
	gw := startRetryGateway(t, backend)

	backend.reset()
	backend.setBehavior(0, 2, 429)

	resp := putToGateway(t, gw, "retry-bucket", "429-metric-key", []byte("data"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after 429 retries, got %d", resp.StatusCode)
	}
	if n := backend.totalRequests(); n < 3 {
		t.Errorf("expected ≥3 backend requests (2 retried 429 + 1 success), got %d", n)
	}
	if retryMetricSeries(t, gw, "s3_backend_retries_total") == 0 {
		t.Error("s3_backend_retries_total: no series after 429 retries")
	}
}

// testRetry_PersistentFailure_GiveUpMetricEmitted verifies that when all retry
// attempts are exhausted, s3_backend_retry_give_ups_total is incremented.
func testRetry_PersistentFailure_GiveUpMetricEmitted(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()
	gw := startRetryGateway(t, backend)

	backend.reset()
	backend.setBehavior(0, 20, http.StatusServiceUnavailable) // always fails

	resp := getFromGateway(t, gw, "retry-bucket", "give-up-key")
	if resp.StatusCode == http.StatusOK {
		t.Error("expected non-200 after persistent 503, got 200")
	}

	if retryMetricSeries(t, gw, "s3_backend_retry_give_ups_total") == 0 {
		t.Error("s3_backend_retry_give_ups_total: no series after exhausted retries")
	}
}

// testRetry_BackoffHistogramPopulated verifies that s3_backend_retry_backoff_seconds
// accumulates observations during retries.
func testRetry_BackoffHistogramPopulated(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()
	gw := startRetryGateway(t, backend)

	backend.reset()
	backend.setBehavior(0, 2, http.StatusServiceUnavailable)

	putToGateway(t, gw, "retry-bucket", "backoff-histo-key", []byte("data"))

	if n := retryHistogramSamples(t, gw, "s3_backend_retry_backoff_seconds"); n == 0 {
		t.Error("s3_backend_retry_backoff_seconds: 0 observations after retries")
	}
}

// testRetry_AttemptsHistogramPopulated verifies that s3_backend_attempts_per_request
// is populated after a request that required retries.
func testRetry_AttemptsHistogramPopulated(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()
	gw := startRetryGateway(t, backend)

	backend.reset()
	backend.setBehavior(0, 2, http.StatusServiceUnavailable)

	resp := putToGateway(t, gw, "retry-bucket", "attempts-histo-key", []byte("data"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if n := retryHistogramSamples(t, gw, "s3_backend_attempts_per_request"); n == 0 {
		t.Error("s3_backend_attempts_per_request: 0 observations after retried request")
	}
}

// testRetry_MaxAttemptsRespected verifies the gateway makes exactly max_attempts
// (default 3) backend requests under persistent failure — no over-retrying.
func testRetry_MaxAttemptsRespected(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()
	gw := startRetryGateway(t, backend)

	backend.reset()
	backend.setBehavior(0, 100, http.StatusServiceUnavailable) // always fail

	getFromGateway(t, gw, "retry-bucket", "max-attempts-key")

	n := backend.totalRequests()
	if n != 3 {
		t.Errorf("expected exactly 3 backend requests (max_attempts=3), got %d", n)
	}
}

// testRetry_ModeOff_SingleAttempt verifies that backend.retry.mode=off
// results in exactly 1 attempt even on a retryable error.
func testRetry_ModeOff_SingleAttempt(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()

	inst := provider.Instance{
		Endpoint:     backend.URL(),
		Region:       "us-east-1",
		AccessKey:    "retry-access",
		SecretKey:    "retry-secret",
		Bucket:       "retry-bucket",
		ProviderName: "retry-chaos",
	}
	gw := harness.StartGateway(t, inst,
		harness.WithConfigMutator(func(cfg *internalconfig.Config) {
			cfg.Backend.UsePathStyle = true
			cfg.Backend.UseSSL = false
			cfg.Backend.Retry.Mode = "off"
			cfg.Backend.Retry.MaxAttempts = 1
		}),
	)

	backend.reset()
	backend.setBehavior(0, 10, http.StatusServiceUnavailable)

	getFromGateway(t, gw, "retry-bucket", "mode-off-key")

	if n := backend.totalRequests(); n != 1 {
		t.Errorf("mode=off: expected exactly 1 backend request, got %d", n)
	}

	// With mode=off the retry counter series must be absent (never registered
	// because no retryer callbacks are wired).
	if retryMetricSeries(t, gw, "s3_backend_retries_total") != 0 {
		t.Error("mode=off: s3_backend_retries_total should have no series")
	}
}

// testRetry_4xxNotRetried verifies that definite 4xx errors (403 Forbidden)
// are never retried — the backend sees exactly 1 request.
func testRetry_4xxNotRetried(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()
	gw := startRetryGateway(t, backend)

	backend.reset()
	backend.setBehavior(0, 100, http.StatusForbidden)

	getFromGateway(t, gw, "retry-bucket", "forbidden-key")

	if n := backend.totalRequests(); n != 1 {
		t.Errorf("403 should not be retried: expected 1 backend request, got %d", n)
	}
	// No retry metrics.
	if retryMetricSeries(t, gw, "s3_backend_retries_total") != 0 {
		t.Error("403: s3_backend_retries_total should have no series (no retry attempted)")
	}
}

// testRetry_RetryAfterHeaderHonoured verifies that the gateway respects a
// Retry-After: 0 header and retries — succeeding on the next attempt.
func testRetry_RetryAfterHeaderHonoured(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newRetryAfterServer(1) // fail once with Retry-After: 0
	defer backend.Close()

	gw := startRetryGatewayAt(t, backend.URL())

	resp := putToGateway(t, gw, "retry-bucket", "ra-key", []byte("retry-after"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after Retry-After retry, got %d", resp.StatusCode)
	}
	if backend.requests() < 2 {
		t.Errorf("expected ≥2 requests (1 retry + 1 success), got %d", backend.requests())
	}
	if retryMetricSeries(t, gw, "s3_backend_retries_total") == 0 {
		t.Error("s3_backend_retries_total: no series after Retry-After retry")
	}
}

// testRetry_ReasonLabel_Throttle503 verifies that the "throttle_503" reason
// label is present on s3_backend_retries_total after a 503 retry.
func testRetry_ReasonLabel_Throttle503(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()
	gw := startRetryGateway(t, backend)

	backend.reset()
	backend.setBehavior(0, 2, http.StatusServiceUnavailable)

	putToGateway(t, gw, "retry-bucket", "reason-label-key", []byte("data"))

	if !retryCounterHasLabel(t, gw, "s3_backend_retries_total", "reason", "throttle_503") {
		t.Error("s3_backend_retries_total{reason=\"throttle_503\"}: label not present after 503 retries")
	}
}

// testRetry_AllMetricsRegistered verifies all four V0.6-PERF-2 Prometheus
// metrics are present in the gateway registry.
func testRetry_AllMetricsRegistered(t *testing.T, _ provider.Instance) {
	t.Helper()
	backend := newToxicServer()
	defer backend.Close()
	gw := startRetryGateway(t, backend)

	// Trigger a retry to ensure all metrics are initialised.
	backend.reset()
	backend.setBehavior(0, 1, http.StatusServiceUnavailable)
	putToGateway(t, gw, "retry-bucket", "init-key", []byte("init"))

	names := gatherMetricNames(t, gw)
	required := []string{
		"s3_backend_retries_total",
		"s3_backend_attempts_per_request",
		"s3_backend_retry_give_ups_total",
		"s3_backend_retry_backoff_seconds",
	}
	for _, name := range required {
		if !names[name] {
			t.Errorf("metric %q not registered in gateway Prometheus registry", name)
		}
	}
}

// suppress unused-import warning — dto is used transitively via the Gather path
var _ = (*dto.MetricFamily)(nil)
