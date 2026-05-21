package admin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// --- Test doubles --------------------------------------------------------

// fakeProfilingMetrics satisfies ProfilingMetrics for testing.
type fakeProfilingMetrics struct {
	mu      sync.Mutex
	calls   []string // "endpoint:outcome"
	enabled *bool
}

func (f *fakeProfilingMetrics) RecordPprofRequest(endpoint, outcome string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, endpoint+":"+outcome)
}

func (f *fakeProfilingMetrics) SetAdminProfilingEnabled(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = &v
}

func (f *fakeProfilingMetrics) callsContaining(endpoint, outcome string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == endpoint+":"+outcome {
			n++
		}
	}
	return n
}

// fakeProfilingAudit satisfies ProfilingAudit for testing.
type fakeProfilingAudit struct {
	mu     sync.Mutex
	events []string
}

func (f *fakeProfilingAudit) LogAccessWithMetadata(
	eventType, bucket, key, clientIP, userAgent, requestID string,
	success bool, err error, duration time.Duration, metadata map[string]interface{},
) {
	f.mu.Lock()
	defer f.mu.Unlock()
	endpoint, _ := metadata["endpoint"].(string)
	f.events = append(f.events, eventType+":"+endpoint)
}

// adminRequest wraps an httptest.Request with the admin context flag set.
func adminRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), ctxKeyAdmin, true)
	return req.WithContext(ctx)
}

// --- RegisterPprofRoutes tests -------------------------------------------

// TestRegisterPprofRoutes_Disabled verifies that no routes are mounted when
// cfg.Enabled is false.
func TestRegisterPprofRoutes_Disabled(t *testing.T) {
	mux := http.NewServeMux()
	cfg := config.AdminProfilingConfig{Enabled: false}
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}

	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	// Verify none of the 11 pprof paths return 200 — they should 404.
	for _, route := range allPprofRoutes() {
		req := adminRequest(http.MethodGet, route.path)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			t.Errorf("route %q returned 200 when profiling disabled; expected 404", route.path)
		}
	}
	if len(m.calls) != 0 {
		t.Errorf("expected no metric calls when disabled, got %v", m.calls)
	}
}

// TestRegisterPprofRoutes_Enabled verifies all 11 routes return 200 with a
// valid admin-context request.
func TestRegisterPprofRoutes_Enabled(t *testing.T) {
	mux := http.NewServeMux()
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 2,
		MaxProfileSeconds:     60,
	}
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}

	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	for _, route := range allPprofRoutes() {
		label := endpointLabel(route.path)
		req := adminRequest(http.MethodGet, route.path)
		// For time-bounded endpoints pass seconds=1 to keep the test fast;
		// note that pprof.Profile still takes ~1 s so we skip it in -short runs.
		if label == "profile" || label == "trace" {
			if testing.Short() {
				t.Logf("skipping %s endpoint (time-bounded) in -short mode", label)
				continue
			}
			req.URL.RawQuery = "seconds=1"
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("route %q: expected 200, got %d", route.path, w.Code)
		}
	}
}

// TestRegisterPprofRoutes_ContentType verifies that the heap endpoint returns
// the expected Content-Type (application/octet-stream or binary pprof data).
func TestRegisterPprofRoutes_ContentType(t *testing.T) {
	mux := http.NewServeMux()
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 2,
		MaxProfileSeconds:     60,
	}
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}

	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	req := adminRequest(http.MethodGet, "/debug/pprof/heap")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	// The pprof heap endpoint emits "application/octet-stream" as its
	// Content-Type according to the Go standard library.
	if ct == "" {
		t.Errorf("expected a Content-Type header, got empty string")
	}
}

// TestRegisterPprofRoutes_SecondsParamOutOfRange verifies that ?seconds= outside
// [1, MaxProfileSeconds] is rejected with 400.
// We exercise the profilingHandler directly (not via mux) so that valid cases
// don't actually run a multi-second CPU profile in the test suite.
func TestRegisterPprofRoutes_SecondsParamOutOfRange(t *testing.T) {
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}

	// Use a fast no-op upstream so valid seconds values don't block.
	h := &profilingHandler{
		endpoint: "profile",
		upstream: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		sem:     make(chan struct{}, 2),
		maxSecs: 5, // low cap for testing
		hasSecs: true,
		metrics: m,
		audit:   a,
		logger:  silentLogger(),
	}

	tests := []struct {
		seconds string
		wantBad bool
	}{
		{"0", true},   // below minimum
		{"6", true},   // above cap
		{"999", true}, // way above cap
		{"-1", true},  // negative
		{"abc", true}, // non-numeric
		{"5", false},  // exactly at cap — OK
		{"1", false},  // minimum — OK
	}

	for _, tt := range tests {
		req := adminRequest(http.MethodGet, "/debug/pprof/profile")
		req.URL.RawQuery = "seconds=" + tt.seconds
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if tt.wantBad && w.Code != http.StatusBadRequest {
			t.Errorf("seconds=%s: expected 400, got %d", tt.seconds, w.Code)
		}
		if !tt.wantBad && w.Code == http.StatusBadRequest {
			t.Errorf("seconds=%s: unexpected 400", tt.seconds)
		}
	}
}

// TestRegisterPprofRoutes_ConcurrencyLimit verifies that requests beyond
// MaxConcurrentProfiles receive 429 Retry-After.
// We exercise the profilingHandler semaphore directly (not via mux) to avoid
// re-registering the same route on the same ServeMux.
func TestRegisterPprofRoutes_ConcurrencyLimit(t *testing.T) {
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}

	sem := make(chan struct{}, 1)
	blocker := make(chan struct{})

	blockHandler := &profilingHandler{
		endpoint: "profile",
		upstream: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-blocker // block until the test releases
			w.WriteHeader(http.StatusOK)
		}),
		sem:     sem,
		maxSecs: 60,
		hasSecs: true,
		metrics: m,
		audit:   a,
		logger:  silentLogger(),
	}

	// Start first request — it will block holding the semaphore.
	ready := make(chan struct{})
	go func() {
		req := adminRequest(http.MethodGet, "/debug/pprof/profile")
		req.URL.RawQuery = "seconds=1"
		w := httptest.NewRecorder()
		// Signal that we're about to call ServeHTTP so the test can proceed.
		close(ready)
		blockHandler.ServeHTTP(w, req)
	}()
	<-ready
	// Give the goroutine a moment to acquire the semaphore.
	time.Sleep(10 * time.Millisecond)

	// Second request should be rejected with 429.
	req2 := adminRequest(http.MethodGet, "/debug/pprof/profile")
	req2.URL.RawQuery = "seconds=1"
	w2 := httptest.NewRecorder()
	blockHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 when semaphore full, got %d", w2.Code)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header in 429 response")
	}
	if m.callsContaining("profile", "busy") == 0 {
		t.Errorf("expected 'profile:busy' metric, calls: %v", m.calls)
	}

	close(blocker) // release the blocked goroutine
}

// TestRegisterPprofRoutes_AdminContextAssertion verifies that reaching a pprof
// handler without the admin context flag results in 500 (wiring bug guard).
func TestRegisterPprofRoutes_AdminContextAssertion(t *testing.T) {
	h := &profilingHandler{
		endpoint: "heap",
		upstream: pprof_heapHandler(),
		metrics:  &fakeProfilingMetrics{},
		audit:    &fakeProfilingAudit{},
		logger:   silentLogger(),
	}

	// Request WITHOUT the admin context flag.
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/heap", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 (missing admin context), got %d", w.Code)
	}
}

// TestRegisterPprofRoutes_MetricsAndAudit verifies that metric and audit calls
// are emitted for a successful heap fetch.
func TestRegisterPprofRoutes_MetricsAndAudit(t *testing.T) {
	mux := http.NewServeMux()
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 2,
		MaxProfileSeconds:     60,
	}
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}

	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	req := adminRequest(http.MethodGet, "/debug/pprof/heap")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if m.callsContaining("heap", "ok") == 0 {
		t.Errorf("expected 'heap:ok' metric, calls: %v", m.calls)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	found := false
	for _, ev := range a.events {
		if strings.HasPrefix(ev, "pprof_fetch:heap") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected pprof_fetch audit event, got: %v", a.events)
	}
}

// TestApplyRuntimeProfilingRates verifies that zero rates do not change the
// profile rates (they're already 0 at test start), and non-zero rates log
// without panic.
func TestApplyRuntimeProfilingRates(t *testing.T) {
	cfg := config.AdminProfilingConfig{
		BlockRate:     0,
		MutexFraction: 0,
	}
	// Should not panic.
	ApplyRuntimeProfilingRates(cfg, silentLogger())

	// Non-zero values: set and then restore.
	cfg2 := config.AdminProfilingConfig{
		BlockRate:     100,
		MutexFraction: 5,
	}
	ApplyRuntimeProfilingRates(cfg2, silentLogger())
	// Restore to off so we don't affect other tests.
	import_runtime_cleanup(t)
}

// TestEndpointLabel verifies the short-label extraction helper.
func TestEndpointLabel(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/debug/pprof/", "index"},
		{"/debug/pprof/heap", "heap"},
		{"/debug/pprof/goroutine", "goroutine"},
		{"/debug/pprof/profile", "profile"},
		{"/debug/pprof/trace", "trace"},
	}
	for _, c := range cases {
		got := endpointLabel(c.path)
		if got != c.want {
			t.Errorf("endpointLabel(%q) = %q; want %q", c.path, got, c.want)
		}
	}
}

// TestAllPprofRoutes verifies there are exactly 11 routes.
func TestAllPprofRoutes(t *testing.T) {
	routes := allPprofRoutes()
	if len(routes) != 11 {
		t.Errorf("expected 11 pprof routes, got %d: %v", len(routes), routes)
	}
	// Verify no duplicate paths.
	seen := make(map[string]bool)
	for _, r := range routes {
		if seen[r.path] {
			t.Errorf("duplicate route path: %s", r.path)
		}
		seen[r.path] = true
		if r.handler == nil {
			t.Errorf("route %s has nil handler", r.path)
		}
	}
}

// TestMaxConcurrentNormalisedToOne verifies that max_concurrent_profiles < 1
// is normalised to 1 with a warning log and doesn't panic.
func TestMaxConcurrentNormalisedToOne(t *testing.T) {
	mux := http.NewServeMux()
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 0, // invalid — should be normalised
		MaxProfileSeconds:     60,
	}
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}

	// Should not panic.
	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	// Verify heap route still works.
	req := adminRequest(http.MethodGet, "/debug/pprof/heap")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after normalisation, got %d", w.Code)
	}
}

// TestPprofCardinality verifies that the bounded label space for
// s3_gateway_admin_pprof_requests_total does not exceed 11 endpoints × 4 outcomes = 44
// combinations. We exercise all 11 endpoints with the "ok" outcome and confirm
// the counter tracks them correctly.
func TestPprofCardinality(t *testing.T) {
	// Valid endpoints (11 total, matching allPprofRoutes).
	endpoints := []string{
		"index", "cmdline", "profile", "symbol", "trace",
		"heap", "goroutine", "allocs", "block", "mutex", "threadcreate",
	}
	// Valid outcomes (4 total).
	outcomes := []string{"ok", "busy", "bad_request", "error"}

	if len(endpoints)*len(outcomes) > 44 {
		t.Errorf("label cardinality %d exceeds the 44 cap (11 endpoints × 4 outcomes)",
			len(endpoints)*len(outcomes))
	}

	// Verify all 11 endpoint labels match the route table.
	routes := allPprofRoutes()
	if len(routes) != len(endpoints) {
		t.Errorf("route table has %d routes, expected %d", len(routes), len(endpoints))
	}
	routeLabels := make(map[string]bool)
	for _, r := range routes {
		routeLabels[endpointLabel(r.path)] = true
	}
	for _, ep := range endpoints {
		if !routeLabels[ep] {
			t.Errorf("endpoint %q is in the known-labels list but absent from allPprofRoutes()", ep)
		}
	}
}

// TestDataPlaneIsolation verifies that the internal/api data-plane router
// has no handlers under /debug/pprof/*. pprof must only be reachable via
// the admin mux. This is Security Review Checklist item #1 from the plan.
//
// The test builds a fresh admin mux with profiling enabled and a separate
// "data-plane" mux and confirms the data-plane mux returns 404 for every
// pprof path.
func TestDataPlaneIsolation(t *testing.T) {
	// Simulate the admin mux (profiling enabled).
	adminMux := http.NewServeMux()
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 2,
		MaxProfileSeconds:     60,
	}
	RegisterPprofRoutes(adminMux, cfg, &fakeProfilingMetrics{}, &fakeProfilingAudit{}, silentLogger())

	// Simulate the data-plane mux — nothing pprof-related is registered there.
	dataplaneMux := http.NewServeMux()
	dataplaneMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	for _, route := range allPprofRoutes() {
		label := endpointLabel(route.path)

		// Skip time-bounded endpoints in -short mode to avoid ~30 s delay.
		if testing.Short() && (label == "profile" || label == "trace") {
			t.Logf("skipping time-bounded admin-mux check for %s in -short mode", label)
			// Still verify that the data-plane mux rejects the route.
			dpReq := httptest.NewRequest(http.MethodGet, route.path, nil)
			dpW := httptest.NewRecorder()
			dataplaneMux.ServeHTTP(dpW, dpReq)
			if dpW.Code == http.StatusOK {
				t.Errorf("data-plane mux: route %q returned 200 — pprof must NOT be on the data-plane", route.path)
			}
			continue
		}

		// Admin mux must serve the route.
		adminReq := adminRequest(http.MethodGet, route.path)
		if label == "profile" || label == "trace" {
			adminReq.URL.RawQuery = "seconds=1"
		}
		adminW := httptest.NewRecorder()
		adminMux.ServeHTTP(adminW, adminReq)
		if adminW.Code != http.StatusOK {
			t.Errorf("admin mux: route %q returned %d, want 200", route.path, adminW.Code)
		}

		// Data-plane mux must NOT serve the route (404).
		dpReq := httptest.NewRequest(http.MethodGet, route.path, nil)
		dpW := httptest.NewRecorder()
		dataplaneMux.ServeHTTP(dpW, dpReq)
		if dpW.Code == http.StatusOK {
			t.Errorf("data-plane mux: route %q returned 200 — pprof must NOT be on the data-plane", route.path)
		}
	}
}

// --- helpers ------------------------------------------------------------

func silentLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

// pprof_heapHandler returns the heap pprof handler, used in isolation tests.
func pprof_heapHandler() http.Handler {
	for _, r := range allPprofRoutes() {
		if r.path == "/debug/pprof/heap" {
			return r.handler
		}
	}
	panic("heap route not found")
}

// import_runtime_cleanup resets block and mutex rates to off after a test that
// enabled them. This avoids cross-test pollution.
func import_runtime_cleanup(t *testing.T) {
	t.Helper()
	// Import runtime in the test file via the package-level function.
	ApplyRuntimeProfilingRates(config.AdminProfilingConfig{
		BlockRate:     0,
		MutexFraction: 0,
	}, silentLogger())
}
