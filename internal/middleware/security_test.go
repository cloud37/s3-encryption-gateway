package middleware

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := SecurityHeadersMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Check security headers
	headers := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	for _, header := range headers {
		if rr.Header().Get(header) == "" {
			t.Errorf("Expected header %s to be set", header)
		}
	}

	// HSTS should not be set for non-TLS requests
	if rr.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS header should not be set for non-TLS requests")
	}
}

func TestSecurityHeadersMiddleware_TLS(t *testing.T) {
	handler := SecurityHeadersMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{} // Simulate TLS connection
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// HSTS should be set for TLS requests
	if rr.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS header should be set for TLS requests")
	}
}

func TestSecurityHeadersMiddleware_ForceHTTPS(t *testing.T) {
	// With forceHTTPS=true and no TLS, HSTS should still be set.
	handlerTrue := SecurityHeadersMiddleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handlerTrue.ServeHTTP(rr, req)

	if rr.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS header should be set when forceHTTPS=true even without TLS")
	}

	// With forceHTTPS=false and no TLS, HSTS should NOT be set.
	handlerFalse := SecurityHeadersMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr2 := httptest.NewRecorder()
	handlerFalse.ServeHTTP(rr2, req)

	if rr2.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS header should NOT be set when forceHTTPS=false and no TLS")
	}

	// With forceHTTPS=true and TLS present, HSTS should still be set.
	reqTLS := httptest.NewRequest("GET", "/test", nil)
	reqTLS.TLS = &tls.ConnectionState{}
	rr3 := httptest.NewRecorder()
	handlerTrue.ServeHTTP(rr3, reqTLS)

	if rr3.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS header should be set when forceHTTPS=true with TLS")
	}
}

func TestRateLimiter(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Suppress logs during testing

	limiter := NewRateLimiter(5, 1*time.Second, logger)
	defer limiter.Stop()

	// Test allowing requests within limit
	for i := 0; i < 5; i++ {
		if !limiter.Allow("test-client") {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// Test rate limiting
	if limiter.Allow("test-client") {
		t.Error("Request should be rate limited")
	}

	// Test different clients
	if !limiter.Allow("other-client") {
		t.Error("Different client should be allowed")
	}
}

func TestRateLimiter_WindowReset(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	limiter := NewRateLimiter(5, 100*time.Millisecond, logger)
	defer limiter.Stop()

	// Exhaust limit
	for i := 0; i < 5; i++ {
		limiter.Allow("test-client")
	}

	// Should be rate limited
	if limiter.Allow("test-client") {
		t.Error("Request should be rate limited")
	}

	// Wait for window to reset
	time.Sleep(150 * time.Millisecond)

	// Should be allowed after window reset
	if !limiter.Allow("test-client") {
		t.Error("Request should be allowed after window reset")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	limiter := NewRateLimiter(2, 1*time.Second, logger)
	defer limiter.Stop()

	handler := RateLimitMiddleware(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Request %d should succeed, got status %d", i+1, rr.Code)
		}
	}

	// Third request should be rate limited
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rr.Code)
	}
}

func TestGetClientKey(t *testing.T) {
	// Test without IP extractor (legacy behavior - uses RemoteAddr)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	key := getClientKey(req)
	// Without an extractor, it extracts IP from RemoteAddr (port removed)
	if key != "127.0.0.1" {
		t.Errorf("Expected key %s, got %s", "127.0.0.1", key)
	}

	// Note: Full trusted proxy testing is done in internal/util/ip_test.go
	// This test just verifies the fallback behavior when no extractor is set.
}

// TestRateLimiter_CleanupRuns verifies the cleanup goroutine runs and removes
// expired entries without panicking.
func TestRateLimiter_CleanupRuns(t *testing.T) {
	// Use a very short cleanup interval so the test finishes quickly.
	rl := &RateLimiter{
		requests:        make(map[string]*tokenBucket),
		limit:           100,
		window:          1 * time.Second,
		cleanupInterval: 10 * time.Millisecond,
		stopCleanup:     make(chan struct{}),
	}

	// Add a stale entry.
	rl.mu.Lock()
	rl.requests["stale-key"] = &tokenBucket{
		tokens:     1,
		lastUpdate: time.Now().Add(-1 * time.Minute), // already expired
	}
	rl.mu.Unlock()

	// Start cleanup.
	go rl.cleanup()

	// Wait for at least one cleanup tick.
	time.Sleep(30 * time.Millisecond)

	// Stop.
	rl.Stop()

	// The stale entry should have been removed.
	rl.mu.Lock()
	_, exists := rl.requests["stale-key"]
	rl.mu.Unlock()
	if exists {
		t.Error("cleanup should have removed the stale entry")
	}
}

// TestRateLimiter_AllowTiming verifies that the timing side-channel mitigation
// in Allow keeps P99 latency within the allowed bound (minAllowTime + 40µs).
func TestRateLimiter_AllowTiming(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	limiter := NewRateLimiter(1000, 1*time.Second, logger)
	defer limiter.Stop()

	const iterations = 10000
	latencies := make([]time.Duration, iterations)

	for i := 0; i < iterations; i++ {
		start := time.Now()
		limiter.Allow("timing-client")
		latencies[i] = time.Since(start)
	}

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	p99 := latencies[len(latencies)*99/100]
	maxAllowed := minAllowTime + 40*time.Microsecond

	if p99 > maxAllowed {
		t.Fatalf("P99 latency %v exceeds allowed bound %v", p99, maxAllowed)
	}
}

// TestRateLimiter_MaxMapSizeCap verifies that when the requests map is at
// capacity, new unseen keys are rejected while existing keys still work.
func TestRateLimiter_MaxMapSizeCap(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	limiter := NewRateLimiter(1, 1*time.Hour, logger)
	defer limiter.Stop()

	// Manually fill the map to capacity.
	limiter.mu.Lock()
	for i := 0; i < maxRateLimitClients; i++ {
		key := fmt.Sprintf("client-%d", i)
		limiter.requests[key] = &tokenBucket{
			tokens:     1,
			lastUpdate: time.Now(),
		}
	}
	limiter.mu.Unlock()

	// A new unseen key should be rejected.
	if limiter.Allow("new-client") {
		t.Error("expected Allow to return false when map is at capacity")
	}

	// An existing key should still be allowed (within limit).
	if !limiter.Allow("client-0") {
		t.Error("expected existing key to still be allowed")
	}
}

// BenchmarkRateLimiter_Allow measures the latency of Allow under load.
func BenchmarkRateLimiter_Allow(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	limiter := NewRateLimiter(1000, 1*time.Second, logger)
	defer limiter.Stop()

	b.ReportAllocs()
	b.SetBytes(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow("bench-client")
	}
}
