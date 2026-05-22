package admin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
	"github.com/kenchrcum/s3-encryption-gateway/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return hex.EncodeToString(b)
}

// --- Bearer Auth Tests ---

func TestBearerAuth_ValidToken(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestBearerAuth_MissingHeader(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestBearerAuth_WrongToken(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token-value-that-is-long")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestBearerAuth_TruncatedToken(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer "+token[:len(token)/2])
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestBearerAuth_MalformedHeader(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("Authorization", "Basic "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// --- Rate Limiter Tests ---

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(10, testLogger())
	for i := 0; i < 10; i++ {
		if !rl.allow("127.0.0.1") {
			t.Fatalf("rate limiter denied request %d (under limit)", i+1)
		}
	}
}

func TestRateLimiter_DeniesOverLimit(t *testing.T) {
	rl := NewRateLimiter(5, testLogger())
	// Exhaust the bucket
	for i := 0; i < 5; i++ {
		rl.allow("127.0.0.1")
	}
	// Next request should be denied
	if rl.allow("127.0.0.1") {
		t.Fatal("rate limiter allowed request over limit")
	}
}

func TestRateLimiter_PerIP(t *testing.T) {
	rl := NewRateLimiter(3, testLogger())
	// Exhaust IP A
	for i := 0; i < 3; i++ {
		rl.allow("10.0.0.1")
	}
	// IP B should still be allowed
	if !rl.allow("10.0.0.2") {
		t.Fatal("rate limiter denied request for different IP")
	}
}

func TestRateLimiter_Middleware429(t *testing.T) {
	rl := NewRateLimiter(1, testLogger())
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request should succeed
	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on first request, got %d", w.Code)
	}

	// Second request should be rate-limited
	req = httptest.NewRequest("GET", "/admin/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on second request, got %d", w.Code)
	}
}

// TestExtractIP_NoPort exercises the extractIP error branch when RemoteAddr has no port.
func TestExtractIP_NoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.RemoteAddr = "192.168.1.1" // no port → SplitHostPort fails
	ip := extractIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("extractIP without port = %q, want 192.168.1.1", ip)
	}
}

// TestRateLimiter_GlobalLimit exercises the globalCount >= globalRPM branch.
func TestRateLimiter_GlobalLimit(t *testing.T) {
	// Create a rate limiter where globalRPM is very small.
	rl := &RateLimiter{
		buckets:   make(map[string]*bucket),
		rpm:       1000,    // high per-IP limit
		globalRPM: 2,       // very low global cap
		globalReset: time.Now().Add(time.Minute),
		logger:    testLogger(),
	}

	// First two requests should succeed (global cap is 2).
	if !rl.allow("10.0.0.1") {
		t.Error("first request should be allowed")
	}
	if !rl.allow("10.0.0.2") {
		t.Error("second request should be allowed")
	}
	// Third request should hit global cap.
	if rl.allow("10.0.0.3") {
		t.Error("third request should be denied by global cap")
	}
}

// TestRateLimiter_TokenRefillCap exercises the token refill cap branch.
func TestRateLimiter_TokenRefillCap(t *testing.T) {
	rl := NewRateLimiter(60, testLogger()) // 60 RPM

	// Make one request to create a bucket.
	rl.allow("192.168.1.1")

	// Manually set lastCheck far in the past to simulate refill.
	rl.mu.Lock()
	b := rl.buckets["192.168.1.1"]
	if b != nil {
		b.tokens = 0
		b.lastCheck = time.Now().Add(-2 * time.Minute) // 2 mins ago → huge refill
	}
	rl.mu.Unlock()

	// Next allow() should refill tokens but cap at rpm.
	if !rl.allow("192.168.1.1") {
		t.Error("expected allow after token refill")
	}
}

// TestRateLimiter_CleanupEvery100 exercises the cleanup on every 100th request.
func TestRateLimiter_CleanupEvery100(t *testing.T) {
	rl := &RateLimiter{
		buckets:     make(map[string]*bucket),
		rpm:         1000,
		globalRPM:   10000,
		globalReset: time.Now().Add(time.Minute),
		globalCount: 99, // next allow() will be the 100th → triggers cleanup
		logger:      testLogger(),
	}

	// Add a stale bucket.
	rl.buckets["stale-ip"] = &bucket{
		tokens:    0,
		lastCheck: time.Now().Add(-10 * time.Minute),
	}

	// The 100th request triggers cleanup.
	rl.allow("new-ip")

	// stale-ip should have been removed.
	rl.mu.Lock()
	_, exists := rl.buckets["stale-ip"]
	rl.mu.Unlock()
	if exists {
		t.Error("cleanup should have removed stale-ip")
	}
}

// TestRateLimiter_MaxMapSizeCap verifies that when the buckets map is at
// capacity, new unseen IPs are rejected while existing IPs still work.
func TestRateLimiter_MaxMapSizeCap(t *testing.T) {
	rl := NewRateLimiter(100, testLogger())

	// Manually fill the map to capacity.
	rl.mu.Lock()
	for i := 0; i < maxAdminRateLimitClients; i++ {
		key := fmt.Sprintf("ip-%d", i)
		rl.buckets[key] = &bucket{
			tokens:    1,
			lastCheck: time.Now(),
		}
	}
	rl.mu.Unlock()

	// A new unseen IP should be rejected.
	if rl.allow("new-ip") {
		t.Error("expected Allow to return false when map is at capacity")
	}

	// An existing IP should still be allowed (within limit).
	if !rl.allow("ip-0") {
		t.Error("expected existing IP to still be allowed")
	}
}

// --- Admin Context Tests ---

func TestIsAdminRequest_OnAdminMux(t *testing.T) {
	var isAdmin bool
	handler := adminContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAdmin = IsAdminRequest(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !isAdmin {
		t.Fatal("expected IsAdminRequest=true on admin mux")
	}
}

func TestIsAdminRequest_OnDataPlane(t *testing.T) {
	// Without admin middleware, the context flag should be false
	req := httptest.NewRequest("GET", "/test", nil)
	if IsAdminRequest(req) {
		t.Fatal("expected IsAdminRequest=false on data-plane")
	}
}

// --- Integration Tests: full admin server + pprof ---

// buildAdminHandler wires the same middleware chain as Server.Start without
// binding to a real TCP port. It returns an http.Handler suitable for use
// with httptest.NewServer or httptest.NewRecorder.
func buildAdminHandler(token string, rpm int, mux *http.ServeMux, logger *logrus.Logger) http.Handler {
	var handler http.Handler = mux
	if rpm > 0 {
		rl := NewRateLimiter(rpm, logger)
		handler = rl.Middleware(handler)
	}
	source := func() []byte { return []byte(token) }
	handler = BearerAuthMiddleware(source, logger)(handler)
	handler = adminContextMiddleware(handler)
	return handler
}

// TestPprofIntegration_HeapWithValidToken verifies the full admin stack:
// adminContextMiddleware → BearerAuthMiddleware → mux → profilingHandler
// A valid bearer token to /debug/pprof/heap must return 200 with a non-empty body.
func TestPprofIntegration_HeapWithValidToken(t *testing.T) {
	token := randomToken(t)
	mux := http.NewServeMux()

	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 2,
		MaxProfileSeconds:     60,
	}
	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	srv := httptest.NewServer(buildAdminHandler(token, 60, mux, silentLogger()))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/debug/pprof/heap", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("expected non-empty pprof body for heap profile")
	}
	// Metric must have been incremented.
	if m.callsContaining("heap", "ok") == 0 {
		t.Errorf("expected heap:ok metric, calls: %v", m.calls)
	}
}

// TestPprofIntegration_NoToken verifies that a request without a bearer token
// returns 401 before any pprof handler is invoked.
func TestPprofIntegration_NoToken(t *testing.T) {
	mux := http.NewServeMux()
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 2,
		MaxProfileSeconds:     60,
	}
	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	srv := httptest.NewServer(buildAdminHandler("secret-token-xyz", 60, mux, silentLogger()))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/debug/pprof/heap", nil)
	// Intentionally no Authorization header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", resp.StatusCode)
	}
	// No pprof metrics should have been recorded since the handler was never reached.
	if len(m.calls) != 0 {
		t.Errorf("expected no metric calls when auth fails, got %v", m.calls)
	}
}

// TestPprofIntegration_RateLimitExhausted verifies that when the admin
// rate-limiter is exhausted all further requests receive 429.
func TestPprofIntegration_RateLimitExhausted(t *testing.T) {
	token := randomToken(t)
	mux := http.NewServeMux()
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 5,
		MaxProfileSeconds:     60,
	}
	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	// RPM=3 so the 4th request within the window is rate-limited.
	srv := httptest.NewServer(buildAdminHandler(token, 3, mux, silentLogger()))
	defer srv.Close()

	doReq := func() int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/debug/pprof/heap", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// First 3 requests should succeed (under the rate limit).
	for i := 0; i < 3; i++ {
		if code := doReq(); code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, code)
		}
	}
	// 4th request must be rate-limited.
	if code := doReq(); code != http.StatusTooManyRequests {
		t.Errorf("expected 429 on 4th request, got %d", code)
	}
}

// TestPprofIntegration_DisabledRoutes404 verifies that without profiling enabled
// the /debug/pprof/* paths return 404 even with a valid token.
func TestPprofIntegration_DisabledRoutes404(t *testing.T) {
	token := randomToken(t)
	mux := http.NewServeMux()
	// Profiling disabled — no routes registered.

	srv := httptest.NewServer(buildAdminHandler(token, 60, mux, silentLogger()))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/debug/pprof/heap", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 when profiling disabled, got %d", resp.StatusCode)
	}
}

// --- Error Response Tests ---

func TestWriteAdminError_Shape(t *testing.T) {
	w := httptest.NewRecorder()
	writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "test message")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json content type, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Unauthorized") {
		t.Fatalf("expected error body to contain 'Unauthorized', got: %s", body)
	}
}

// --- WriteAdminErrorWithRotation Tests ---

func TestWriteAdminErrorWithRotation_Shape(t *testing.T) {
	w := httptest.NewRecorder()
	WriteAdminErrorWithRotation(w, http.StatusConflict, "RotationConflict", "rotation in progress", "rotation-id-abc")

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json content type, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "RotationConflict") {
		t.Errorf("expected body to contain 'RotationConflict', got: %s", body)
	}
	if !strings.Contains(body, "rotation-id-abc") {
		t.Errorf("expected body to contain 'rotation-id-abc', got: %s", body)
	}
	if !strings.Contains(body, "rotation in progress") {
		t.Errorf("expected body to contain message, got: %s", body)
	}
}

// --- NewServer and Server lifecycle Tests ---

func TestNewServer_CreatesMux(t *testing.T) {
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0",
		Auth: config.AdminAuthConfig{
			Token: randomToken(t),
		},
	}
	s := NewServer(cfg, testLogger())
	if s == nil {
		t.Fatal("NewServer() returned nil")
	}
	mux := s.Mux()
	if mux == nil {
		t.Fatal("Server.Mux() returned nil")
	}
}

func TestServer_BoundAddr_BeforeStart(t *testing.T) {
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0",
		Auth: config.AdminAuthConfig{
			Token: randomToken(t),
		},
	}
	s := NewServer(cfg, testLogger())
	addr := s.BoundAddr()
	if addr != "" {
		t.Errorf("BoundAddr() before Start() = %q, want empty string", addr)
	}
}

func TestServer_StartShutdown(t *testing.T) {
	token := randomToken(t)
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0", // OS assigns port
		Auth: config.AdminAuthConfig{
			Token: token,
		},
	}
	s := NewServer(cfg, testLogger())

	// Register a simple handler
	s.Mux().HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Start server in a goroutine
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		errCh <- s.Start(ctx)
	}()

	// Wait for the server to bind (poll BoundAddr)
	var addr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		addr = s.BoundAddr()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if addr == "" {
		t.Fatal("Server did not bind within 3 seconds")
	}

	// Make a request to verify the server is running
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request to server failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Shutdown the server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := s.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown() error: %v", err)
	}

	// Wait for Start() to exit
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Start() error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Start() did not exit after Shutdown")
	}
}

func TestServer_MaxHeaderBytes(t *testing.T) {
	cfg := config.AdminConfig{
		Address:        "127.0.0.1:0",
		MaxHeaderBytes: 32 * 1024, // explicit 32 KB
		Auth: config.AdminAuthConfig{
			Token: randomToken(t),
		},
	}
	s := NewServer(cfg, testLogger())

	s.Mux().HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	// Wait for binding
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.BoundAddr() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if s.BoundAddr() == "" {
		t.Fatal("Server did not bind within 3 seconds")
	}

	if s.httpServer == nil {
		t.Fatal("httpServer not initialized")
	}
	if s.httpServer.MaxHeaderBytes != 32*1024 {
		t.Errorf("MaxHeaderBytes = %d, want %d", s.httpServer.MaxHeaderBytes, 32*1024)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := s.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown() error: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Start() error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Start() did not exit after Shutdown")
	}
}

func TestServer_MaxHeaderBytes_Default(t *testing.T) {
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0",
		// MaxHeaderBytes left at zero → should default to 64 KB
		Auth: config.AdminAuthConfig{
			Token: randomToken(t),
		},
	}
	s := NewServer(cfg, testLogger())

	s.Mux().HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	// Wait for binding
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.BoundAddr() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if s.BoundAddr() == "" {
		t.Fatal("Server did not bind within 3 seconds")
	}

	if s.httpServer == nil {
		t.Fatal("httpServer not initialized")
	}
	if s.httpServer.MaxHeaderBytes != 64*1024 {
		t.Errorf("MaxHeaderBytes = %d, want %d", s.httpServer.MaxHeaderBytes, 64*1024)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := s.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown() error: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Start() error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Start() did not exit after Shutdown")
	}
}

func TestServer_Shutdown_BeforeStart(t *testing.T) {
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0",
		Auth: config.AdminAuthConfig{
			Token: "test-token",
		},
	}
	s := NewServer(cfg, testLogger())

	// Shutdown before Start should return nil (not panic)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := s.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() before Start() returned error: %v", err)
	}
}

// TestServer_Shutdown_ZeroesTokenCache verifies that Shutdown zeroes and nils
// the in-memory token cache (V1.0-SEC-H05).
func TestServer_Shutdown_ZeroesTokenCache(t *testing.T) {
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0",
		Auth: config.AdminAuthConfig{
			Token: "test-token",
		},
	}
	s := NewServer(cfg, testLogger())

	// Set a known token cache value.
	s.tokenCache = []byte("secret-token-cache")

	// Shutdown should zero and nil the cache.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	if s.tokenCache != nil {
		t.Errorf("tokenCache should be nil after Shutdown, got %q", s.tokenCache)
	}
}

// --- RateLimiter cleanup tests ---

func TestRateLimiter_Cleanup_RemovesExpiredEntries(t *testing.T) {
	// Create a rate limiter with very short TTL (via a direct test of cleanup)
	rl := NewRateLimiter(100, testLogger())

	// Add some entries by calling allow()
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.2")

	// Manually set bucket lastCheck to a time in the past beyond the stale threshold
	staleTime := time.Now().Add(-10 * time.Minute) // > 5 minute stale threshold
	rl.mu.Lock()
	for _, b := range rl.buckets {
		b.lastCheck = staleTime
	}
	rl.mu.Unlock()

	// Run cleanup with "now" = current time (stale threshold = 5 minutes ago)
	rl.mu.Lock()
	rl.cleanup(time.Now())
	count := len(rl.buckets)
	rl.mu.Unlock()

	if count != 0 {
		t.Errorf("cleanup() did not remove expired entries; %d remain", count)
	}
}

// --- buildTokenSource tests ---

func TestBuildTokenSource_InlineToken(t *testing.T) {
	cfg := config.AdminConfig{
		Auth: config.AdminAuthConfig{
			Token: "my-inline-token",
		},
	}
	s := NewServer(cfg, testLogger())
	source := s.buildTokenSource()
	got := source()
	if string(got) != "my-inline-token" {
		t.Errorf("buildTokenSource() inline = %q, want %q", string(got), "my-inline-token")
	}
}

func TestBuildTokenSource_TokenFile(t *testing.T) {
	// Write a token to a temp file
	tmpFile, err := os.CreateTemp(t.TempDir(), "admin-token-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	token := "file-token-xyz"
	tmpFile.WriteString(token + "\n") // trailing newline is trimmed
	tmpFile.Close()

	cfg := config.AdminConfig{
		Auth: config.AdminAuthConfig{
			TokenFile: tmpFile.Name(),
		},
	}
	s := NewServer(cfg, testLogger())
	source := s.buildTokenSource()
	got := source()
	if string(got) != token {
		t.Errorf("buildTokenSource() file = %q, want %q", string(got), token)
	}
}

func TestBuildTokenSource_TokenFile_Missing(t *testing.T) {
	cfg := config.AdminConfig{
		Auth: config.AdminAuthConfig{
			TokenFile: "/nonexistent/path/to/token.txt",
		},
	}
	s := NewServer(cfg, testLogger())
	source := s.buildTokenSource()
	// Should return nil (not panic) when file is missing
	got := source()
	if got != nil {
		t.Errorf("buildTokenSource() with missing file should return nil, got: %q", string(got))
	}
}

// testHook is a logrus hook that captures warning messages for tests.
type testHook struct {
	mu       sync.Mutex
	warnings []string
}

func (h *testHook) Levels() []logrus.Level { return logrus.AllLevels }
func (h *testHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if entry.Level == logrus.WarnLevel {
		h.warnings = append(h.warnings, entry.Message)
	}
	return nil
}

// TestBuildTokenSource_TokenFile_Cached verifies that the token file is read
// once at construction time and subsequent calls return the cached value
// without re-reading the disk (V1.0-SEC-22).
func TestBuildTokenSource_TokenFile_Cached(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "admin-token-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	token := "initial-token"
	if _, err := tmpFile.WriteString(token + "\n"); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg := config.AdminConfig{
		Auth: config.AdminAuthConfig{
			TokenFile: tmpFile.Name(),
		},
	}
	s := NewServer(cfg, testLogger())
	source := s.buildTokenSource()

	if got := string(source()); got != token {
		t.Fatalf("initial token = %q, want %q", got, token)
	}

	// Overwrite file with a new token; the cached source must still return
	// the old value because it does not re-read on every call.
	if err := os.WriteFile(tmpFile.Name(), []byte("new-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if got := string(source()); got != token {
		t.Fatalf("cached token should remain %q after file change, got %q", token, got)
	}
}

// TestBuildTokenSource_PermissionCheck verifies that buildTokenSource refuses
// to load a token when the file has overly permissive permissions (group/world
// readable), and loads correctly with restrictive permissions (V1.0-SEC-F2).
func TestBuildTokenSource_PermissionCheck(t *testing.T) {
	token := "my-secret-token"

	// Case 1: World-readable permissions (0644) → should return nil.
	t.Run("world readable", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(t.TempDir(), "admin-token-*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer tmpFile.Close()
		if _, err := tmpFile.WriteString(token + "\n"); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		if err := os.Chmod(tmpFile.Name(), 0644); err != nil {
			t.Fatal(err)
		}

		cfg := config.AdminConfig{
			Auth: config.AdminAuthConfig{
				TokenFile: tmpFile.Name(),
			},
		}
		s := NewServer(cfg, testLogger())
		source := s.buildTokenSource()
		got := source()
		if got != nil {
			t.Errorf("buildTokenSource() with 0644 perms = %q, want nil (refused)", string(got))
		}
	})

	// Case 2: Restrictive permissions (0600) → should load token correctly.
	t.Run("owner only", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(t.TempDir(), "admin-token-*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer tmpFile.Close()
		if _, err := tmpFile.WriteString(token + "\n"); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		if err := os.Chmod(tmpFile.Name(), 0600); err != nil {
			t.Fatal(err)
		}

		cfg := config.AdminConfig{
			Auth: config.AdminAuthConfig{
				TokenFile: tmpFile.Name(),
			},
		}
		s := NewServer(cfg, testLogger())
		source := s.buildTokenSource()
		got := source()
		if string(got) != token {
			t.Errorf("buildTokenSource() with 0600 perms = %q, want %q", string(got), token)
		}
	})
}

// TestRefreshToken_UpdatesCache verifies that calling refreshToken explicitly
// updates the cached token value.
func TestRefreshToken_UpdatesCache(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "admin-token-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := os.WriteFile(tmpFile.Name(), []byte("old-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.AdminConfig{
		Auth: config.AdminAuthConfig{
			TokenFile: tmpFile.Name(),
		},
	}
	s := NewServer(cfg, testLogger())
	source := s.buildTokenSource()

	if got := string(source()); got != "old-token" {
		t.Fatalf("initial token = %q, want old-token", got)
	}

	if err := os.WriteFile(tmpFile.Name(), []byte("refreshed-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	s.refreshToken(tmpFile.Name())

	if got := string(source()); got != "refreshed-token" {
		t.Fatalf("refreshed token = %q, want refreshed-token", got)
	}
}

// TestRefreshToken_PermissionWarning verifies that when the token file
// permissions are relaxed (group/other readable) a warning is emitted.
func TestRefreshToken_PermissionWarning(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "admin-token-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := os.WriteFile(tmpFile.Name(), []byte("token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	hook := &testHook{}
	logger := testLogger()
	logger.AddHook(hook)

	cfg := config.AdminConfig{
		Auth: config.AdminAuthConfig{
			TokenFile: tmpFile.Name(),
		},
	}
	s := NewServer(cfg, logger)
	// Initial buildTokenSource read with 0600 should not produce a warning.
	s.buildTokenSource()

	// Relax permissions to 0644 (group/other read).
	if err := os.Chmod(tmpFile.Name(), 0644); err != nil {
		t.Fatal(err)
	}

	s.refreshToken(tmpFile.Name())

	hook.mu.Lock()
	defer hook.mu.Unlock()
	if len(hook.warnings) == 0 {
		t.Fatal("expected warning for relaxed token file permissions, got none")
	}
	found := false
	for _, w := range hook.warnings {
		if strings.Contains(w, "relaxed") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected warning containing 'relaxed', got: %v", hook.warnings)
	}
}

// TestServer_Start_ListenError verifies Start returns error when the address is invalid.
func TestServer_Start_ListenError(t *testing.T) {
	cfg := config.AdminConfig{
		Address: "256.0.0.0:9999", // invalid IP → net.Listen will fail
		Auth: config.AdminAuthConfig{
			Token: randomToken(t),
		},
	}
	s := NewServer(cfg, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := s.Start(ctx)
	if err == nil {
		t.Error("expected error for invalid listen address")
	}
}

// generateTestCert creates a self-signed RSA certificate for TLS tests.
func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load key pair: %v", err)
	}
	return cert
}

// TestBuildAdminTLSConfig_CipherSuites verifies that the admin TLS config
// contains the expected cipher suites and curve preferences (V1.0-SEC-23).
func TestBuildAdminTLSConfig_CipherSuites(t *testing.T) {
	cert := generateTestCert(t)
	cfg := buildAdminTLSConfig(cert)

	if cfg == nil {
		t.Fatal("buildAdminTLSConfig returned nil")
	}
	if len(cfg.CipherSuites) == 0 {
		t.Error("expected non-empty CipherSuites")
	}
	if len(cfg.CurvePreferences) == 0 {
		t.Error("expected non-empty CurvePreferences")
	}

	// Ensure no CBC-mode cipher suites are present.
	cbcCiphers := map[uint16]bool{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:         true,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:         true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:   true,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:   true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: true,
	}
	for _, cs := range cfg.CipherSuites {
		if cbcCiphers[cs] {
			t.Errorf("CBC cipher suite found in allowed list: 0x%04x", cs)
		}
	}

	// Verify expected ciphers are present.
	expected := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	for _, exp := range expected {
		found := false
		for _, cs := range cfg.CipherSuites {
			if cs == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected cipher suite 0x%04x not found in config", exp)
		}
	}

	// Verify curve preferences.
	expectedCurves := []tls.CurveID{tls.X25519, tls.CurveP256}
	for _, exp := range expectedCurves {
		found := false
		for _, c := range cfg.CurvePreferences {
			if c == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected curve %v not found in CurvePreferences", exp)
		}
	}
}

// TestBuildAdminTLSConfig_RejectCBC verifies that a client offering only
// CBC-mode cipher suites is rejected by the admin listener (V1.0-SEC-23).
func TestBuildAdminTLSConfig_RejectCBC(t *testing.T) {
	cert := generateTestCert(t)
	serverConfig := buildAdminTLSConfig(cert)
	serverConfig.MaxVersion = tls.VersionTLS12 // force TLS 1.2 for this test

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	// Accept goroutine — the handshake will fail, so we just wait for close.
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Force handshake attempt by reading.
		buf := make([]byte, 1)
		conn.Read(buf)
	}()

	clientConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConfig)
	if err == nil {
		conn.Close()
		t.Fatal("expected handshake to fail with CBC-only client, but it succeeded")
	}

	// Clean up the accept goroutine.
	listener.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Log("accept goroutine did not finish in time (non-fatal)")
	}
}

// TestAdminServer_MetricsMiddleware_RecordsRequest verifies that adminMetricsMiddleware
// records gateway_admin_api_requests_total and gateway_admin_api_request_duration_seconds
// when a request is served (V1.0-OBS-1 G6).
func TestAdminServer_MetricsMiddleware_RecordsRequest(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)

	handler := adminMetricsMiddleware(m, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_admin_api_requests_total"] {
		t.Error("gateway_admin_api_requests_total not found after request")
	}
	if !names["gateway_admin_api_request_duration_seconds"] {
		t.Error("gateway_admin_api_request_duration_seconds not found after request")
	}
}
