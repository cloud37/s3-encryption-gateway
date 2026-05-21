//go:build conformance

package conformance

// Chaos tests — tier-2, in-process, no external Docker backend required.
//
// Each test starts a ToxicServer (an httptest.Server with injectable faults)
// and a harness gateway that talks to it. The gateway runs in-process; the
// ToxicServer runs in-process; no Testcontainers are used here.
//
// Ported from test/chaos_test.go (deleted when the legacy test/ package was
// removed during the v0.6-QA-4 cleanup).

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	internalconfig "github.com/kenchrcum/s3-encryption-gateway/internal/config"
	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// ── ToxicServer ─────────────────────────────────────────────────────────────

// toxicServer is a minimal httptest.Server that can inject latency, transient
// HTTP error codes, or hang connections. It mimics enough of the S3 wire
// protocol for the gateway's S3 client to retry correctly.
type toxicServer struct {
	server       *httptest.Server
	mu           sync.Mutex
	latency      time.Duration
	failCount    int   // how many consecutive requests to fail
	failCode     int   // HTTP status code to return on failure
	requestCount int   // current consecutive failure count
	hangForever  bool
	totalReqs    int32 // atomic
}

func newToxicServer() *toxicServer {
	ts := &toxicServer{}
	ts.server = httptest.NewServer(http.HandlerFunc(ts.handle))
	return ts
}

func (ts *toxicServer) Close() { ts.server.Close() }
func (ts *toxicServer) URL() string { return ts.server.URL }

func (ts *toxicServer) reset() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.latency = 0
	ts.failCount = 0
	ts.failCode = 0
	ts.requestCount = 0
	ts.hangForever = false
	atomic.StoreInt32(&ts.totalReqs, 0)
}

func (ts *toxicServer) setBehavior(latency time.Duration, failCount, failCode int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.latency = latency
	ts.failCount = failCount
	ts.failCode = failCode
	ts.requestCount = 0
}

func (ts *toxicServer) setHang(hang bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.hangForever = hang
}

func (ts *toxicServer) totalRequests() int32 { return atomic.LoadInt32(&ts.totalReqs) }

func (ts *toxicServer) handle(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&ts.totalReqs, 1)

	ts.mu.Lock()
	latency := ts.latency
	shouldFail := ts.requestCount < ts.failCount
	failCode := ts.failCode
	hang := ts.hangForever
	if shouldFail {
		ts.requestCount++
	}
	ts.mu.Unlock()

	if hang {
		// Sleep slightly longer than the test's 2 s context timeout so the
		// gateway's client-side cancellation fires before the "backend" responds.
		// 30 s would stall CI; 4 s is enough to outlast the 2 s ctx timeout.
		time.Sleep(4 * time.Second)
		return
	}
	if latency > 0 {
		time.Sleep(latency)
	}
	if shouldFail && failCode > 0 {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(failCode)
		code := "InternalError"
		msg := "We encountered an internal error. Please try again."
		if failCode == http.StatusServiceUnavailable || failCode == 429 {
			code, msg = "SlowDown", "Reduce your request rate."
		}
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><RequestId>chaos-test</RequestId></Error>`, code, msg)
		return
	}

	// Happy path — minimal S3-compatible responses.
	w.Header().Set("x-amz-request-id", "chaos-ok")
	switch r.Method {
	case "PUT":
		w.Header().Set("ETag", `"chaos-etag"`)
		w.WriteHeader(http.StatusOK)
	case "GET":
		// Respond with stub metadata headers the gateway's decrypt path needs.
		w.Header().Set("ETag", `"chaos-etag"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		// Echo any x-amz-meta-* headers back (gateway stores then reads them).
		for k, vs := range r.Header {
			if len(k) >= 11 && k[:11] == "X-Amz-Meta-" {
				w.Header().Set(k, vs[0])
			}
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "chaos-content")
	case "HEAD":
		w.Header().Set("ETag", `"chaos-etag"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "13") // len("chaos-content")
		w.WriteHeader(http.StatusOK)
	case "DELETE":
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ── Harness helper ──────────────────────────────────────────────────────────

// startChaosGateway starts an in-process harness gateway pointed at toxic's URL.
// No Testcontainers are used; the only external process is the ToxicServer which
// is itself an in-process httptest.Server.
func startChaosGateway(t *testing.T, toxic *toxicServer) *harness.Gateway {
	t.Helper()
	inst := provider.Instance{
		Endpoint:     toxic.URL(),
		Region:       "us-east-1",
		AccessKey:    "chaos-access",
		SecretKey:    "chaos-secret",
		Bucket:       "chaos-bucket",
		ProviderName: "chaos",
	}
	return harness.StartGateway(t, inst,
		harness.WithConfigMutator(func(cfg *internalconfig.Config) {
			cfg.Backend.UsePathStyle = true
			cfg.Backend.UseSSL = false
		}),
	)
}

// ── Tests ────────────────────────────────────────────────────────────────────

// testChaosThrottling verifies that the gateway's S3 client retries
// on transient 429/SlowDown responses and eventually succeeds, and that
// it correctly propagates failure when the backend throttles persistently.
func testChaosThrottling(t *testing.T, _ provider.Instance) {
	t.Helper()

	backend := newToxicServer()
	defer backend.Close()
	gw := startChaosGateway(t, backend)

	t.Run("Transient429", func(t *testing.T) {
		backend.reset()
		backend.setBehavior(0, 2, 429) // fail twice, then succeed

		req, _ := http.NewRequest("PUT",
			fmt.Sprintf("%s/chaos-bucket/throttle-key", gw.URL),
			bytes.NewReader([]byte("data")))
		resp, err := gw.HTTPClient().Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// The gateway must surface 200 after retries succeed.
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 after retries, got %d", resp.StatusCode)
		}
		// Backend must have seen at least 3 requests (2 failures + 1 success).
		if n := backend.totalRequests(); n < 3 {
			t.Errorf("expected ≥3 backend requests (retries), got %d", n)
		}
		// V0.6-PERF-2: verify retry metrics were emitted.
		if testutil.CollectAndCount(gw.Metrics, "s3_backend_retries_total") == 0 {
			t.Error("s3_backend_retries_total: no series recorded after 429 retries")
		}
	})

	t.Run("Persistent429", func(t *testing.T) {
		backend.reset()
		backend.setBehavior(0, 20, 429) // fail more times than max retries

		req, _ := http.NewRequest("PUT",
			fmt.Sprintf("%s/chaos-bucket/throttle-persist", gw.URL),
			bytes.NewReader([]byte("data")))
		resp, err := gw.HTTPClient().Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("expected failure for persistent throttling, got 200 OK")
		}
		// V0.6-PERF-2: verify give-up metric was emitted.
		if testutil.CollectAndCount(gw.Metrics, "s3_backend_retry_give_ups_total") == 0 {
			t.Error("s3_backend_retry_give_ups_total: no series recorded after exhausted retries")
		}
	})
}

// testChaosBackend500 verifies retry behaviour on transient backend 500s
// and hard failure on persistent 500s.
func testChaosBackend500(t *testing.T, _ provider.Instance) {
	t.Helper()

	backend := newToxicServer()
	defer backend.Close()
	gw := startChaosGateway(t, backend)

	t.Run("Transient500", func(t *testing.T) {
		backend.reset()
		backend.setBehavior(0, 2, 500)

		// Use GET so the SDK retries (PUT is not safe to retry automatically).
		resp, err := gw.HTTPClient().Get(
			fmt.Sprintf("%s/chaos-bucket/retry-key", gw.URL))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// After retries the backend serves 200 with stub content.
		// The gateway may fail to decrypt (no real encryption headers) and
		// return 500 — that is acceptable here; what we care about is that
		// the backend saw retry traffic, not the HTTP status code from the gateway.
		if n := backend.totalRequests(); n < 3 {
			t.Errorf("expected ≥3 backend requests (retries on 500), got %d", n)
		}
		// V0.6-PERF-2: retry metrics must have fired.
		if testutil.CollectAndCount(gw.Metrics, "s3_backend_retries_total") == 0 {
			t.Error("s3_backend_retries_total: no series recorded after 500 retries")
		}
	})

	t.Run("Persistent500", func(t *testing.T) {
		backend.reset()
		backend.setBehavior(0, 20, 500)

		resp, err := gw.HTTPClient().Get(
			fmt.Sprintf("%s/chaos-bucket/fail-key", gw.URL))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("expected failure for persistent 500s, got 200 OK")
		}
		// V0.6-PERF-2: give-up metric must have fired.
		if testutil.CollectAndCount(gw.Metrics, "s3_backend_retry_give_ups_total") == 0 {
			t.Error("s3_backend_retry_give_ups_total: no series recorded after exhausted 500 retries")
		}
	})
}

// testChaosNetworkTimeout verifies that the gateway propagates a client-side
// context cancellation (or timeout) correctly when the backend hangs.
func testChaosNetworkTimeout(t *testing.T, _ provider.Instance) {
	t.Helper()

	backend := newToxicServer()
	defer backend.Close()
	gw := startChaosGateway(t, backend)

	backend.reset()
	backend.setHang(true)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/chaos-bucket/hang-key", gw.URL), nil)

	start := time.Now()
	resp, err := gw.HTTPClient().Do(req)
	elapsed := time.Since(start)

	if err != nil {
		// Context timeout reached before the gateway responded — correct.
		t.Logf("request failed as expected after %v: %v", elapsed, err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// If the gateway responded before the context timed out it must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected non-200 when backend hangs, got 200 after %v", elapsed)
	} else {
		t.Logf("gateway returned %d after %v (backend was hanging)", resp.StatusCode, elapsed)
	}
}
