//go:build conformance

package conformance

// V0.6-OBS-1 pprof conformance tests.
//
// These tests verify the admin profiling surface end-to-end against every
// registered provider. Because pprof is purely an admin-plane feature (it
// does not interact with the S3 backend at all), the tests use cap=0 so
// every provider exercises the same code path.
//
// Run with:
//
//	make test-conformance-minio                          # fast subset
//	go test -tags=conformance ./test/conformance/ -run TestConformance/.*/OBS1_
//
// All time-bounded pprof endpoints (/profile, /trace) use ?seconds=1 to keep
// wall-clock runtime low. The semaphore-429 test uses a cap-1 in-process
// handler so it is instantaneous.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

const obs1AdminToken = "obs1-conformance-token-abc123"

// obs1GlobalProfileMu serialises calls to the CPU `profile` and execution
// `trace` endpoints across all providers running in parallel under
// TestConformance. Both endpoints invoke process-global Go runtime APIs
// (runtime/pprof.StartCPUProfile and runtime/trace.Start) that admit exactly
// one concurrent writer per OS process. Without this mutex, tests from
// different providers (e.g. rustfs and garage, both running concurrently via
// t.Parallel() at the provider level) would race on these runtime singletons
// and one of them would receive a 500 with "cpu profiling already in use" or
// "tracing is already enabled".
//
// Note: per-gateway semaphores (admin.MaxConcurrentProfiles) are NOT enough;
// they guard one gateway instance, but each provider starts its own gateway,
// so the semaphores are disjoint. The Go runtime singletons are shared.
var obs1GlobalProfileMu sync.Mutex

// startOBS1Gateway starts a gateway with the admin listener and pprof enabled.
// The bearer token is obs1AdminToken. The S3 backend is real (inst); the
// pprof tests never touch S3 but a running gateway is required.
func startOBS1Gateway(t *testing.T, inst provider.Instance) *harness.Gateway {
	t.Helper()
	return harness.StartGateway(t, inst,
		harness.WithAdminServer(obs1AdminToken, true /* profilingEnabled */),
	)
}

// adminGet issues a GET to the admin listener with the bearer token and returns
// the response. The caller is responsible for closing resp.Body.
func adminGet(t *testing.T, gw *harness.Gateway, path string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s%s", gw.AdminURL, path)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("adminGet: new request %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+gw.AdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("adminGet: do %s: %v", path, err)
	}
	return resp
}

// testOBS1_AllEndpointsReturn200 verifies that each of the 11 pprof endpoints
// returns 200 with a valid bearer token. Time-bounded endpoints use ?seconds=1.
func testOBS1_AllEndpointsReturn200(t *testing.T, inst provider.Instance) {
	gw := startOBS1Gateway(t, inst)
	if gw.AdminURL == "" {
		t.Fatal("admin URL not set — harness.WithAdminServer may not have wired correctly")
	}

	endpoints := []struct {
		path  string
		query string
	}{
		{"/debug/pprof/", ""},
		{"/debug/pprof/cmdline", ""},
		{"/debug/pprof/profile", "seconds=1"},
		{"/debug/pprof/symbol", ""},
		{"/debug/pprof/trace", "seconds=1"},
		{"/debug/pprof/heap", ""},
		{"/debug/pprof/goroutine", ""},
		{"/debug/pprof/allocs", ""},
		{"/debug/pprof/block", ""},
		{"/debug/pprof/mutex", ""},
		{"/debug/pprof/threadcreate", ""},
	}

	for _, ep := range endpoints {
		ep := ep
		t.Run(ep.path, func(t *testing.T) {
			fullPath := ep.path
			if ep.query != "" {
				fullPath = fullPath + "?" + ep.query
			}
			// Serialise profile/trace calls across all providers. Go's
			// runtime singletons (StartCPUProfile, trace.Start) accept only
			// one writer per process, and providers run in parallel.
			if ep.path == "/debug/pprof/profile" || ep.path == "/debug/pprof/trace" {
				obs1GlobalProfileMu.Lock()
				defer obs1GlobalProfileMu.Unlock()
			}
			resp := adminGet(t, gw, fullPath)
			defer resp.Body.Close()
			_, _ = io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET %s: expected 200, got %d", fullPath, resp.StatusCode)
			}
		})
	}
}

// testOBS1_NoTokenReturns401 verifies that hitting any pprof endpoint without
// a bearer token returns 401 and no profile data.
func testOBS1_NoTokenReturns401(t *testing.T, inst provider.Instance) {
	gw := startOBS1Gateway(t, inst)

	url := fmt.Sprintf("%s/debug/pprof/heap", gw.AdminURL)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	// Intentionally no Authorization header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", resp.StatusCode)
	}
}

// testOBS1_WrongTokenReturns401 verifies that a wrong bearer token is rejected.
func testOBS1_WrongTokenReturns401(t *testing.T, inst provider.Instance) {
	gw := startOBS1Gateway(t, inst)

	url := fmt.Sprintf("%s/debug/pprof/heap", gw.AdminURL)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer this-is-the-wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", resp.StatusCode)
	}
}

// testOBS1_InvalidSecondsReturns400 verifies that ?seconds= outside the
// allowed range is rejected with 400.
func testOBS1_InvalidSecondsReturns400(t *testing.T, inst provider.Instance) {
	gw := startOBS1Gateway(t, inst)

	for _, bad := range []string{"0", "999", "abc", "-5"} {
		url := fmt.Sprintf("%s/debug/pprof/profile?seconds=%s", gw.AdminURL, bad)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+gw.AdminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("seconds=%s: expected 400, got %d", bad, resp.StatusCode)
		}
	}
}

// testOBS1_DataPlaneHasNoPprofRoutes verifies that the S3 data-plane listener
// does NOT expose any /debug/pprof/* routes. Security Review Checklist item #1.
func testOBS1_DataPlaneHasNoPprofRoutes(t *testing.T, inst provider.Instance) {
	gw := startOBS1Gateway(t, inst)

	pprofPaths := []string{
		"/debug/pprof/",
		"/debug/pprof/heap",
		"/debug/pprof/goroutine",
		"/debug/pprof/profile",
	}

	for _, path := range pprofPaths {
		url := fmt.Sprintf("%s%s", gw.URL, path) // data-plane URL
		resp, err := http.DefaultClient.Get(url)
		if err != nil {
			t.Fatalf("data-plane GET %s failed: %v", path, err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("data-plane: path %s returned 200 — must NOT be reachable on data-plane", path)
		}
	}
}

// testOBS1_MetricEmitted verifies that the
// s3_gateway_admin_pprof_requests_total counter is incremented for a heap fetch.
func testOBS1_MetricEmitted(t *testing.T, inst provider.Instance) {
	gw := startOBS1Gateway(t, inst)

	resp := adminGet(t, gw, "/debug/pprof/heap")
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Check that at least one pprof request was counted in the Prometheus registry.
	mfs, err := gw.Metrics.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "s3_gateway_admin_pprof_requests_total" {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "endpoint" && lp.GetValue() == "heap" {
						found = true
					}
				}
			}
		}
	}
	if !found {
		t.Error("expected s3_gateway_admin_pprof_requests_total{endpoint=\"heap\"} to exist after a heap fetch")
	}
}
