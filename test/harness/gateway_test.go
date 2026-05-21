package harness_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// TestGateway_LifecycleNoProvider verifies the harness can start and stop a
// gateway even when the provider Instance is minimal (no real backend). The
// gateway will fail all S3 operations, but the start/stop lifecycle itself
// should be clean.
//
// NOTE: This is a tier-1 test. It does not start a MinIO container.
func TestGateway_LifecycleNoProvider(t *testing.T) {
	// Use a dummy provider instance pointing at localhost:1 (no server).
	// The gateway will start successfully; S3 operations will fail, but
	// the lifecycle test only verifies the harness itself.
	inst := provider.Instance{
		Endpoint:     "http://127.0.0.1:1",
		Region:       "us-east-1",
		AccessKey:    "DUMMYACCESSKEY",
		SecretKey:    "dummysecretkey00000000000000000000",
		Bucket:       "test-bucket",
		ProviderName: "minio",
	}

	gw := harness.StartGateway(t, inst)

	if gw.URL == "" {
		t.Fatal("gateway URL is empty")
	}
	if gw.Addr == "" {
		t.Fatal("gateway Addr is empty")
	}
	if gw.Metrics == nil {
		t.Fatal("gateway Metrics registry is nil")
	}

	// The health endpoint must return 200.
	resp, err := gw.HTTPClient().Get(gw.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health returned %d, want 200", resp.StatusCode)
	}

	// The metrics endpoint must return 200.
	resp2, err := gw.HTTPClient().Get(gw.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics returned %d, want 200", resp2.StatusCode)
	}
}
