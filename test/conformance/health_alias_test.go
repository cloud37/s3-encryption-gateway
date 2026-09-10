//go:build conformance

package conformance

import (
	"io"
	"net/http"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testCompatibleHealthAliases verifies the health URLs used by the MinIO and
// RustFS S3 listeners. It runs against every provider because the gateway's
// public endpoint contract must not vary by backend.
func testCompatibleHealthAliases(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithAuth(config.GatewayCredential{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
	}))

	for _, path := range []string{
		"/minio/health/live", "/minio/health/ready",
		"/health/live", "/health/ready",
	} {
		t.Run(path, func(t *testing.T) {
			resp, err := gw.HTTPClient().Get(gw.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", path, resp.StatusCode, http.StatusOK)
			}
		})
	}
}

// testCompatibleHealthAliasNearMatchesRequireAuth ensures aliases do not
// reintroduce an authentication prefix bypass (V1.0-SEC-30).
func testCompatibleHealthAliasNearMatchesRequireAuth(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithAuth(config.GatewayCredential{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
	}))

	for _, path := range []string{
		"/minio/health/live-extra",
		"/minio/health/ready/anything",
		"/health/live-extra",
		"/health/ready/anything",
	} {
		t.Run(path, func(t *testing.T) {
			resp, err := gw.HTTPClient().Get(gw.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("GET %s status = %d, want %d", path, resp.StatusCode, http.StatusForbidden)
			}
		})
	}
}
