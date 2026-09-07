//go:build conformance

package conformance

import (
	"bytes"
	"net/url"
	"testing"

	internalconfig "github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testBackendSchemeLessHTTPRoundTrip verifies that UseSSL=false selects HTTP
// when the backend fixture endpoint does not provide a scheme.
func testBackendSchemeLessHTTPRoundTrip(t *testing.T, inst provider.Instance) {
	u, err := url.Parse(inst.Endpoint)
	if err != nil {
		t.Skipf("fixture endpoint cannot be parsed: %v", err)
	}
	if u.Scheme != "http" {
		t.Skipf("fixture endpoint scheme %q is not HTTP", u.Scheme)
	}
	if u.Host == "" {
		t.Skip("fixture endpoint has no host")
	}

	gw := harness.StartGateway(t, inst, harness.WithConfigMutator(func(cfg *internalconfig.Config) {
		cfg.Backend.Endpoint = u.Host
		cfg.Backend.UseSSL = false
		cfg.Backend.UsePathStyle = true
	}))
	key := uniqueKey(t)
	want := bytes.Repeat([]byte("scheme-less-http"), 1024)
	put(t, gw, inst.Bucket, key, want)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, want) {
		t.Fatalf("scheme-less HTTP round-trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
}
