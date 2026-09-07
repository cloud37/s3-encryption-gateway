//go:build conformance

package conformance

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	internalconfig "github.com/cloud37/s3-encryption-gateway/internal/config"
	internalS3 "github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func backendTLSGateway(t *testing.T, inst provider.Instance, insecure bool, ca string) *harness.Gateway {
	t.Helper()
	tlsInst, _, _, _ := backendTLSValues(inst)
	return harness.StartGateway(t, tlsInst, harness.WithConfigMutator(func(cfg *internalconfig.Config) {
		cfg.Backend.Endpoint = tlsInst.BackendTLS.Endpoint
		cfg.Backend.UseSSL = true
		cfg.Backend.TLS.CAFile = ca
		cfg.Backend.TLS.InsecureSkipVerify = insecure
	}))
}

// backendTLSValues returns the exact initialized TLS fixture resource and
// credentials without changing the ordinary provider instance used by the
// rest of the conformance matrix.
func backendTLSValues(inst provider.Instance) (provider.Instance, string, string, string) {
	tlsInst := inst
	if inst.BackendTLS != nil {
		tlsInst.Endpoint = inst.BackendTLS.Endpoint
		if inst.BackendTLS.Bucket != "" {
			tlsInst.Bucket = inst.BackendTLS.Bucket
		}
		if inst.BackendTLS.AccessKey != "" {
			tlsInst.AccessKey = inst.BackendTLS.AccessKey
		}
		if inst.BackendTLS.SecretKey != "" {
			tlsInst.SecretKey = inst.BackendTLS.SecretKey
		}
	}
	return tlsInst, tlsInst.Bucket, tlsInst.AccessKey, tlsInst.SecretKey
}

func backendTLSAuthOptions(inst provider.Instance) harness.Option {
	return harness.WithAuth(internalconfig.GatewayCredential{AccessKey: inst.AccessKey, SecretKey: inst.SecretKey})
}

func testBackendTLSCustomCARoundTrip(t *testing.T, inst provider.Instance) {
	if inst.BackendTLS == nil {
		t.Skip("backend TLS fixture unavailable")
	}
	gw := backendTLSGateway(t, inst, false, inst.BackendTLS.CAFile)
	_, bucket, _, _ := backendTLSValues(inst)
	want := []byte("private CA round trip")
	key := uniqueKey(t)
	put(t, gw, bucket, key, want)
	if got := get(t, gw, bucket, key); !bytes.Equal(got, want) {
		t.Fatalf("TLS round trip mismatch")
	}
}

func testBackendTLSInsecureSkipVerifyRoundTrip(t *testing.T, inst provider.Instance) {
	if inst.BackendTLS == nil {
		t.Skip("backend TLS fixture unavailable")
	}
	tlsInst, bucket, _, _ := backendTLSValues(inst)
	gw := backendTLSGateway(t, tlsInst, true, "")
	want := []byte("insecure diagnostic round trip")
	key := uniqueKey(t)
	put(t, gw, bucket, key, want)
	if got := get(t, gw, bucket, key); !bytes.Equal(got, want) {
		t.Fatalf("TLS insecure round trip mismatch")
	}
}

func testBackendTLSUntrustedCertificateRejected(t *testing.T, inst provider.Instance) {
	if inst.BackendTLS == nil {
		t.Skip("backend TLS fixture unavailable")
	}
	tlsInst, bucket, accessKey, secretKey := backendTLSValues(inst)
	gw := harness.StartGateway(t, tlsInst, backendTLSAuthOptions(tlsInst), harness.WithConfigMutator(func(cfg *internalconfig.Config) {
		cfg.Backend.Endpoint = tlsInst.BackendTLS.Endpoint
		cfg.Backend.UseSSL = true
		cfg.Backend.TLS.CAFile = ""
	}))
	key := uniqueKey(t)
	req, err := http.NewRequest("PUT", objectURL(gw, bucket, key), bytes.NewReader([]byte("must not persist")))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, accessKey, secretKey, []byte("must not persist"))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("authenticated request did not reach gateway: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read backend TLS failure response: %v", readErr)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		t.Fatalf("request failed gateway authentication (%d), not backend TLS verification: %s", resp.StatusCode, body)
	}
	if resp.StatusCode < 400 {
		t.Fatalf("untrusted backend unexpectedly accepted mutation: %d", resp.StatusCode)
	}
	if resp.StatusCode < 500 {
		t.Fatalf("expected backend transport failure, got status=%d body=%q", resp.StatusCode, body)
	}
	backendCfg := &internalconfig.BackendConfig{Endpoint: tlsInst.BackendTLS.Endpoint, Region: tlsInst.Region, AccessKey: accessKey, SecretKey: secretKey, Provider: tlsInst.ProviderName, UseSSL: true, UsePathStyle: true, TLS: internalconfig.BackendTLSConfig{CAFile: tlsInst.BackendTLS.CAFile}}
	backend, err := internalS3.NewClient(backendCfg)
	if err != nil {
		t.Fatalf("new TLS fixture client: %v", err)
	}
	if _, err := backend.HeadObject(t.Context(), bucket, key, nil); err == nil {
		t.Fatalf("untrusted request mutated backend object %q", key)
	}
}
