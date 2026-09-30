//go:build conformance

package conformance

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

type passthroughTransportObservation struct {
	method       string
	body         []byte
	readErr      error
	signatureErr error
}

func observePassthroughTransport(r *http.Request, secret string) passthroughTransportObservation {
	obs := passthroughTransportObservation{method: r.Method}
	ctx, err := api.ValidateSignatureV4(r, secret, 5*time.Minute)
	obs.signatureErr = err
	if ctx != nil {
		ctx.Close()
	}
	obs.body, obs.readErr = io.ReadAll(r.Body)
	return obs
}

func transportSecurityRequest(t *testing.T, gw *harness.Gateway, bucket, method string, body []byte, credential config.GatewayCredential) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, gw.URL+"/"+bucket+"?cors", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/xml")
	signV4Headers(t, req, credential.AccessKey, credential.SecretKey, body)
	client := gw.HTTPClient()
	// Prevent the test client from following the redirect returned by the
	// gateway, so every destination request is attributable to the gateway.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authenticated request failed to reach gateway: %v", err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

// Register in the provider matrix with capability 0: the injected S3 frontend
// owns the redirect response, so no backend-specific capability is necessary.
func testPassthroughRedirectNotFollowed(t *testing.T, inst provider.Instance) {
	credential := config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey, BucketPermissions: []config.BucketPermission{config.BucketPermissionManage}}
	const responseBody = "<Error><Code>TemporaryRedirect</Code></Error>"
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			for _, sameOrigin := range []bool{true, false} {
				t.Run(fmt.Sprintf("%d/%s/same_origin=%t", status, method, sameOrigin), func(t *testing.T) {
					var destinationCalls atomic.Int32
					var initialCalls atomic.Int32
					observations := make(chan passthroughTransportObservation, 1)
					target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						destinationCalls.Add(1)
						w.WriteHeader(http.StatusNoContent)
					}))
					defer target.Close()
					location := target.URL + "/stolen"
					if sameOrigin {
						location = "/stolen"
					}
					frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/stolen" {
							destinationCalls.Add(1)
							w.WriteHeader(http.StatusNoContent)
							return
						}
						initialCalls.Add(1)
						observations <- observePassthroughTransport(r, inst.SecretKey)
						w.Header().Set("Location", location)
						w.WriteHeader(status)
						_, _ = io.WriteString(w, responseBody)
					}))
					defer frontend.Close()
					gw := harness.StartGateway(t, inst, harness.WithAuth(credential), harness.WithConfigMutator(func(cfg *config.Config) {
						cfg.Backend.Endpoint = frontend.URL
					}))
					var body []byte
					if method == http.MethodPut {
						body = []byte("<CORSConfiguration><CORSRule><AllowedOrigin>https://private.example</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>")
					}
					resp, data := transportSecurityRequest(t, gw, inst.Bucket, method, body, credential)
					if resp.StatusCode != status || resp.Header.Get("Location") != location || string(data) != responseBody {
						t.Fatalf("backend redirect not preserved: status=%d location=%q body=%q", resp.StatusCode, resp.Header.Get("Location"), data)
					}
					select {
					case obs := <-observations:
						if obs.signatureErr != nil || obs.readErr != nil || obs.method != method || !bytes.Equal(obs.body, body) {
							t.Fatalf("original backend request invalid: signature=%v read=%v method=%q body=%q", obs.signatureErr, obs.readErr, obs.method, obs.body)
						}
					default:
						t.Fatal("request did not reach the configured backend")
					}
					if initialCalls.Load() != 1 || destinationCalls.Load() != 0 {
						t.Fatalf("backend calls=%d redirect target calls=%d; gateway must not change destination or replay the body", initialCalls.Load(), destinationCalls.Load())
					}
				})
			}
		}
	}
}

// This fixture exercises the raw passthrough TLS path independently of the
// provider's SDK client and of any CapBackendTLSFixture support.
func testPassthroughTLSVerification(t *testing.T, inst provider.Instance) {
	credential := config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey, BucketPermissions: []config.BucketPermission{config.BucketPermissionManage}}
	var calls atomic.Int32
	observations := make(chan passthroughTransportObservation, 2)
	frontend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		observations <- observePassthroughTransport(r, inst.SecretKey)
		w.WriteHeader(http.StatusNoContent)
	}))
	frontend.Config.ErrorLog = log.New(io.Discard, "", 0)
	frontend.StartTLS()
	defer frontend.Close()
	caFile := filepath.Join(t.TempDir(), "passthrough-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: frontend.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		tls  config.BackendTLSConfig
		ok   bool
	}{
		{"untrusted_private_ca", config.BackendTLSConfig{}, false},
		{"custom_ca_verified", config.BackendTLSConfig{CAFile: caFile}, true},
		{"explicit_insecure_opt_in", config.BackendTLSConfig{InsecureSkipVerify: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := harness.StartGateway(t, inst, harness.WithAuth(credential), harness.WithConfigMutator(func(cfg *config.Config) {
				cfg.Backend.Endpoint = frontend.URL
				cfg.Backend.UseSSL = true
				cfg.Backend.TLS = tc.tls
			}))
			body := []byte("<CORSConfiguration/>")
			before := calls.Load()
			resp, data := transportSecurityRequest(t, gw, inst.Bucket, http.MethodPut, body, credential)
			if !tc.ok {
				if resp.StatusCode != http.StatusBadGateway || !bytes.Contains(data, []byte("<Code>BadGateway</Code>")) || calls.Load() != before {
					t.Fatalf("untrusted TLS must fail as backend transport error without delivery: status=%d body=%q calls=%d", resp.StatusCode, data, calls.Load()-before)
				}
				return
			}
			if resp.StatusCode != http.StatusNoContent || calls.Load() != before+1 {
				t.Fatalf("TLS control request failed: status=%d body=%q calls=%d", resp.StatusCode, data, calls.Load()-before)
			}
			select {
			case obs := <-observations:
				if obs.signatureErr != nil || obs.readErr != nil || !bytes.Equal(obs.body, body) {
					t.Fatalf("TLS request invalid: signature=%v read=%v body=%q", obs.signatureErr, obs.readErr, obs.body)
				}
			default:
				t.Fatal("TLS request did not reach backend frontend")
			}
		})
	}
}
