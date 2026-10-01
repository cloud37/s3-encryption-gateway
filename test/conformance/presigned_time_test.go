//go:build conformance

package conformance

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

type presignedTimeTransport struct {
	base  http.RoundTripper
	calls atomic.Int64
}

func (c *presignedTimeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.base.RoundTrip(r)
}

// Sign for the gateway at an explicit time, without changing any clocks or
// sleeping. The real SDK signer is independent of gateway signature validation.
func presignedTimeSDKRequest(t *testing.T, rawURL string, at time.Time, expires []string, header bool) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	credentials := aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}
	signer := v4.NewSigner()
	if header {
		req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		if err := signer.SignHTTP(t.Context(), credentials, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", at); err != nil {
			t.Fatal(err)
		}
		return req
	}
	q := req.URL.Query()
	if expires != nil {
		q["X-Amz-Expires"] = expires
	}
	req.URL.RawQuery = q.Encode()
	signedURL, _, err := signer.PresignHTTP(t.Context(), credentials, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", at)
	if err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, signedURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

type presignedTimeCase struct {
	name    string
	age     time.Duration
	expires []string
	header  bool
	tamper  bool
	code    string
	status  int
}

func testPresignedTimeLifetime(t *testing.T, inst provider.Instance) {
	runPresignedTimeCases(t, inst, []presignedTimeCase{
		{name: "recent_control", age: 2 * time.Minute, expires: []string{"900"}, status: 200},
		{name: "15m_link_after_6m", age: 6 * time.Minute, expires: []string{"900"}, status: 200},
		{name: "30m_link_after_20m", age: 20 * time.Minute, expires: []string{"1800"}, status: 200},
		{name: "60m_link_after_59m", age: 59 * time.Minute, expires: []string{"3600"}, status: 200},
		{name: "7day_link_after_6days", age: 6 * 24 * time.Hour, expires: []string{"604800"}, status: 200},
	})
}

func testPresignedTimeFailures(t *testing.T, inst provider.Instance) {
	runPresignedTimeCases(t, inst, []presignedTimeCase{
		{name: "future_inside_skew", age: -2 * time.Minute, expires: []string{"900"}, status: 200},
		{name: "future_outside_skew", age: -6 * time.Minute, expires: []string{"900"}, code: "RequestTimeTooSkewed", status: 403},
		{name: "expired_inside_skew", age: 3 * time.Minute, expires: []string{"60"}, code: "AccessDenied", status: 403},
		{name: "expired_outside_skew", age: 16 * time.Minute, expires: []string{"900"}, code: "AccessDenied", status: 403},
		{name: "tampered_expiry_after_6m", age: 6 * time.Minute, expires: []string{"900"}, tamper: true, code: "SignatureDoesNotMatch", status: 403},
	})
}

func testPresignedTimeInvalidExpiry(t *testing.T, inst provider.Instance) {
	runPresignedTimeCases(t, inst, []presignedTimeCase{
		{name: "missing", code: "InvalidArgument", status: 400},
		{name: "empty", expires: []string{""}, code: "InvalidArgument", status: 400},
		{name: "zero_future", age: -2 * time.Minute, expires: []string{"0"}, code: "InvalidArgument", status: 400},
		{name: "negative_future", age: -2 * time.Minute, expires: []string{"-1"}, code: "InvalidArgument", status: 400},
		{name: "malformed", expires: []string{"900x"}, code: "InvalidArgument", status: 400},
		{name: "above_maximum", expires: []string{"604801"}, code: "InvalidArgument", status: 400},
		{name: "overflow", expires: []string{"18446744073709551616"}, code: "InvalidArgument", status: 400},
		{name: "duplicate", expires: []string{"900", "900"}, code: "InvalidArgument", status: 400},
	})
}

func testPresignedTimeHeaderSkew(t *testing.T, inst provider.Instance) {
	runPresignedTimeCases(t, inst, []presignedTimeCase{
		{name: "inside_skew", header: true, age: 2 * time.Minute, status: 200},
		{name: "old", header: true, age: 6 * time.Minute, code: "RequestTimeTooSkewed", status: 403},
		{name: "future", header: true, age: -6 * time.Minute, code: "RequestTimeTooSkewed", status: 403},
	})
}

func runPresignedTimeCases(t *testing.T, inst provider.Instance, cases []presignedTimeCase) {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	counted := &presignedTimeTransport{base: transport}
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}),
		harness.WithChunking(true), harness.WithKeyManager(makeAESKEKManager(t)),
		harness.WithPBKDF2Iterations(100000), harness.WithBackendTransport(counted),
		harness.WithConfigMutator(func(cfg *config.Config) { cfg.Auth.ClockSkewTolerance = 5 * time.Minute }),
	)
	key := uniqueKey(t)
	plain := []byte("GH-345 delayed presigned download plaintext")
	putSigned(t, gw, inst.Bucket, key, plain, testAccessKey, testSecretKey)
	client := gw.HTTPClient()
	t.Cleanup(client.CloseIdleConnections)
	rawURL := objectURL(gw, inst.Bucket, key)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := presignedTimeSDKRequest(t, rawURL, time.Now().UTC().Add(-tc.age), tc.expires, tc.header)
			if tc.tamper {
				q := req.URL.Query()
				q.Set("X-Amz-Expires", "1800")
				req.URL.RawQuery = q.Encode()
			}
			before := counted.calls.Load()
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status {
				t.Errorf("status=%d, want %d; body=%s", resp.StatusCode, tc.status, body)
			}
			if tc.status == 200 {
				if !bytes.Equal(body, plain) || resp.ContentLength != int64(len(plain)) {
					t.Errorf("plaintext=%q length=%d, want %q length=%d", body, resp.ContentLength, plain, len(plain))
				}
				return
			}
			if counted.calls.Load() != before {
				t.Error("rejected request contacted backend")
			}
			var response struct{ Code, Message, Resource string }
			if err := xml.Unmarshal(body, &response); err != nil {
				t.Fatal(err)
			}
			if response.Code != tc.code || response.Resource != req.URL.Path {
				t.Errorf("XML=%+v, want code=%s resource=%s", response, tc.code, req.URL.Path)
			}
			if tc.code == "AccessDenied" && response.Message != "Request has expired." {
				t.Errorf("expiry message=%q", response.Message)
			}
			if tc.code == "RequestTimeTooSkewed" && response.Message != "The difference between the request time and the server's time is too large." {
				t.Errorf("skew message=%q", response.Message)
			}
			if tc.code == "InvalidArgument" && response.Message != "X-Amz-Expires must be a single integer between 1 and 604800 seconds." {
				t.Errorf("invalid expiry message=%q", response.Message)
			}
			signature := req.URL.Query().Get("X-Amz-Signature")
			if bytes.Contains(body, []byte(testSecretKey)) || signature != "" && strings.Contains(string(body), signature) || bytes.Contains(body, plain) {
				t.Error("failure response leaked signing material or plaintext")
			}
		})
	}
	// Invalid requests must not poison subsequent authenticated reads.
	if got := getSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey); !bytes.Equal(got, plain) {
		t.Fatalf("post-failure positive control=%q", got)
	}
}
