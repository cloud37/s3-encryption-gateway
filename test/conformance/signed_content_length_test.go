//go:build conformance

package conformance

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// Observe transport serialization, not just the outgoing Header map: Go may
// leave Content-Length in that map while omitting it from the HTTP wire.
type contentLengthProxyTransport struct {
	base          http.RoundTripper
	calls         atomic.Int64
	lengthHeaders atomic.Int64
}

func (c *contentLengthProxyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	trace := &httptrace.ClientTrace{WroteHeaderField: func(key string, _ []string) {
		if strings.EqualFold(key, "Content-Length") {
			c.lengthHeaders.Add(1)
		}
	}}
	return c.base.RoundTrip(r.WithContext(httptrace.WithClientTrace(r.Context(), trace)))
}

// The existing conformance signing primitives are independent of the gateway.
// Unlike the AWS Go SDK, this fixture deliberately signs zero content-length.
func contentLengthSignedDelete(t *testing.T, rawURL, length string, presigned, unsigned bool) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Content-Length", length)
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	scope := timestamp[:8] + "/" + testRegion + "/" + testService + "/aws4_request"
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if presigned {
		signed = []string{"host"}
	} else {
		req.Header.Set("X-Amz-Date", timestamp)
		req.Header.Set("X-Amz-Content-Sha256", sha256Hex(nil))
	}
	if !unsigned {
		signed = append([]string{"content-length"}, signed...)
	}
	q := req.URL.Query()
	if presigned {
		q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
		q.Set("X-Amz-Credential", testAccessKey+"/"+scope)
		q.Set("X-Amz-Date", timestamp)
		q.Set("X-Amz-Expires", "900")
		q.Set("X-Amz-SignedHeaders", strings.Join(signed, ";"))
		req.URL.RawQuery = q.Encode()
	}
	canonical := buildCanonicalRequest(req, presigned, signed)
	key := getSignatureKey(testSecretKey, timestamp[:8], testRegion, testService)
	signature := hex.EncodeToString(hmacSHA256(key, []byte(buildStringToSign(timestamp, scope, canonical))))
	if presigned {
		q.Set("X-Amz-Signature", signature)
		req.URL.RawQuery = q.Encode()
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", testAccessKey, scope, strings.Join(signed, ";"), signature))
	}
	return req
}

func contentLengthSendDelete(t *testing.T, endpoint string, req *http.Request) (int, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(endpoint, "http://"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Always send the real empty body's length, even for a bad-signature control.
	// Request.Write/Client.Do would omit the header before it reached our proxy.
	req.Header.Set("Content-Length", "0")
	if _, err := fmt.Fprintf(conn, "DELETE %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", req.URL.RequestURI(), req.Host); err != nil {
		t.Fatal(err)
	}
	if err := req.Header.Write(conn); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func testSignedContentLengthDelete(t *testing.T, inst provider.Instance) {
	runContentLengthDeletes(t, inst, false)
}

func testSignedContentLengthPresignedDelete(t *testing.T, inst provider.Instance) {
	runContentLengthDeletes(t, inst, true)
}

func runContentLengthDeletes(t *testing.T, inst provider.Instance, presigned bool) {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	counted := &presignedTimeTransport{base: transport}
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}),
		harness.WithChunking(true), harness.WithKeyManager(makeAESKEKManager(t)),
		harness.WithPBKDF2Iterations(100000), harness.WithBackendTransport(counted),
	)
	target, err := url.Parse(gw.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyTransport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(proxyTransport.CloseIdleConnections)
	wire := &contentLengthProxyTransport{base: proxyTransport}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = wire
	var frontendCalls atomic.Int64
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		frontendCalls.Add(1)
		if r.Header.Get("Content-Length") != "0" || r.ContentLength != 0 {
			t.Errorf("frontend did not receive explicit zero length: header=%q length=%d", r.Header.Get("Content-Length"), r.ContentLength)
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(frontend.Close)
	backend := newS3Client(t, inst)
	for _, tc := range []struct {
		name, length string
		proxy        bool
		unsigned     bool
		bad          bool
	}{
		{name: "direct_signed_zero", length: "0"},
		{name: "proxy_unsigned_control", length: "0", proxy: true, unsigned: true},
		{name: "proxy_signed_zero", length: "0", proxy: true},
		{name: "proxy_wrong_signed_length", length: "1", proxy: true, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := uniqueKey(t)
			plain := []byte("GH-356 encrypted blob awaiting authenticated purge")
			putSigned(t, gw, inst.Bucket, key, plain, testAccessKey, testSecretKey)
			t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey) })
			if got := getSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey); !bytes.Equal(got, plain) {
				t.Fatal("encrypted positive control returned wrong plaintext")
			}
			raw, _, err := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, readErr := io.ReadAll(raw)
			_ = raw.Close()
			if readErr != nil || len(ciphertext) == 0 || bytes.Equal(ciphertext, plain) {
				t.Fatalf("backend fixture not genuinely encrypted: err=%v", readErr)
			}
			req := contentLengthSignedDelete(t, objectURL(gw, inst.Bucket, key), tc.length, presigned, tc.unsigned)
			endpoint := gw.URL
			if tc.proxy {
				endpoint = frontend.URL
			}
			beforeBackend, beforeProxy, beforeFrontend := counted.calls.Load(), wire.calls.Load(), frontendCalls.Load()
			status, body := contentLengthSendDelete(t, endpoint, req)
			want := http.StatusNoContent
			if tc.bad {
				want = http.StatusForbidden
			}
			if status != want {
				t.Errorf("DELETE status=%d, want %d; body=%s", status, want, body)
			}
			if tc.proxy && (wire.calls.Load() != beforeProxy+1 || frontendCalls.Load() != beforeFrontend+1 || wire.lengthHeaders.Load() != 0) {
				t.Errorf("proxy did not drop zero length on wire: upstream calls=%d frontend calls=%d length headers=%d", wire.calls.Load()-beforeProxy, frontendCalls.Load()-beforeFrontend, wire.lengthHeaders.Load())
			}
			if tc.bad {
				if counted.calls.Load() != beforeBackend {
					t.Error("rejected signature contacted backend")
				}
				var response struct{ Code, Message, Resource string }
				if err := xml.Unmarshal(body, &response); err != nil {
					t.Fatal(err)
				}
				if response.Code != "SignatureDoesNotMatch" || response.Resource != req.URL.Path || response.Message != "The request signature we calculated does not match the signature you provided. Check your key and signing method." {
					t.Errorf("unexpected auth error: %+v", response)
				}
				if bytes.Contains(body, plain) || bytes.Contains(body, []byte(testSecretKey)) {
					t.Error("auth error leaked plaintext or signing material")
				}
				if got := getSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey); !bytes.Equal(got, plain) {
					t.Fatal("rejected DELETE altered stored object")
				}
				return
			}
			if counted.calls.Load() == beforeBackend {
				t.Error("authenticated DELETE never reached backend")
			}
			result, err := backend.ListObjects(t.Context(), inst.Bucket, key, s3.ListOptions{MaxKeys: 10})
			if err != nil {
				t.Fatal(err)
			}
			for _, object := range result.Objects {
				if object.Key == key {
					t.Error("successful DELETE left object in backend")
				}
			}
		})
	}
}
