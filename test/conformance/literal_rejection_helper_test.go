//go:build conformance

package conformance

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func TestGH353LiteralRejectionWireClassification(t *testing.T) {
	for _, tc := range []struct {
		code               string
		status, front      int
		frontCode, message string
	}{
		{"XMinioInvalidResourceName", 400, 500, "InternalError", "We encountered an internal error. Please try again."},
		{"InvalidRequest", 400, 500, "InternalError", "We encountered an internal error. Please try again."},
		{"InvalidArgument", 400, 400, "InvalidArgument", "The request contains an invalid argument."},
	} {
		t.Run(tc.code, func(t *testing.T) {
			expect := provider.LiteralPostRejection{BackendStatus: tc.status, BackendCode: tc.code, GatewayStatus: tc.front, GatewayCode: tc.frontCode}
			for _, bad := range []string{"", "other", tc.code} {
				rec := &literalRejectionRecorder{bucket: "bucket", key: "literal/../name", base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if bad == "" {
						return nil, errors.New("transport")
					}
					status := tc.status
					if bad == tc.code {
						status = tc.status
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("<Error><Code>" + bad + "</Code></Error>"))}, nil
				})}
				req, _ := http.NewRequest("PUT", "http://fixture/bucket/literal/../name", nil)
				req.Header.Set("Authorization", "fake")
				resp, _ := rec.RoundTrip(req)
				if resp != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				if rec.matches(expect) != (bad == tc.code) {
					t.Fatal("backend rejection classification wrong")
				}
			}
			resp := &http.Response{StatusCode: tc.front, Header: make(http.Header)}
			body := []byte("<Error><Code>" + tc.frontCode + "</Code><Message>" + tc.message + "</Message></Error>")
			if !literalRejectionFrontend(resp, body, expect) {
				t.Fatal("valid frontend error rejected")
			}
			resp.Header.Set("ETag", "unexpected")
			if literalRejectionFrontend(resp, body, expect) {
				t.Fatal("success header accepted")
			}
			for _, altered := range []literalRejectionRecorder{
				{count: 1, exact: true, transportOK: true, status: 403, code: tc.code},
				{count: 1, exact: false, transportOK: true, status: tc.status, code: tc.code},
				{count: 2, exact: true, transportOK: true, status: tc.status, code: tc.code},
				{count: 1, exact: true, transportOK: true, status: tc.status, code: "AccessDenied"},
			} {
				if altered.matches(expect) {
					t.Fatal("unrelated status, target, count or auth error accepted")
				}
			}
		})
	}
}

func TestGH353LiteralRejectionPreservationAndCleanup(t *testing.T) {
	for _, p := range provider.LiteralPostRejectionProviders() {
		p := p
		t.Run(p.Name(), func(t *testing.T) {
			var mu sync.Mutex
			var key string
			var data []byte
			deletes := 0
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Header.Get("Authorization") == "" {
					t.Error("backend signature missing")
					w.WriteHeader(403)
					return
				}
				if r.URL.Query().Get("list-type") == "2" {
					w.Header().Set("Content-Type", "application/xml")
					if key == "" {
						_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
					} else {
						fmt.Fprintf(w, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>%s</Key></Contents></ListBucketResult>`, key)
					}
					return
				}
				object := strings.TrimPrefix(r.URL.Path, "/bucket/")
				switch r.Method {
				case http.MethodPut:
					if strings.Contains(object, "/literal/../") {
						policy, _ := provider.LiteralPostRejectionForInstance(provider.Instance{ProviderName: p.Name()})
						w.Header().Set("Content-Type", "application/xml")
						w.WriteHeader(policy.BackendStatus)
						fmt.Fprintf(w, `<Error><Code>%s</Code><Message>private</Message></Error>`, policy.BackendCode)
						return
					}
					key = object
					data, _ = io.ReadAll(r.Body)
					w.Header().Set("ETag", `"sentinel"`)
				case http.MethodHead, http.MethodGet:
					if key == "" || object != key {
						t.Error("unexpected HEAD or GET target")
						w.WriteHeader(404)
						return
					}
					w.Header().Set("ETag", `"sentinel"`)
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Header().Set("x-amz-meta-purpose", "neighbor-proof")
					w.Header().Set("Content-Length", fmt.Sprint(len(data)))
					if r.Method == http.MethodGet {
						_, _ = w.Write(data)
					}
				case http.MethodDelete:
					if object != key || key == "" {
						t.Error("cleanup targeted unowned key")
						w.WriteHeader(400)
						return
					}
					deletes++
					key = ""
					w.WriteHeader(204)
				default:
					t.Error("unexpected backend method")
					w.WriteHeader(400)
				}
			}))
			defer fixture.Close()
			t.Run("scenario", func(t *testing.T) {
				inst := provider.Instance{ProviderName: p.Name(), Endpoint: fixture.URL, Region: "us-east-1", Bucket: "bucket", AccessKey: "fake", SecretKey: "fake-secret"}
				expectation, ok := provider.LiteralPostRejectionForInstance(inst)
				if !ok {
					t.Fatal("missing policy")
				}
				testLiteralNativeRejection(t, inst, expectation)
			})
			mu.Lock()
			defer mu.Unlock()
			if deletes != 1 || key != "" || !bytes.Equal(data, []byte("owned neighbor sentinel")) {
				t.Fatal("neighbor ownership/cleanup mismatch")
			}
		})
	}
}
