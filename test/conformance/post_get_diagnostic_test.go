//go:build conformance

package conformance

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// A controlled backend exercises the same signed POST and HTTP GET/HEAD path
// as provider feedback. Injected differences are hypotheses, not provider facts.
func TestGH353PostGetSafeSourceDiagnostics(t *testing.T) {
	for _, variant := range []string{"normal", "language", "language-missing", "short", "gzip", "stored-gzip"} {
		t.Run(variant, func(t *testing.T) {
			var mu sync.Mutex
			var stored []byte
			var headers http.Header
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodPut {
					stored, _ = io.ReadAll(r.Body)
					headers = r.Header.Clone()
					w.Header().Set("ETag", `"opaque"`)
					return
				}
				for _, name := range []string{"Content-Type", "Content-Encoding", "Content-Language"} {
					w.Header().Set(name, headers.Get(name))
				}
				w.Header().Set("ETag", `"opaque"`)
				data := stored
				if r.Method == http.MethodGet {
					switch variant {
					case "language":
						w.Header().Set("Content-Language", "other")
					case "language-missing":
						w.Header().Del("Content-Language")
					case "short":
						data = stored[:len(stored)-1]
					case "gzip":
						var compressed bytes.Buffer
						writer := gzip.NewWriter(&compressed)
						_, _ = writer.Write(stored)
						_ = writer.Close()
						data = compressed.Bytes()
						w.Header().Set("Content-Encoding", "gzip")
					}
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(data)))
				if r.Method == http.MethodGet {
					_, _ = w.Write(data)
				}
			}))
			defer backend.Close()
			inst := provider.Instance{ProviderName: provider.GH353FeedbackConservativeProvider().Name(), Endpoint: backend.URL, Region: testRegion, Bucket: "bucket", AccessKey: "backend-access", SecretKey: "backend-secret"}
			payload := bytes.Repeat([]byte("local-object"), 256)
			if variant == "stored-gzip" {
				var compressed bytes.Buffer
				writer := gzip.NewWriter(&compressed)
				_, _ = writer.Write(payload)
				_ = writer.Close()
				payload = compressed.Bytes()
			}
			recorder := &postWriteRecorder{base: http.DefaultTransport, diagnosticEnabled: true, diagnosticLength: int64(len(payload)), diagnosticLanguage: "en"}
			credential := postCredential("", nil)
			gw := postGateway(t, inst, credential, harness.WithPolicyManager(newBypassPolicyManager(t, "bucket")), harness.WithBackendTransport(recorder))
			fields := map[string]string{"Content-Type": "application/octet-stream", "Content-Encoding": "identity", "Content-Language": "en"}
			if variant == "stored-gzip" {
				fields["Content-Encoding"] = "gzip"
			}
			req := makePostRequest(t, postFormURL(gw, "bucket"), "bucket", "key", credential, postFormCase{fields: fields, file: payload})
			resp, _ := postHTTP(t, gw, credential, req)
			if resp.StatusCode != http.StatusNoContent {
				t.Fatal("local POST failed")
			}
			get, body := postGatewayGet(t, gw, "bucket", "key", "", nil)
			head := postGatewayHead(t, gw, "bucket", "key", "", nil)
			if get.StatusCode != 200 || head.StatusCode != 200 || head.Header.Get("Content-Language") != "en" {
				t.Fatal("local response failure")
			}
			summary := recorder.safeReadSummary()
			if variant == "language" || variant == "language-missing" {
				if get.Header.Get("Content-Language") == "en" || !strings.Contains(summary, "language_match=false") {
					t.Fatal("GET metadata source difference not detected")
				}
				recorder.diagnosticMu.Lock()
				found := false
				for _, observation := range recorder.diagnosticReads {
					if observation.method == http.MethodGet && observation.languagePresent == (variant == "language") && !observation.languageMatch {
						found = true
					}
				}
				recorder.diagnosticMu.Unlock()
				if !found {
					t.Fatal("GET language presence not distinguished")
				}
			} else if variant == "short" {
				if bytes.Equal(body, payload) || !strings.Contains(summary, "length_match=false") {
					t.Fatal("GET length difference not detected")
				}
			} else if variant == "stored-gzip" {
				if bytes.Equal(body, payload) || !get.Uncompressed {
					t.Fatal("client automatic decompression hypothesis not reproduced")
				}
				request := signedGatewayRequest(t, http.MethodGet, postObjectURL(gw, "bucket", "key"), nil, "", nil)
				transport := &http.Transport{DisableCompression: true}
				defer transport.CloseIdleConnections()
				raw, err := (&http.Client{Transport: transport}).Do(request)
				if err != nil {
					t.Fatal("raw client request failed")
				}
				rawBody, err := io.ReadAll(raw.Body)
				raw.Body.Close()
				if err != nil || !bytes.Equal(rawBody, payload) || raw.Header.Get("Content-Encoding") != "gzip" {
					t.Fatal("raw encoded payload not preserved")
				}
			} else if !bytes.Equal(body, payload) {
				t.Fatal("GET payload mismatch")
			}
			mu.Lock()
			atRestMatches := bytes.Equal(stored, payload)
			mu.Unlock()
			if !atRestMatches {
				t.Fatal("bypass POST did not persist exact plaintext")
			}
			if variant == "gzip" && (!get.Uncompressed || !strings.Contains(summary, "uncompressed=false")) {
				t.Fatal("frontend automatic decompression not detected")
			}
			if strings.Contains(summary, "local-object") || strings.Contains(summary, "other") || strings.Contains(summary, "bucket") {
				t.Fatal("unsafe diagnostic output")
			}
			if variant == "normal" {
				put := signedGatewayRequest(t, http.MethodPut, postObjectURL(gw, "bucket", "ordinary"), payload, "", http.Header{"Content-Type": {"application/octet-stream"}, "Content-Encoding": {"identity"}, "Content-Language": {"en"}})
				putResponse, _ := postHTTP(t, gw, credential, put)
				if putResponse.StatusCode != http.StatusOK {
					t.Fatal("ordinary PUT failed")
				}
				mu.Lock()
				putStored := bytes.Equal(stored, payload)
				mu.Unlock()
				read, putBody := postGatewayGet(t, gw, "bucket", "ordinary", "", nil)
				putHead := postGatewayHead(t, gw, "bucket", "ordinary", "", nil)
				if !putStored || read.StatusCode != 200 || putHead.StatusCode != 200 || !bytes.Equal(putBody, payload) || read.Header.Get("Content-Language") != "en" || putHead.Header.Get("Content-Language") != "en" {
					t.Fatal("ordinary PUT bypass round trip failed")
				}
			}
		})
	}
}

// SeaweedFS 4.48's directory branch serves content without user metadata.
// This local HTTP simulation tests the gateway consequence, not provider runtime.
func TestGH353LiteralDirectoryMetadataSource(t *testing.T) {
	const key = "literal/dot..segment/plus+percent%25/雪/"
	for _, tc := range []struct{ omit, chunked bool }{{false, false}, {true, false}, {true, true}} {
		t.Run(fmt.Sprintf("omit-metadata-%t-chunked-%t", tc.omit, tc.chunked), func(t *testing.T) {
			var stored []byte
			var headers http.Header
			var mu sync.Mutex
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodPut {
					stored, _ = io.ReadAll(r.Body)
					headers = r.Header.Clone()
					w.Header().Set("ETag", `"opaque"`)
					return
				}
				if !tc.omit {
					for name, values := range headers {
						if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") || strings.EqualFold(name, "Content-Encoding") || strings.EqualFold(name, "Content-Language") {
							w.Header()[name] = values
						}
					}
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Length", fmt.Sprint(len(stored)))
				w.Header().Set("ETag", `"opaque"`)
				if r.Method == http.MethodGet {
					_, _ = w.Write(stored)
				}
			}))
			defer backend.Close()
			inst := provider.Instance{ProviderName: "seaweedfs", Endpoint: backend.URL, Region: testRegion, Bucket: "bucket", AccessKey: "backend-access", SecretKey: "backend-secret"}
			payload := bytes.Repeat([]byte("local-encrypted-object"), 1024)
			recorder := &postWriteRecorder{base: http.DefaultTransport, diagnosticEnabled: true, diagnosticLength: int64(len(payload)), diagnosticLanguage: "en", diagnosticTarget: "/bucket/" + key}
			credential := postCredential("", nil)
			gw := postGateway(t, inst, credential, harness.WithChunking(tc.chunked), harness.WithBackendTransport(recorder))
			fields := map[string]string{"Content-Type": "application/octet-stream", "Content-Encoding": "identity", "Content-Language": "en"}
			req := makePostRequest(t, postFormURL(gw, "bucket"), "bucket", key, credential, postFormCase{fields: fields, file: payload})
			resp, _ := postHTTP(t, gw, credential, req)
			if resp.StatusCode != http.StatusNoContent {
				t.Fatal("local encrypted POST failed")
			}
			get, body := postGatewayGet(t, gw, "bucket", key, "", nil)
			if get.StatusCode != http.StatusOK || bytes.Equal(body, payload) == tc.omit {
				t.Fatalf("unexpected local GET classification result status=%d bytes_match=%t backend={%s}", get.StatusCode, bytes.Equal(body, payload), recorder.safeReadSummary())
			}
			summary := recorder.safeReadSummary()
			if strings.Contains(summary, "target_match=false") || !strings.Contains(summary, "marker_present=true expanded_marker=true") {
				t.Fatal("PUT marker or literal target missing")
			}
			if tc.omit && !strings.Contains(summary, "marker_present=false expanded_marker=false") {
				t.Fatal("GET marker loss not detected")
			}
			if !tc.omit && strings.Contains(summary, "marker_present=false") {
				t.Fatal("marker unexpectedly lost")
			}
		})
	}
}
