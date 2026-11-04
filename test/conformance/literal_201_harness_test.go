//go:build conformance

package conformance

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// The real harness and production handler use a local S3 wire fixture, not a
// provider runtime. This reproduces the original oracle's plus-escape mismatch.
func TestGH353Literal201HarnessProjection(t *testing.T) {
	const namespace = "gh353literal-local"
	const key = namespace + "/literal/../plus+percent%25/name.bin"
	var mu sync.Mutex
	var stored []byte
	var metadata http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/bucket/"+key {
			t.Error("backend path mismatch")
			w.WriteHeader(400)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var err error
			stored, err = io.ReadAll(r.Body)
			if err != nil {
				t.Error("backend write failed")
				w.WriteHeader(500)
				return
			}
			metadata = make(http.Header)
			for name, values := range r.Header {
				if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
					metadata[name] = append([]string(nil), values...)
				}
			}
			w.Header().Set("ETag", `"backend"`)
		case http.MethodHead, http.MethodGet:
			for name, values := range metadata {
				w.Header()[name] = append([]string(nil), values...)
			}
			w.Header().Set("ETag", `"backend"`)
			data := stored
			if interval := r.Header.Get("Range"); interval != "" {
				var start, end int
				if _, err := fmt.Sscanf(interval, "bytes=%d-%d", &start, &end); err != nil || start < 0 || end >= len(data) || end < start {
					w.WriteHeader(416)
					return
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
				data = data[start : end+1]
				w.Header().Set("Content-Length", fmt.Sprint(len(data)))
				w.WriteHeader(http.StatusPartialContent)
			} else {
				w.Header().Set("Content-Length", fmt.Sprint(len(data)))
			}
			if r.Method == http.MethodGet {
				_, _ = w.Write(data)
			}
		default:
			w.WriteHeader(405)
		}
	}))
	defer backend.Close()
	providers := provider.LiteralPostPositiveProofProviders()
	if len(providers) != 1 {
		t.Fatal("mandatory provider policy missing")
	}
	inst := provider.Instance{Endpoint: backend.URL, Region: providers[0].Name(), AccessKey: "fixture", SecretKey: "fixture-secret", Bucket: "bucket", ProviderName: providers[0].Name()}
	gw := postGateway(t, inst, postCredential("", nil), harness.WithChunking(true), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	want := bytes.Repeat([]byte("literal provider plaintext-"), 64)
	formKey := namespace + "/literal/../plus+percent%25/${filename}"
	req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, formKey, postCredential("", nil), postFormCase{fields: map[string]string{"success_action_status": "201", "Content-Type": "application/octet-stream", "x-amz-meta-purpose": "literal-proof"}, startsWithConditions: map[string]string{"key": strings.TrimSuffix(formKey, "${filename}")}, file: want, fileName: "dir/sub/name.bin"})
	client := gw.HTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, body := postHTTPWithClient(t, client, req)
	etag := `"` + fmt.Sprintf("%x", md5Sum(want)) + `"`
	location, checks := validateLiteral201(resp.StatusCode, body, gw.URL, inst.Bucket, namespace, key, etag)
	if !checks.valid() {
		t.Fatalf("local projection mismatch checks=%+v", checks)
	}
	// The original oracle required %2B; actual production emits a literal '+'
	// in the encoded path. The old check therefore rejects this valid response.
	oldPath := "/bucket/" + namespace + "/literal/%2E%2E/plus%2Bpercent%2525/name%2Ebin"
	if strings.HasSuffix(location, oldPath) {
		t.Fatal("old oracle unexpectedly accepted production representation")
	}
	for _, tc := range []struct {
		method, interval string
		status           int
		body             []byte
	}{{"GET", "", 200, want}, {"HEAD", "", 200, nil}, {"GET", "bytes=1-7", 206, want[1:8]}} {
		read, data := literalLocationRead(t, client, location, tc.method, tc.interval)
		if read.StatusCode != tc.status || !bytes.Equal(data, tc.body) || read.Header.Get("ETag") != etag || read.Header.Get("X-Amz-Meta-Purpose") != "literal-proof" {
			t.Fatalf("local signed Location read failed status=%d", read.StatusCode)
		}
	}
}
