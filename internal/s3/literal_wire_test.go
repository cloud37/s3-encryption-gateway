package s3

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func TestGH353LiteralRouting_SDKWire(t *testing.T) {
	const key = "literal/../plus+percent%25/name.bin"
	var mu sync.Mutex
	var methods []string
	valid := true
	c, _ := gh353WireClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		methods = append(methods, r.Method)
		if r.URL.Path != "/bucket/"+key || r.URL.Path == "/bucket/plus+percent%25/name.bin" || r.Header.Get("Authorization") == "" {
			valid = false
		}
		original := r.Header.Get("Authorization")
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		clone.Header.Del("Authorization")
		signedAt, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		if err != nil {
			valid = false
		} else {
			signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
			if signer.SignHTTP(context.Background(), aws.Credentials{AccessKeyID: "backend", SecretAccessKey: "backend-secret", SessionToken: "backend-token"}, clone, r.Header.Get("X-Amz-Content-Sha256"), "s3", "us-east-1", signedAt) != nil || clone.Header.Get("Authorization") != original {
				valid = false
			}
		}
		w.Header().Set("ETag", `"wire"`)
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "abc")
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})
	_, err := c.PutObject(t.Context(), "bucket", key, strings.NewReader("abc"), nil, nil, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatal("SDK PUT failed")
	}
	body, _, err := c.GetObject(t.Context(), "bucket", key, nil, nil)
	if err != nil {
		t.Fatal("SDK GET failed")
	}
	data, err := io.ReadAll(body)
	body.Close()
	if err != nil || !bytes.Equal(data, []byte("abc")) {
		t.Fatal("SDK GET payload mismatch")
	}
	if _, err := c.HeadObject(t.Context(), "bucket", key, nil); err != nil {
		t.Fatal("SDK HEAD failed")
	}
	mu.Lock()
	defer mu.Unlock()
	if !valid || len(methods) != 3 || methods[0] != http.MethodPut || methods[1] != http.MethodGet || methods[2] != http.MethodHead {
		t.Fatalf("SDK wire contract valid=%t method_count=%d", valid, len(methods))
	}
}
