//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// keySeq provides unique keys within a test run.
var keySeq int64

// uniqueSuffix returns a short unique string suitable for use in key names.
func uniqueSuffix(t *testing.T) string {
	t.Helper()
	n := atomic.AddInt64(&keySeq, 1)
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), n)
}

// uniqueKey returns a unique object key that encodes the test name and a
// monotonically-increasing counter so parallel tests never collide.
func uniqueKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("conf/%s/%s", sanitizeName(t.Name()), uniqueSuffix(t))
}

// sanitizeName replaces characters invalid in S3 keys with underscores.
func sanitizeName(s string) string {
	var out []byte
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '/' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}

// objectURL returns the full URL for an object in the gateway.
func objectURL(gw *harness.Gateway, bucket, key string) string {
	return fmt.Sprintf("%s/%s/%s", gw.URL, bucket, key)
}

// put uploads data to the gateway and fails the test if the status is not 200.
func put(t *testing.T, gw *harness.Gateway, bucket, key string, data []byte) {
	t.Helper()
	req, err := http.NewRequest("PUT", objectURL(gw, bucket, key), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("put: new request: %v", err)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("put %q: %v", key, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put %q: status %d: %s", key, resp.StatusCode, string(body))
	}
}

// get downloads an object from the gateway and returns the body bytes.
// The test is failed if the response status is not 200.
func get(t *testing.T, gw *harness.Gateway, bucket, key string) []byte {
	t.Helper()
	resp, err := gw.HTTPClient().Get(objectURL(gw, bucket, key))
	if err != nil {
		t.Fatalf("get %q: %v", key, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("get %q: read body: %v", key, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get %q: status %d: %s", key, resp.StatusCode, string(body))
	}
	return body
}

// getRange downloads a byte range from the gateway. start and end are
// inclusive, matching the HTTP Range header semantics.
func getRange(t *testing.T, gw *harness.Gateway, bucket, key string, start, end int64) []byte {
	t.Helper()
	req, err := http.NewRequest("GET", objectURL(gw, bucket, key), nil)
	if err != nil {
		t.Fatalf("getRange: new request: %v", err)
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("getRange %q [%d-%d]: %v", key, start, end, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("getRange %q: read body: %v", key, err)
	}
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("getRange %q [%d-%d]: status %d (want 206): %s",
			key, start, end, resp.StatusCode, string(body))
	}
	return body
}

// newS3Client creates an internal S3 client from a provider instance.
// Used by tests that write objects directly to the backend (bypassing the gateway).
func newS3Client(t *testing.T, inst provider.Instance) s3.Client {
	t.Helper()
	cfg := &config.BackendConfig{
		Endpoint:     inst.Endpoint,
		Region:       inst.Region,
		AccessKey:    inst.AccessKey,
		SecretKey:    inst.SecretKey,
		Provider:     inst.ProviderName,
		UseSSL:       false,
		UsePathStyle: true,
	}
	client, err := s3.NewClient(cfg)
	if err != nil {
		t.Fatalf("newS3Client: %v", err)
	}
	return client
}

// putEncryptedObject encrypts plaintext and stores it in the bucket via the
// internal S3 client. metaMutate allows test-specific metadata modifications
// (e.g. deleting a field to simulate legacy formats).
func putEncryptedObject(t *testing.T, client s3.Client, eng crypto.EncryptionEngine, bucket, key string, plaintext []byte, metaMutate func(map[string]string)) {
	t.Helper()
	ctx := context.Background()

	encReader, encMeta, err := eng.Encrypt(ctx, bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt %s: %v", key, err)
	}
	cipherdata, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read encrypted %s: %v", key, err)
	}

	if metaMutate != nil {
		metaMutate(encMeta)
	}

	if _, err := client.PutObject(ctx, bucket, key, bytes.NewReader(cipherdata), encMeta, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put object %s: %v", key, err)
	}
}

// headMeta reads object metadata via HeadObject.
func headMeta(t *testing.T, client s3.Client, bucket, key string) map[string]string {
	t.Helper()
	ctx := context.Background()
	meta, err := client.HeadObject(ctx, bucket, key, nil)
	if err != nil {
		t.Fatalf("head object %s: %v", key, err)
	}
	return meta
}
