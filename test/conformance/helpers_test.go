//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"

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

	encReader, encMeta, err := eng.Encrypt(ctx, crypto.ObjectContext{Bucket: bucket, Key: key}, bytes.NewReader(plaintext), nil)
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

// copyBackendObject copies the exact stored bytes and metadata between keys in
// one bucket through the portable S3 client contract. It intentionally bypasses
// gateway CopyObject so substitution tests exercise the backend relocation
// boundary itself.
func copyBackendObject(t *testing.T, client s3.Client, bucket, sourceKey, destinationKey string) {
	t.Helper()
	ctx := context.Background()
	body, metadata, err := client.GetObject(ctx, bucket, sourceKey, nil, nil)
	if err != nil {
		t.Fatalf("get backend object %s: %v", sourceKey, err)
	}
	ciphertext, readErr := io.ReadAll(body)
	_ = body.Close()
	if readErr != nil {
		t.Fatalf("read backend object %s: %v", sourceKey, readErr)
	}
	if _, err := client.PutObject(ctx, bucket, destinationKey, bytes.NewReader(ciphertext), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put backend object %s: %v", destinationKey, err)
	}
}

func requireGatewayFailureWithoutPlaintext(t *testing.T, gw *harness.Gateway, bucket, key string, plaintext []byte) {
	t.Helper()
	requireGatewayRequestFailureWithoutPlaintext(t, gw, bucket, key, "", plaintext)
}

// putLegacyBufferedObject writes a pre-SEC-42 buffered object directly to the
// backend, omitting the current format and binding metadata.
func putLegacyBufferedObject(t *testing.T, client s3.Client, bucket, key, password string, plaintext []byte) {
	t.Helper()
	ctx := context.Background()
	salt := bytes.Repeat([]byte{0x31}, 32)
	nonce := bytes.Repeat([]byte{0x42}, 12)
	derived := pbkdf2.Key([]byte(password), salt, crypto.LegacyPBKDF2Iterations, 32, sha256.New)
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatalf("legacy cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("legacy AEAD: %v", err)
	}
	originalSize := fmt.Sprintf("%d", len(plaintext))
	var aad bytes.Buffer
	write := func(value []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		aad.Write(length[:])
		aad.Write(value)
	}
	write([]byte(crypto.AlgorithmAES256GCM))
	write(salt)
	write(nonce)
	write(nil)
	write(nil)
	write([]byte(originalSize))
	ciphertext := aead.Seal(nil, nonce, plaintext, aad.Bytes())
	metadata := map[string]string{
		crypto.MetaEncrypted:    "true",
		crypto.MetaAlgorithm:    crypto.AlgorithmAES256GCM,
		crypto.MetaKeySalt:      base64.RawStdEncoding.EncodeToString(salt),
		crypto.MetaIV:           base64.RawStdEncoding.EncodeToString(nonce),
		crypto.MetaOriginalSize: originalSize,
	}
	if _, err := client.PutObject(ctx, bucket, key, bytes.NewReader(ciphertext), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put legacy object %s: %v", key, err)
	}
}

func requireGatewayRangeFailure(t *testing.T, gw *harness.Gateway, bucket, key string, plaintext []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, objectURL(gw, bucket, key), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-99")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusPartialContent || bytes.Contains(body, plaintext) {
		t.Fatalf("substituted range succeeded: status=%d body=%q", resp.StatusCode, body)
	}
}

// requireGatewayRangeFailureWithoutPlaintext verifies that a relocated object's
// authenticated range path cannot return either a successful range or plaintext.
func requireGatewayRangeFailureWithoutPlaintext(t *testing.T, gw *harness.Gateway, bucket, key, byteRange string, plaintext []byte) {
	t.Helper()
	requireGatewayRequestFailureWithoutPlaintext(t, gw, bucket, key, byteRange, plaintext)
}

func requireGatewayRequestFailureWithoutPlaintext(t *testing.T, gw *harness.Gateway, bucket, key, byteRange string, plaintext []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, objectURL(gw, bucket, key), nil)
	if err != nil {
		t.Fatalf("create GET %s: %v", key, err)
	}
	if byteRange != "" {
		req.Header.Set("Range", byteRange)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read failed response %s: %v", key, readErr)
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent || bytes.Contains(body, plaintext) {
		t.Fatalf("substituted object %s returned plaintext/success: status=%d body=%q", key, resp.StatusCode, body)
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

// replaceKDFMetadata preserves the backend ciphertext and all metadata except
// the authoritative KDF parameter used by the gateway decrypt path.
func replaceKDFMetadata(t *testing.T, client s3.Client, bucket, key, value string) {
	t.Helper()
	ctx := context.Background()
	body, metadata, err := client.GetObject(ctx, bucket, key, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil {
		t.Fatal(err)
	}
	metadata[crypto.MetaKDFParams] = value
	if _, err := client.PutObject(ctx, bucket, key, bytes.NewReader(ciphertext), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
}

// truncateObject removes the authenticated terminal record from a chunked
// object while preserving its provider-managed metadata. It uses only the
// common S3 client contract, so it works across all conformance providers.
func truncateObject(t *testing.T, client s3.Client, bucket, key string, suffix int) {
	t.Helper()
	ctx := context.Background()
	body, metadata, err := client.GetObject(ctx, bucket, key, nil, nil)
	if err != nil {
		t.Fatalf("get encrypted object %s: %v", key, err)
	}
	ciphertext, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil {
		t.Fatalf("read encrypted object %s: %v", key, err)
	}
	if suffix <= 0 || suffix >= len(ciphertext) {
		t.Fatalf("invalid truncation suffix %d for %d-byte object", suffix, len(ciphertext))
	}
	if _, err := client.PutObject(ctx, bucket, key, bytes.NewReader(ciphertext[:len(ciphertext)-suffix]), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("replace truncated object %s: %v", key, err)
	}
}
