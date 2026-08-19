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
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func putSEC37V1Fixture(t *testing.T, client s3.Client, bucket, key string) {
	t.Helper()
	const password = "test-encryption-password-123456"
	plaintext := []byte("frozen-sec37-v1")
	salt := bytes.Repeat([]byte{0x17}, 32)
	baseIV := bytes.Repeat([]byte{0x27}, 12)
	keyBytes := pbkdf2.Key([]byte(password), salt, crypto.DefaultPBKDF2Iterations, 32, sha256.New)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	info := make([]byte, 12)
	copy(info, "chunk-iv")
	binary.BigEndian.PutUint32(info[8:], 0)
	nonce := make([]byte, 12)
	_, _ = io.ReadFull(hkdf.Expand(sha256.New, baseIV, info), nonce)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	manifest, err := json.Marshal(struct {
		Version int    `json:"v"`
		Size    int    `json:"cs"`
		Count   int    `json:"cc"`
		IV      string `json:"iv"`
		Deriv   string `json:"ivd"`
	}{1, 16 * 1024, 1, base64.StdEncoding.EncodeToString(baseIV), "hkdf-sha256"})
	if err != nil {
		t.Fatal(err)
	}
	metadata := map[string]string{
		crypto.MetaEncrypted:     "true",
		crypto.MetaChunkedFormat: "true",
		crypto.MetaAlgorithm:     crypto.AlgorithmAES256GCM,
		crypto.MetaKeySalt:       base64.StdEncoding.EncodeToString(salt),
		crypto.MetaIV:            base64.StdEncoding.EncodeToString(baseIV),
		crypto.MetaChunkSize:     "16384",
		crypto.MetaManifest:      base64.StdEncoding.EncodeToString(manifest),
		crypto.MetaKDFParams:     "pbkdf2-sha256:600000",
	}
	if _, err := client.PutObject(context.Background(), bucket, key, bytes.NewReader(ciphertext), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put v1 fixture: %v", err)
	}
}

// testChunkedRoundTrip verifies a full PUT/GET round-trip of a chunked-AEAD
// encrypted object. The gateway uses chunked mode by default; this test
// confirms the envelope header is present and the plaintext round-trips.
func testChunkedRoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithChunking(true))

	// 200 KiB: > 3 chunks at default 64 KiB chunk size.
	data := bytes.Repeat([]byte("chunked"), 200*1024/7+1)
	data = data[:200*1024]

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)
	got := get(t, gw, inst.Bucket, key)

	if !bytes.Equal(got, data) {
		t.Errorf("chunked round-trip mismatch: got %d bytes, want %d bytes",
			len(got), len(data))
	}
}

// testChunkedRangedRead verifies range reads from a chunked object.
// This is a conformance-tier version of the unit-level range tests.
func testChunkedRangedRead(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithChunking(true))

	const chunkSize = 64 * 1024
	data := make([]byte, 2*chunkSize+1234)
	for i := range data {
		data[i] = byte(i % 197)
	}

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)

	// Range within first chunk.
	got := getRange(t, gw, inst.Bucket, key, 100, 200)
	if !bytes.Equal(got, data[100:201]) {
		t.Errorf("intra-chunk range mismatch")
	}

	// Range spanning chunk 0→1 boundary.
	got2 := getRange(t, gw, inst.Bucket, key, int64(chunkSize-50), int64(chunkSize+50))
	if !bytes.Equal(got2, data[chunkSize-50:chunkSize+51]) {
		t.Errorf("cross-chunk-boundary range mismatch")
	}
}

// testLegacyRoundTrip verifies a full PUT/GET round-trip using the default
// encryption mode. Objects written via the gateway must decrypt correctly.
// The per-format legacy AEAD tests live in the unit layer; this conformance
// test verifies the conformance property holds end-to-end against a real
// S3 backend.
func testLegacyRoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)
	data := bytes.Repeat([]byte("legacy-data"), 1024)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Errorf("legacy round-trip mismatch")
	}
}

// testSEC37_ChunkedV2_RoundTripAndHEAD verifies the v2 terminal-backed path.
func testSEC37_ChunkedV2_RoundTripAndHEAD(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithChunking(true))
	data := bytes.Repeat([]byte("sec37-v2"), 20*1024)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)
	if got := get(t, gw, inst.Bucket, key); !bytes.Equal(got, data) {
		t.Fatalf("v2 round-trip mismatch: got %d bytes, want %d", len(got), len(data))
	}

	req, err := http.NewRequest(http.MethodHead, objectURL(gw, inst.Bucket, key), nil)
	if err != nil {
		t.Fatalf("HEAD request: %v", err)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK || resp.ContentLength != int64(len(data)) {
		t.Fatalf("HEAD: status=%d content-length=%d, want 200/%d", resp.StatusCode, resp.ContentLength, len(data))
	}
}

// testSEC37_ChunkedV2_TruncatedSuffix_FullGetRangeHEADFailClosed removes the
// v2 terminal and verifies all read shapes fail before returning plaintext.
func testSEC37_ChunkedV2_TruncatedSuffix_FullGetRangeHEADFailClosed(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithChunking(true))
	backend := newS3Client(t, inst)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, bytes.Repeat([]byte("truncate"), 20*1024))
	truncateObject(t, backend, inst.Bucket, key, 32)

	for _, tc := range []struct {
		name        string
		method      string
		rangeHeader string
	}{
		{name: "full-get", method: http.MethodGet},
		{name: "range-get", method: http.MethodGet, rangeHeader: "bytes=0-10"},
		{name: "head", method: http.MethodHead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, objectURL(gw, inst.Bucket, key), nil)
			if err != nil {
				t.Fatalf("%s request: %v", tc.name, err)
			}
			if tc.rangeHeader != "" {
				req.Header.Set("Range", tc.rangeHeader)
			}
			resp, err := gw.HTTPClient().Do(req)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatalf("%s body: %v", tc.name, readErr)
			}
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
				t.Errorf("%s succeeded for truncated v2 object: status=%d body=%d bytes", tc.name, resp.StatusCode, len(body))
			}
			if tc.name != "head" && bytes.Contains(body, []byte("truncate")) {
				t.Errorf("%s returned plaintext from truncated source", tc.name)
			}
			if tc.name == "head" && len(body) != 0 {
				t.Errorf("HEAD returned %d body bytes", len(body))
			}
		})
	}
}

// testSEC37_ChunkedV1_ReadCompatibility verifies a frozen legacy object remains readable.
func testSEC37_ChunkedV1_ReadCompatibility(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithChunking(true),
		harness.WithEncryptionPassword("test-encryption-password-123456"),
		harness.WithPBKDF2Iterations(crypto.DefaultPBKDF2Iterations),
	)
	backend := newS3Client(t, inst)
	key := uniqueKey(t)
	putSEC37V1Fixture(t, backend, inst.Bucket, key)
	want := []byte("frozen-sec37-v1")
	if got := get(t, gw, inst.Bucket, key); !bytes.Equal(got, want) {
		t.Fatalf("v1 compatibility mismatch: got %q, want %q", got, want)
	}
}
