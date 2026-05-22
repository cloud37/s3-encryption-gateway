//go:build conformance

package conformance

// V0.6-PERF-1 conformance tests.
//
// These tests verify that the streaming refactors implemented in V0.6-PERF-1
// are correct end-to-end against real S3-compatible backends:
//
//   - testCopyObject_LargeChunked    — CopyObject on a multi-chunk chunked object
//     round-trips correctly after the Phase C streaming pipeline (no intermediate
//     decryptedData []byte allocation).
//   - testChunkedRangedRead_Large    — large range read via io.CopyBuffer (Phase B)
//     spanning two chunk boundaries on a 7-chunk object.
//   - testCompression_RoundTrip      — compression streaming (Phase E) produces a
//     correctly decompressable ciphertext when gzip is enabled.
//   - testUploadPart_OversizeCap     — gateway returns HTTP 413 when a part body
//     exceeds server.max_part_buffer (Phase D SeekableBody cap).

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testCopyObject_LargeChunked verifies that CopyObject on a large
// chunked-encrypted multi-chunk object round-trips byte-perfectly after the
// Phase C streaming pipeline (decryptedReader passed directly to Encrypt).
// 300 KiB ensures at least 4 chunks at the default 64 KiB chunk size.
//
// V0.6-PERF-1 Phase C regression guard.
func testCopyObject_LargeChunked(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	// 300 KiB — 4+ chunks at default 64 KiB chunk size.
	const payloadLen = 300 * 1024
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	srcKey := uniqueKey(t)
	dstKey := uniqueKey(t)

	put(t, gw, inst.Bucket, srcKey, payload)

	// CopyObject: src → dst within the same bucket.
	req, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, dstKey), nil)
	req.Header.Set("x-amz-copy-source", fmt.Sprintf("/%s/%s", inst.Bucket, srcKey))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("CopyObject: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CopyObject returned %d: %s", resp.StatusCode, string(body))
	}

	// Retrieve the copy and verify it is byte-identical to the original.
	got := get(t, gw, inst.Bucket, dstKey)
	if !bytes.Equal(got, payload) {
		t.Errorf("CopyObject_LargeChunked: got %d bytes, want %d bytes",
			len(got), len(payload))
	}
}

// testChunkedRangedRead_Large verifies that a range read on a large
// chunked-encrypted object returns the correct bytes via the Phase B
// io.CopyBuffer streaming path.  7 chunks × 64 KiB; the range spans two
// chunk boundaries so the optimised-range path (io.CopyBuffer to the writer)
// is exercised end-to-end against a real backend.
//
// V0.6-PERF-1 Phase B regression guard.
func testChunkedRangedRead_Large(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	const chunkSize = 64 * 1024
	const payloadLen = 7 * chunkSize // exactly 7 chunks
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte((i * 7) % 251)
	}

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, payload)

	// Range spanning the boundary between chunk 0 and chunk 1.
	// rangeStart is 536 bytes before the end of chunk 0.
	const rangeStart = int64(chunkSize - 536) // 65000
	const rangeEnd = int64(chunkSize + 1023)  // 66559
	want := payload[rangeStart : rangeEnd+1]

	got := getRange(t, gw, inst.Bucket, key, rangeStart, rangeEnd)
	if !bytes.Equal(got, want) {
		t.Errorf("ChunkedRangedRead_Large: got %d bytes, want %d bytes; first byte mismatch at index 0: got %02x want %02x",
			len(got), len(want), safeIndex(got, 0), safeIndex(want, 0))
	}
}

// testCompression_RoundTrip verifies that the Phase E streaming compression
// implementation (gzip io.Pipe in Compress, gzip.Reader in Decompress) correctly
// round-trips compressible data through the full gateway pipeline.
// 200 KiB of highly compressible text is used so the gzip writer flushes
// non-trivially and the gzip reader must decompress all data.
//
// V0.6-PERF-1 Phase E regression guard.
func testCompression_RoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	// Start a gateway with gzip compression enabled.
	// MinSize defaults to 0 via the harness (WithCompression sets Enabled=true
	// and Algorithm; MinSize stays 0 so even small objects are compressed).
	gw := harness.StartGateway(t, inst,
		harness.WithCompression("gzip"),
		harness.WithConfigMutator(func(cfg *config.Config) {
			cfg.Compression.MinSize = 0
			cfg.Compression.Level = 6
		}),
	)

	// 200 KiB of highly compressible text.
	const payloadLen = 200 * 1024
	payload := bytes.Repeat(
		[]byte("the quick brown fox jumps over the lazy dog. "),
		payloadLen/45+1,
	)
	payload = payload[:payloadLen]

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, payload)
	got := get(t, gw, inst.Bucket, key)

	if !bytes.Equal(got, payload) {
		t.Errorf("Compression_RoundTrip mismatch: got %d bytes, want %d bytes",
			len(got), len(payload))
	}
}

// testUploadPart_OversizeCap verifies that the gateway returns HTTP 413
// EntityTooLarge when a plaintext UploadPart request body exceeds
// server.max_part_buffer (Phase D SeekableBody cap). The gateway is configured
// with a 100-byte cap so that a 101-byte part body triggers the guard before
// any backend write occurs.
//
// V0.6-PERF-1 Phase D regression guard.
func testUploadPart_OversizeCap(t *testing.T, inst provider.Instance) {
	t.Helper()
	const cap = int64(100)
	gw := harness.StartGateway(t, inst,
		harness.WithConfigMutator(func(cfg *config.Config) {
			cfg.Server.MaxPartBuffer = cap
		}),
	)

	key := uniqueKey(t)

	// Initiate a multipart upload.
	u := fmt.Sprintf("%s/%s/%s?uploads", gw.URL, inst.Bucket, key)
	initResp, err := gw.HTTPClient().Post(u, "application/xml", nil)
	if err != nil {
		t.Fatalf("InitiateMultipartUpload: %v", err)
	}
	defer initResp.Body.Close()
	initBody, _ := io.ReadAll(initResp.Body)
	if initResp.StatusCode != http.StatusOK {
		t.Fatalf("InitiateMultipartUpload: status %d: %s", initResp.StatusCode, string(initBody))
	}
	// Extract uploadId from XML.
	uploadID := extractXMLField(string(initBody), "UploadId")
	if uploadID == "" {
		t.Fatalf("InitiateMultipartUpload: no UploadId in response: %s", string(initBody))
	}
	t.Cleanup(func() {
		abortURL := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, inst.Bucket, key, uploadID)
		req, _ := http.NewRequest("DELETE", abortURL, nil)
		resp, err := gw.HTTPClient().Do(req)
		if err == nil {
			resp.Body.Close()
		}
	})

	// Upload a part body that is 1 byte over the cap — must be refused with 413.
	partURL := fmt.Sprintf("%s/%s/%s?partNumber=1&uploadId=%s", gw.URL, inst.Bucket, key, uploadID)
	oversizeBody := strings.Repeat("X", int(cap)+1) // 101 bytes
	req, _ := http.NewRequest("PUT", partURL, strings.NewReader(oversizeBody))
	req.ContentLength = int64(len(oversizeBody))
	partResp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("UploadPart (oversize): %v", err)
	}
	defer partResp.Body.Close()
	partBody, _ := io.ReadAll(partResp.Body)

	if partResp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("UploadPart_OversizeCap: expected HTTP 413, got %d; body: %s",
			partResp.StatusCode, string(partBody))
	}
	if !strings.Contains(string(partBody), "EntityTooLarge") {
		t.Errorf("UploadPart_OversizeCap: expected EntityTooLarge in response body, got: %s",
			string(partBody))
	}
}

// safeIndex returns data[i] or 0 if out of bounds.
func safeIndex(data []byte, i int) byte {
	if i < len(data) {
		return data[i]
	}
	return 0
}

// extractXMLField is a minimal XML value extractor for single-value tags.
func extractXMLField(xml, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	start := strings.Index(xml, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(xml[start:], close)
	if end < 0 {
		return ""
	}
	return xml[start : start+end]
}
