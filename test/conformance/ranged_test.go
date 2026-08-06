//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testRangedRead verifies basic byte-range GET against an encrypted object.
func testRangedRead(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	// Build a 256-byte payload where each byte encodes its offset (mod 256).
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)

	cases := []struct {
		name       string
		start, end int64
	}{
		{"first_byte", 0, 0},
		{"last_byte", 255, 255},
		{"middle_10", 10, 19},
		{"first_half", 0, 127},
		{"second_half", 128, 255},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := getRange(t, gw, inst.Bucket, key, tc.start, tc.end)
			want := data[tc.start : tc.end+1]
			if !bytes.Equal(got, want) {
				t.Errorf("range [%d-%d]: got %v, want %v", tc.start, tc.end, got, want)
			}
		})
	}
}

// testRangedRead_CrossChunk verifies ranges that span chunked-AEAD chunk
// boundaries (default 64 KiB chunks). The test seeds a 192 KiB object
// (3 chunks) and issues ranges that start in chunk 0 and end in chunk 2.
func testRangedRead_CrossChunk(t *testing.T, inst provider.Instance) {
	t.Helper()

	const chunkSize = 64 * 1024
	payload := make([]byte, 3*chunkSize)
	for i := range payload {
		payload[i] = byte(i % 251) // prime modulus for a varied pattern
	}

	gw := harness.StartGateway(t, inst)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, payload)

	cases := []struct {
		name       string
		start, end int64
	}{
		// Mid-chunk within chunk 0.
		{"mid_chunk0", 1000, 1999},
		// Exactly at chunk boundary (end of chunk 0 / start of chunk 1).
		{"boundary_0_1", int64(chunkSize - 10), int64(chunkSize + 10)},
		// Spanning all three chunks.
		{"span_all", 100, int64(3*chunkSize - 100)},
		// End of last chunk.
		{"end_last_chunk", int64(2*chunkSize + 100), int64(3*chunkSize - 1)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := getRange(t, gw, inst.Bucket, key, tc.start, tc.end)
			want := payload[tc.start : tc.end+1]
			if !bytes.Equal(got, want) {
				t.Errorf("cross-chunk range [%d-%d]: mismatch (%d bytes got vs %d expected)",
					tc.start, tc.end, len(got), len(want))
			}
		})
	}
}

// testPassthroughRangedRead verifies ranges on objects stored directly in the
// backend, without gateway encryption metadata.
func testPassthroughRangedRead(t *testing.T, inst provider.Instance) {
	t.Helper()
	gateway := harness.StartGateway(t, inst)
	backend := newS3Client(t, inst)
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 251)
	}
	key := uniqueKey(t)
	if _, err := backend.PutObject(context.Background(), inst.Bucket, key, bytes.NewReader(data), nil, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put passthrough object: %v", err)
	}

	start, end := int64(1000), int64(1099)
	req, err := http.NewRequest("GET", objectURL(gateway, inst.Bucket, key), nil)
	if err != nil {
		t.Fatalf("create passthrough range request: %v", err)
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	resp, err := gateway.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("passthrough range request: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read passthrough range response: %v", err)
	}
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("passthrough range status %d, want 206: %s", resp.StatusCode, string(got))
	}
	if want := fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)); resp.Header.Get("Content-Range") != want {
		t.Fatalf("passthrough Content-Range %q, want %q", resp.Header.Get("Content-Range"), want)
	}
	if want := fmt.Sprintf("%d", end-start+1); resp.Header.Get("Content-Length") != want {
		t.Fatalf("passthrough Content-Length %q, want %q", resp.Header.Get("Content-Length"), want)
	}
	if !bytes.Equal(got, data[start:end+1]) {
		t.Fatalf("passthrough range [%d-%d]: got %d bytes with incorrect content", start, end, len(got))
	}
}
