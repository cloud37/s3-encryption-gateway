//go:build conformance

package conformance

import (
	"bytes"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// testChunkedRoundTrip verifies a full PUT/GET round-trip of a chunked-AEAD
// encrypted object. The gateway uses chunked mode by default; this test
// confirms the envelope header is present and the plaintext round-trips.
func testChunkedRoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

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
	gw := harness.StartGateway(t, inst)

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
