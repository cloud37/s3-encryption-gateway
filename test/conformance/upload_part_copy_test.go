//go:build conformance

package conformance

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// doUploadPartCopy issues an UploadPartCopy request and returns the ETag
// parsed from the <CopyPartResult> XML response body (the ETag is *not*
// returned in the response header for UploadPartCopy — this differs from
// the plain UploadPart response).
func doUploadPartCopy(t *testing.T, gw *harness.Gateway, destBucket, destKey, uploadID string,
	partNum int, srcBucket, srcKey string, byteRange string) string {
	t.Helper()

	u := fmt.Sprintf("%s/%s/%s?partNumber=%d&uploadId=%s",
		gw.URL, destBucket, destKey, partNum, uploadID)
	req, _ := http.NewRequest("PUT", u, nil)
	req.Header.Set("x-amz-copy-source", fmt.Sprintf("/%s/%s", srcBucket, srcKey))
	if byteRange != "" {
		req.Header.Set("x-amz-copy-source-range", "bytes="+byteRange)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("UploadPartCopy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UploadPartCopy: status %d: %s", resp.StatusCode, string(body))
	}
	// Prefer the header if present (gateways may emit both), then fall back
	// to the <CopyPartResult><ETag> XML body.
	if etag := resp.Header.Get("ETag"); etag != "" {
		return etag
	}
	var result struct {
		XMLName xml.Name `xml:"CopyPartResult"`
		ETag    string   `xml:"ETag"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("UploadPartCopy: decode CopyPartResult XML: %v (body=%s)", err, string(body))
	}
	if result.ETag == "" {
		t.Fatalf("UploadPartCopy: empty ETag in response body: %s", string(body))
	}
	return result.ETag
}

// testUPC_Full copies a full chunked-encrypted source object via UploadPartCopy
// and verifies the assembled object matches the original plaintext.
func testUPC_Full(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	// Seed a source object.
	srcKey := uniqueKey(t)
	srcData := bytes.Repeat([]byte("chunked-src"), 10*1024) // ~110 KiB
	put(t, gw, inst.Bucket, srcKey, srcData)

	// Create destination MPU.
	dstKey := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })

	etag := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1,
		inst.Bucket, srcKey, "")
	completeMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{{1, etag}})

	got := get(t, gw, inst.Bucket, dstKey)
	if !bytes.Equal(got, srcData) {
		t.Errorf("UPC_Full: round-trip mismatch (%d bytes vs %d expected)", len(got), len(srcData))
	}
}

// testUPC_Range copies a byte range from a chunked source via UploadPartCopy.
func testUPC_Range(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	// Seed a 200 KiB source object with a distinct pattern.
	const size = 200 * 1024
	srcData := make([]byte, size)
	for i := range srcData {
		srcData[i] = byte(i % 199)
	}
	srcKey := uniqueKey(t)
	put(t, gw, inst.Bucket, srcKey, srcData)

	// Copy the middle 50 KiB (bytes 75000-124999).
	const (
		rangeStart = 75000
		rangeEnd   = 124999
	)

	dstKey := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })

	etag := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1,
		inst.Bucket, srcKey, fmt.Sprintf("%d-%d", rangeStart, rangeEnd))
	completeMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{{1, etag}})

	got := get(t, gw, inst.Bucket, dstKey)
	want := srcData[rangeStart : rangeEnd+1]
	if !bytes.Equal(got, want) {
		t.Errorf("UPC_Range: range mismatch (%d bytes vs %d expected)", len(got), len(want))
	}
}

// testUPC_Plaintext verifies the backend-native fast path for plaintext sources.
func testUPC_Plaintext(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	// Seed a plaintext source (no encryption metadata).
	// We seed it directly via the gateway — for a truly unencrypted object
	// we would need to bypass the gateway, so instead we verify that
	// UploadPartCopy handles a gateway-encrypted source.
	srcKey := uniqueKey(t)
	srcData := bytes.Repeat([]byte("pt"), 5*1024*1024/2) // 5 MiB
	put(t, gw, inst.Bucket, srcKey, srcData)

	dstKey := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })

	etag := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1,
		inst.Bucket, srcKey, "")
	completeMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{{1, etag}})

	got := get(t, gw, inst.Bucket, dstKey)
	if !bytes.Equal(got, srcData) {
		t.Errorf("UPC_Plaintext: round-trip mismatch")
	}
}

// testUPC_Legacy verifies UploadPartCopy from a legacy-AEAD encrypted source.
// Since we cannot seed a true legacy object via the current gateway (which
// writes chunked AEAD), this test exercises the chunked path and serves as
// a placeholder for the legacy-source path.
func testUPC_Legacy(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	srcKey := uniqueKey(t)
	srcData := bytes.Repeat([]byte("lga"), 1024) // small object (< chunk size)
	put(t, gw, inst.Bucket, srcKey, srcData)

	dstKey := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })

	etag := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1,
		inst.Bucket, srcKey, "")
	completeMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{{1, etag}})

	got := get(t, gw, inst.Bucket, dstKey)
	if !bytes.Equal(got, srcData) {
		t.Errorf("UPC_Legacy: round-trip mismatch")
	}
}

// testUPC_Mixed interleaves UploadPartCopy and UploadPart in the same MPU.
func testUPC_Mixed(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	// Seed source for the copy parts.
	srcKey := uniqueKey(t)
	srcData := bytes.Repeat([]byte("c"), 5*1024*1024) // 5 MiB
	put(t, gw, inst.Bucket, srcKey, srcData)

	// Direct-upload parts.
	directData := bytes.Repeat([]byte("d"), 5*1024*1024) // 5 MiB

	dstKey := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })

	// Part 1: copied from srcKey.
	etag1 := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1,
		inst.Bucket, srcKey, "")
	// Part 2: direct upload.
	etag2 := uploadPart(t, gw, inst.Bucket, dstKey, uploadID, 2, directData)
	// Part 3: copied again.
	etag3 := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 3,
		inst.Bucket, srcKey, "")

	completeMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{
		{1, etag1}, {2, etag2}, {3, etag3},
	})

	got := get(t, gw, inst.Bucket, dstKey)
	want := append(append(srcData, directData...), srcData...)
	if !bytes.Equal(got, want) {
		t.Errorf("UPC_Mixed: round-trip mismatch (%d bytes vs %d expected)", len(got), len(want))
	}
}

// testUPC_AbortMidway aborts an MPU that has had UploadPartCopy calls and
// verifies no destination object is left behind.
func testUPC_AbortMidway(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	srcKey := uniqueKey(t)
	put(t, gw, inst.Bucket, srcKey, bytes.Repeat([]byte("src"), 5*1024*1024/3))

	dstKey := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)

	doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1, inst.Bucket, srcKey, "")
	abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID)

	// Destination object must not exist.
	resp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, dstKey))
	if err != nil {
		t.Fatalf("GET after abort: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET after abort returned %d, want 404", resp.StatusCode)
	}
}

// testUPC_CrossBucket copies from one bucket to another (simulated by using
// two different key prefixes in the same bucket, since the conformance
// harness typically provisions one bucket per test run).
func testUPC_CrossBucket(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	srcKey := uniqueKey(t)
	srcData := bytes.Repeat([]byte("cross"), 5*1024*1024/5)
	put(t, gw, inst.Bucket, srcKey, srcData)

	dstKey := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })

	etag := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1,
		inst.Bucket, srcKey, "")
	completeMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{{1, etag}})

	got := get(t, gw, inst.Bucket, dstKey)
	if !bytes.Equal(got, srcData) {
		t.Errorf("UPC_CrossBucket: round-trip mismatch")
	}
}
