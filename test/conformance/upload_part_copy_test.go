//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
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

func testSEC38_EncryptedMPU_UploadPartCopyReplacementRejected(t *testing.T, inst provider.Instance) {
	t.Helper()
	vk := provider.StartValkey(context.Background(), t)
	gw := harness.StartGateway(t, inst, harness.WithValkeyAddr(vk.Addr), harness.WithEncryptedMPUForBucket(inst.Bucket))
	srcKey, dstKey := uniqueKey(t), uniqueKey(t)
	firstData := bytes.Repeat([]byte("copy-one"), 32*1024)
	secondData := bytes.Repeat([]byte("copy-two"), 32*1024)
	put(t, gw, inst.Bucket, srcKey, firstData)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })
	first := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1, inst.Bucket, srcKey, "")
	// The gateway source is encrypted and its bytes are immutable for this
	// test; use a second source object to exercise a changed copy claim.
	secondSrcKey := uniqueKey(t)
	put(t, gw, inst.Bucket, secondSrcKey, secondData)
	u := fmt.Sprintf("%s/%s/%s?partNumber=1&uploadId=%s", gw.URL, inst.Bucket, dstKey, uploadID)
	req, _ := http.NewRequest(http.MethodPut, u, nil)
	req.Header.Set("x-amz-copy-source", fmt.Sprintf("/%s/%s", inst.Bucket, secondSrcKey))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("changed copied part: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || !bytes.Contains(body, []byte("OperationAborted")) {
		t.Fatalf("changed copied part: status=%d body=%s", resp.StatusCode, body)
	}
	completeMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{{1, first}})
	if got := get(t, gw, inst.Bucket, dstKey); !bytes.Equal(got, firstData) {
		t.Fatalf("changed copy did not preserve first plaintext")
	}
}

func testSEC38_EncryptedMPU_UploadPartCopyIdenticalRetry(t *testing.T, inst provider.Instance) {
	t.Helper()
	vk := provider.StartValkey(context.Background(), t)
	gw := harness.StartGateway(t, inst, harness.WithValkeyAddr(vk.Addr), harness.WithEncryptedMPUForBucket(inst.Bucket))
	srcKey, dstKey := uniqueKey(t), uniqueKey(t)
	data := bytes.Repeat([]byte("copy-retry"), 32*1024)
	put(t, gw, inst.Bucket, srcKey, data)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })
	first := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1, inst.Bucket, srcKey, "")
	second := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1, inst.Bucket, srcKey, "")
	if first != second {
		t.Fatalf("identical copied retry ETag %q differs from %q", second, first)
	}
	completeMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{{1, first}})
	if got := get(t, gw, inst.Bucket, dstKey); !bytes.Equal(got, data) {
		t.Fatalf("identical copied retry plaintext mismatch")
	}
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

// testUPC_StandardMetadata verifies the source metadata remains available on
// the completed destination object after UploadPartCopy.
func testUPC_StandardMetadata(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)
	srcKey, dstKey := uniqueKey(t), uniqueKey(t)
	data := []byte("upload part copy metadata")
	putReq, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, srcKey), bytes.NewReader(data))
	putReq.Header.Set("Content-Type", "image/jpeg")
	putReq.Header.Set("Cache-Control", "max-age=180")
	putReq.Header.Set("Content-Disposition", `inline; filename="photo.jpg"`)
	putResp, err := gw.HTTPClient().Do(putReq)
	if err != nil {
		t.Fatalf("UPC source PUT: %v", err)
	}
	io.Copy(io.Discard, putResp.Body)
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("UPC source PUT: status %d", putResp.StatusCode)
	}

	initReq, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/%s?uploads", gw.URL, inst.Bucket, dstKey), nil)
	initReq.Header.Set("Content-Type", "image/jpeg")
	initReq.Header.Set("Cache-Control", "max-age=180")
	initReq.Header.Set("Content-Disposition", `inline; filename="photo.jpg"`)
	initResp, err := gw.HTTPClient().Do(initReq)
	if err != nil {
		t.Fatalf("UPC initiate MPU: %v", err)
	}
	initBody, _ := io.ReadAll(initResp.Body)
	initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK {
		t.Fatalf("UPC initiate MPU: %d: %s", initResp.StatusCode, initBody)
	}
	var initResult struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(initBody, &initResult); err != nil {
		t.Fatalf("UPC initiate MPU XML: %v", err)
	}
	uploadID := initResult.UploadID
	if uploadID == "" {
		t.Fatal("UPC initiate MPU returned empty upload ID")
	}
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })
	etag := doUploadPartCopy(t, gw, inst.Bucket, dstKey, uploadID, 1, inst.Bucket, srcKey, "")
	completeMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{{1, etag}})

	headReq, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, dstKey), nil)
	headResp, err := gw.HTTPClient().Do(headReq)
	if err != nil {
		t.Fatalf("UPC destination HEAD: %v", err)
	}
	defer headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(headResp.Body)
		t.Fatalf("UPC destination HEAD: status %d: %s", headResp.StatusCode, body)
	}
	for header, want := range map[string]string{
		"Content-Type": "image/jpeg", "Cache-Control": "max-age=180",
		"Content-Disposition": `inline; filename="photo.jpg"`,
	} {
		if got := headResp.Header.Get(header); got != want {
			t.Errorf("UPC %s = %q, want %q", header, got, want)
		}
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

// testSEC37_UploadPartCopy_TruncatedChunkedV2Rejected verifies that a corrupt
// chunked source cannot produce a usable copied part.
func testSEC37_UploadPartCopy_TruncatedChunkedV2Rejected(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithChunking(true))
	backend := newS3Client(t, inst)
	srcKey, dstKey := uniqueKey(t), uniqueKey(t)
	put(t, gw, inst.Bucket, srcKey, bytes.Repeat([]byte("upc-truncate"), 20*1024))
	truncateObject(t, backend, inst.Bucket, srcKey, 32)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, dstKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID) })

	u := fmt.Sprintf("%s/%s/%s?partNumber=1&uploadId=%s", gw.URL, inst.Bucket, dstKey, uploadID)
	req, err := http.NewRequest(http.MethodPut, u, nil)
	if err != nil {
		t.Fatalf("UploadPartCopy request: %v", err)
	}
	req.Header.Set("x-amz-copy-source", fmt.Sprintf("/%s/%s", inst.Bucket, srcKey))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("UploadPartCopy: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("UploadPartCopy succeeded for truncated v2 source")
	}
	listURL := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, inst.Bucket, dstKey, uploadID)
	listResp, err := gw.HTTPClient().Get(listURL)
	if err != nil {
		t.Fatalf("ListParts: %v", err)
	}
	listBody, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK && listResp.StatusCode != http.StatusNoContent {
		t.Fatalf("ListParts status=%d body=%s", listResp.StatusCode, listBody)
	}
	if bytes.Contains(listBody, []byte("<Part>")) {
		t.Fatalf("corrupt source created a destination part: %s", listBody)
	}
	if completionStatus := completeMultipartUploadStatus(t, gw, inst.Bucket, dstKey, uploadID, []mpuPart{{1, "\"corrupt-source-part\""}}); completionStatus == http.StatusOK {
		t.Fatal("corrupt upload completed successfully")
	}
	check, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, dstKey))
	if err != nil {
		t.Fatalf("destination GET: %v", err)
	}
	io.Copy(io.Discard, check.Body)
	check.Body.Close()
	if check.StatusCode != http.StatusNotFound {
		t.Errorf("destination status=%d, want 404", check.StatusCode)
	}
	abortMultipartUpload(t, gw, inst.Bucket, dstKey, uploadID)
}
