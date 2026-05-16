//go:build conformance

package conformance

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/test/harness"
	"github.com/kenneth/s3-encryption-gateway/test/provider"
)

// s3ListBucketResult is a minimal XML struct for parsing ListObjects responses.
type s3ListBucketResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	Name        string   `xml:"Name"`
	IsTruncated bool     `xml:"IsTruncated"`
	MaxKeys     int      `xml:"MaxKeys"`
	Contents    []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	NextMarker            string `xml:"NextMarker"`
}

// testListObjectsV1_Pagination verifies ListObjects (v1) pagination via marker.
func testListObjectsV1_Pagination(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	prefix := fmt.Sprintf("v1-pag-%s/", uniqueSuffix(t))
	keys := []string{prefix + "a", prefix + "b", prefix + "c"}
	for _, k := range keys {
		put(t, gw, inst.Bucket, k, []byte("data-"+k))
	}

	// Page 1: max-keys=1, no marker
	listURL := fmt.Sprintf("%s/%s?prefix=%s&max-keys=1", gw.URL, inst.Bucket, prefix)
	resp, err := gw.HTTPClient().Get(listURL)
	if err != nil {
		t.Fatalf("LIST page 1: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LIST page 1 returned %d: %s", resp.StatusCode, string(body))
	}

	var page1 s3ListBucketResult
	if err := xml.Unmarshal(body, &page1); err != nil {
		t.Fatalf("unmarshal page 1: %v", err)
	}
	if len(page1.Contents) != 1 {
		t.Fatalf("page 1: expected 1 object, got %d", len(page1.Contents))
	}
	if page1.Contents[0].Key != keys[0] {
		t.Errorf("page 1: expected %q, got %q", keys[0], page1.Contents[0].Key)
	}
	if !page1.IsTruncated {
		t.Fatalf("page 1: expected truncated")
	}
	if page1.NextMarker == "" {
		t.Fatalf("page 1: expected NextMarker to be set")
	}

	// Page 2: use marker from page 1
	listURL2 := fmt.Sprintf("%s/%s?prefix=%s&max-keys=1&marker=%s", gw.URL, inst.Bucket, prefix, page1.NextMarker)
	resp2, err := gw.HTTPClient().Get(listURL2)
	if err != nil {
		t.Fatalf("LIST page 2: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("LIST page 2 returned %d: %s", resp2.StatusCode, string(body2))
	}

	var page2 s3ListBucketResult
	if err := xml.Unmarshal(body2, &page2); err != nil {
		t.Fatalf("unmarshal page 2: %v", err)
	}
	if len(page2.Contents) != 1 {
		t.Fatalf("page 2: expected 1 object, got %d", len(page2.Contents))
	}
	if page2.Contents[0].Key != keys[1] {
		t.Errorf("page 2: expected %q, got %q", keys[1], page2.Contents[0].Key)
	}
	if !page2.IsTruncated {
		t.Fatalf("page 2: expected truncated")
	}

	// Page 3
	listURL3 := fmt.Sprintf("%s/%s?prefix=%s&max-keys=1&marker=%s", gw.URL, inst.Bucket, prefix, page2.NextMarker)
	resp3, err := gw.HTTPClient().Get(listURL3)
	if err != nil {
		t.Fatalf("LIST page 3: %v", err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("LIST page 3 returned %d: %s", resp3.StatusCode, string(body3))
	}

	var page3 s3ListBucketResult
	if err := xml.Unmarshal(body3, &page3); err != nil {
		t.Fatalf("unmarshal page 3: %v", err)
	}
	if len(page3.Contents) != 1 {
		t.Fatalf("page 3: expected 1 object, got %d", len(page3.Contents))
	}
	if page3.Contents[0].Key != keys[2] {
		t.Errorf("page 3: expected %q, got %q", keys[2], page3.Contents[0].Key)
	}
	if page3.IsTruncated {
		t.Errorf("page 3: expected not truncated")
	}
	if page3.NextMarker != "" {
		t.Errorf("page 3: NextMarker should be empty when not truncated")
	}

	// Verify page 2 does not contain page 1's key (no duplicate token bug)
	if strings.Contains(string(body2), keys[0]) {
		t.Errorf("page 2 contains %q which should have been filtered by marker", keys[0])
	}
}

// testListObjectsV2_Pagination verifies ListObjectsV2 pagination via continuation-token.
func testListObjectsV2_Pagination(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	prefix := fmt.Sprintf("v2-pag-%s/", uniqueSuffix(t))
	keys := []string{prefix + "a", prefix + "b", prefix + "c"}
	for _, k := range keys {
		put(t, gw, inst.Bucket, k, []byte("data-"+k))
	}

	// Page 1: max-keys=1
	listURL := fmt.Sprintf("%s/%s?list-type=2&prefix=%s&max-keys=1", gw.URL, inst.Bucket, prefix)
	resp, err := gw.HTTPClient().Get(listURL)
	if err != nil {
		t.Fatalf("LIST page 1: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LIST page 1 returned %d: %s", resp.StatusCode, string(body))
	}

	var page1 s3ListBucketResult
	if err := xml.Unmarshal(body, &page1); err != nil {
		t.Fatalf("unmarshal page 1: %v", err)
	}
	if len(page1.Contents) != 1 {
		t.Fatalf("page 1: expected 1 object, got %d", len(page1.Contents))
	}
	if page1.Contents[0].Key != keys[0] {
		t.Errorf("page 1: expected %q, got %q", keys[0], page1.Contents[0].Key)
	}
	if !page1.IsTruncated {
		t.Fatalf("page 1: expected truncated")
	}
	if page1.NextContinuationToken == "" {
		t.Fatalf("page 1: expected NextContinuationToken")
	}

	// Page 2: use continuation-token from page 1
	listURL2 := fmt.Sprintf("%s/%s?list-type=2&prefix=%s&max-keys=1&continuation-token=%s", gw.URL, inst.Bucket, prefix, page1.NextContinuationToken)
	resp2, err := gw.HTTPClient().Get(listURL2)
	if err != nil {
		t.Fatalf("LIST page 2: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("LIST page 2 returned %d: %s", resp2.StatusCode, string(body2))
	}

	var page2 s3ListBucketResult
	if err := xml.Unmarshal(body2, &page2); err != nil {
		t.Fatalf("unmarshal page 2: %v", err)
	}
	if len(page2.Contents) != 1 {
		t.Fatalf("page 2: expected 1 object, got %d", len(page2.Contents))
	}
	if page2.Contents[0].Key != keys[1] {
		t.Errorf("page 2: expected %q, got %q", keys[1], page2.Contents[0].Key)
	}
	if !page2.IsTruncated {
		t.Fatalf("page 2: expected truncated")
	}

	// Page 3
	listURL3 := fmt.Sprintf("%s/%s?list-type=2&prefix=%s&max-keys=1&continuation-token=%s", gw.URL, inst.Bucket, prefix, page2.NextContinuationToken)
	resp3, err := gw.HTTPClient().Get(listURL3)
	if err != nil {
		t.Fatalf("LIST page 3: %v", err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("LIST page 3 returned %d: %s", resp3.StatusCode, string(body3))
	}

	var page3 s3ListBucketResult
	if err := xml.Unmarshal(body3, &page3); err != nil {
		t.Fatalf("unmarshal page 3: %v", err)
	}
	if len(page3.Contents) != 1 {
		t.Fatalf("page 3: expected 1 object, got %d", len(page3.Contents))
	}
	if page3.Contents[0].Key != keys[2] {
		t.Errorf("page 3: expected %q, got %q", keys[2], page3.Contents[0].Key)
	}
	// Note: some backends (including MinIO) may return a non-empty
	// NextContinuationToken on the final page. The only reliable signal
	// that pagination is complete is when a subsequent request with that
	// token returns zero Contents.
}

// testListObjectsV1_SizeAccuracy verifies that ListObjects (v1) returns ciphertext
// sizes while HeadObject and GetObject return decrypted (plaintext) sizes.
func testListObjectsV1_SizeAccuracy(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	prefix := fmt.Sprintf("v1-size-%s/", uniqueSuffix(t))
	key := prefix + "object.txt"
	plaintext := []byte("This is plaintext for the v1 size-accuracy conformance test.")
	plaintextSize := int64(len(plaintext))

	put(t, gw, inst.Bucket, key, plaintext)

	// --- LIST via gateway (v1) ---
	listURL := fmt.Sprintf("%s/%s?prefix=%s", gw.URL, inst.Bucket, prefix)
	resp, err := gw.HTTPClient().Get(listURL)
	if err != nil {
		t.Fatalf("LIST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LIST returned %d: %s", resp.StatusCode, string(body))
	}

	var listResult s3ListBucketResult
	if err := xml.Unmarshal(body, &listResult); err != nil {
		t.Fatalf("unmarshal LIST response: %v", err)
	}
	if len(listResult.Contents) != 1 {
		t.Fatalf("expected 1 object in listing, got %d", len(listResult.Contents))
	}
	listedSize := listResult.Contents[0].Size

	// --- HEAD via gateway ---
	reqHead, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, key), nil)
	respHead, err := gw.HTTPClient().Do(reqHead)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	respHead.Body.Close()
	if respHead.StatusCode != http.StatusOK {
		t.Fatalf("HEAD returned %d", respHead.StatusCode)
	}
	headCL := respHead.Header.Get("Content-Length")
	headSize, err := strconv.ParseInt(headCL, 10, 64)
	if err != nil {
		t.Fatalf("HEAD Content-Length %q: %v", headCL, err)
	}

	// --- GET via gateway ---
	respGet, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	respGet.Body.Close()
	if respGet.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d", respGet.StatusCode)
	}
	getCL := respGet.Header.Get("Content-Length")
	getSize, err := strconv.ParseInt(getCL, 10, 64)
	if err != nil {
		t.Fatalf("GET Content-Length %q: %v", getCL, err)
	}

	// Assertions:
	if headSize != getSize {
		t.Errorf("HEAD Content-Length (%d) != GET Content-Length (%d)", headSize, getSize)
	}
	if headSize != plaintextSize {
		t.Errorf("HEAD Content-Length = %d, want plaintext size %d", headSize, plaintextSize)
	}
	if getSize != plaintextSize {
		t.Errorf("GET Content-Length = %d, want plaintext size %d", getSize, plaintextSize)
	}
	if listedSize <= plaintextSize {
		t.Errorf("LIST Size = %d, expected > plaintext size %d (should be ciphertext size)", listedSize, plaintextSize)
	}

	t.Logf("v1-size-accuracy: listed=%d (ciphertext) head=%d get=%d (plaintext=%d)",
		listedSize, headSize, getSize, plaintextSize)
}

// testListObjectsV2_SizeAccuracy verifies that ListObjectsV2 returns ciphertext
// sizes while HeadObject and GetObject return decrypted (plaintext) sizes.
func testListObjectsV2_SizeAccuracy(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	prefix := fmt.Sprintf("v2-size-%s/", uniqueSuffix(t))
	key := prefix + "object.txt"
	plaintext := []byte("This is plaintext for the v2 size-accuracy conformance test.")
	plaintextSize := int64(len(plaintext))

	put(t, gw, inst.Bucket, key, plaintext)

	// --- LIST via gateway (v2) ---
	listURL := fmt.Sprintf("%s/%s?list-type=2&prefix=%s", gw.URL, inst.Bucket, prefix)
	resp, err := gw.HTTPClient().Get(listURL)
	if err != nil {
		t.Fatalf("LIST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LIST returned %d: %s", resp.StatusCode, string(body))
	}

	var listResult s3ListBucketResult
	if err := xml.Unmarshal(body, &listResult); err != nil {
		t.Fatalf("unmarshal LIST response: %v", err)
	}
	if len(listResult.Contents) != 1 {
		t.Fatalf("expected 1 object in listing, got %d", len(listResult.Contents))
	}
	listedSize := listResult.Contents[0].Size

	// --- HEAD via gateway ---
	reqHead, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, key), nil)
	respHead, err := gw.HTTPClient().Do(reqHead)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	respHead.Body.Close()
	if respHead.StatusCode != http.StatusOK {
		t.Fatalf("HEAD returned %d", respHead.StatusCode)
	}
	headCL := respHead.Header.Get("Content-Length")
	headSize, err := strconv.ParseInt(headCL, 10, 64)
	if err != nil {
		t.Fatalf("HEAD Content-Length %q: %v", headCL, err)
	}

	// --- GET via gateway ---
	respGet, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	respGet.Body.Close()
	if respGet.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d", respGet.StatusCode)
	}
	getCL := respGet.Header.Get("Content-Length")
	getSize, err := strconv.ParseInt(getCL, 10, 64)
	if err != nil {
		t.Fatalf("GET Content-Length %q: %v", getCL, err)
	}

	// Assertions:
	if headSize != getSize {
		t.Errorf("HEAD Content-Length (%d) != GET Content-Length (%d)", headSize, getSize)
	}
	if headSize != plaintextSize {
		t.Errorf("HEAD Content-Length = %d, want plaintext size %d", headSize, plaintextSize)
	}
	if getSize != plaintextSize {
		t.Errorf("GET Content-Length = %d, want plaintext size %d", getSize, plaintextSize)
	}
	if listedSize <= plaintextSize {
		t.Errorf("LIST Size = %d, expected > plaintext size %d (should be ciphertext size)", listedSize, plaintextSize)
	}

	t.Logf("v2-size-accuracy: listed=%d (ciphertext) head=%d get=%d (plaintext=%d)",
		listedSize, headSize, getSize, plaintextSize)
}
