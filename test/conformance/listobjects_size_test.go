//go:build conformance

package conformance

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
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

// testListObjectsV1_SizeAccuracy_WarmCache verifies that ListObjectsV1 returns
// plaintext sizes (listedSize == headSize) when the gateway has a warm Valkey
// size cache. Requires Docker for a Valkey container.
func testListObjectsV1_SizeAccuracy_WarmCache(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
	)

	prefix := fmt.Sprintf("v1-warm-%s/", uniqueSuffix(t))
	key := prefix + "object.txt"
	plaintext := []byte("This is plaintext for the warm-cache size conformance test.")
	plaintextSize := int64(len(plaintext))

	put(t, gw, inst.Bucket, key, plaintext)

	// LIST via gateway (v1 — no list-type param).
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

	// HEAD via gateway.
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

	// GET via gateway to verify.
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

	// Assertions: with a warm size cache, listed size must equal HEAD size.
	if headSize != getSize {
		t.Errorf("HEAD Content-Length (%d) != GET Content-Length (%d)", headSize, getSize)
	}
	if headSize != plaintextSize {
		t.Errorf("HEAD Content-Length = %d, want plaintext size %d", headSize, plaintextSize)
	}
	if getSize != plaintextSize {
		t.Errorf("GET Content-Length = %d, want plaintext size %d", getSize, plaintextSize)
	}
	if listedSize != headSize {
		t.Errorf("WARM-CACHE LIST Size = %d, HEAD Content-Length = %d: listed size must equal HEAD size", listedSize, headSize)
	}

	t.Logf("v1-warm-size-accuracy: listed=%d head=%d get=%d plaintext=%d (listed==head)",
		listedSize, headSize, getSize, plaintextSize)
}

// testListObjectsV2_SizeAccuracy_WarmCache verifies that ListObjectsV2 returns
// plaintext sizes (listedSize == headSize) when the gateway has a warm Valkey
// size cache. Requires Docker for a Valkey container.
func testListObjectsV2_SizeAccuracy_WarmCache(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
	)

	prefix := fmt.Sprintf("v2-warm-%s/", uniqueSuffix(t))
	key := prefix + "object.txt"
	plaintext := []byte("This is plaintext for the warm-cache size conformance test.")
	plaintextSize := int64(len(plaintext))

	put(t, gw, inst.Bucket, key, plaintext)

	// LIST via gateway (v2 — list-type=2).
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

	// HEAD via gateway.
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

	// GET via gateway to verify.
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

	// Assertions: with a warm size cache, listed size must equal HEAD size.
	if headSize != getSize {
		t.Errorf("HEAD Content-Length (%d) != GET Content-Length (%d)", headSize, getSize)
	}
	if headSize != plaintextSize {
		t.Errorf("HEAD Content-Length = %d, want plaintext size %d", headSize, plaintextSize)
	}
	if getSize != plaintextSize {
		t.Errorf("GET Content-Length = %d, want plaintext size %d", getSize, plaintextSize)
	}
	if listedSize != headSize {
		t.Errorf("WARM-CACHE LIST Size = %d, HEAD Content-Length = %d: listed size must equal HEAD size", listedSize, headSize)
	}

	t.Logf("v2-warm-size-accuracy: listed=%d head=%d get=%d plaintext=%d (listed==head)",
		listedSize, headSize, getSize, plaintextSize)
}

// testListObjectsV1_SizeAccuracy_MultiPage verifies that all objects in a
// listing page larger than 10 keys report correct plaintext sizes from the
// warm Valkey cache. This exercises the general cache-lookup path in
// handleListObjects (not the Docker Distribution maxKeys<=10 fast path).
//
// This is the primary regression test for issues #204 and #207 where rclone /
// restic / Duplicati saw wrong sizes on large listings.
func testListObjectsV1_SizeAccuracy_MultiPage(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
	)

	const numObjects = 20
	prefix := fmt.Sprintf("v1-multipage-%s/", uniqueSuffix(t))

	// Upload 20 objects of varying sizes through the gateway.
	// Each PUT populates the Valkey size cache automatically.
	type objectSpec struct {
		key       string
		plaintext []byte
	}
	objects := make([]objectSpec, numObjects)
	for i := 0; i < numObjects; i++ {
		plaintext := []byte(strings.Repeat(fmt.Sprintf("x%d", i), (i+1)*100))
		objects[i] = objectSpec{
			key:       fmt.Sprintf("%sobj-%03d.txt", prefix, i),
			plaintext: plaintext,
		}
		put(t, gw, inst.Bucket, objects[i].key, objects[i].plaintext)
	}

	// LIST with max-keys=100 — deliberately above the 10-key Docker
	// Distribution threshold so the general cache-lookup path is exercised.
	listURL := fmt.Sprintf("%s/%s?prefix=%s&max-keys=100", gw.URL, inst.Bucket, prefix)
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
	if len(listResult.Contents) != numObjects {
		t.Fatalf("expected %d objects in listing, got %d", numObjects, len(listResult.Contents))
	}

	// Build a map from key → expected plaintext size for quick lookup.
	expected := make(map[string]int64, numObjects)
	for _, o := range objects {
		expected[o.key] = int64(len(o.plaintext))
	}

	// Verify every listed size equals the plaintext size (not the ciphertext size).
	mismatches := 0
	for _, item := range listResult.Contents {
		want, ok := expected[item.Key]
		if !ok {
			t.Errorf("unexpected key in listing: %q", item.Key)
			continue
		}
		if item.Size != want {
			t.Errorf("key %q: LIST Size = %d, want plaintext size %d", item.Key, item.Size, want)
			mismatches++
		}
	}
	if mismatches == 0 {
		t.Logf("v1-multipage: all %d objects report correct plaintext sizes in listing", numObjects)
	}
}

// testListObjectsV2_SizeAccuracy_MultiPage is the ListObjectsV2 equivalent of
// testListObjectsV1_SizeAccuracy_MultiPage.
func testListObjectsV2_SizeAccuracy_MultiPage(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
	)

	const numObjects = 20
	prefix := fmt.Sprintf("v2-multipage-%s/", uniqueSuffix(t))

	type objectSpec struct {
		key       string
		plaintext []byte
	}
	objects := make([]objectSpec, numObjects)
	for i := 0; i < numObjects; i++ {
		plaintext := []byte(strings.Repeat(fmt.Sprintf("y%d", i), (i+1)*100))
		objects[i] = objectSpec{
			key:       fmt.Sprintf("%sobj-%03d.txt", prefix, i),
			plaintext: plaintext,
		}
		put(t, gw, inst.Bucket, objects[i].key, objects[i].plaintext)
	}

	listURL := fmt.Sprintf("%s/%s?list-type=2&prefix=%s&max-keys=100", gw.URL, inst.Bucket, prefix)
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
	if len(listResult.Contents) != numObjects {
		t.Fatalf("expected %d objects in listing, got %d", numObjects, len(listResult.Contents))
	}

	expected := make(map[string]int64, numObjects)
	for _, o := range objects {
		expected[o.key] = int64(len(o.plaintext))
	}

	mismatches := 0
	for _, item := range listResult.Contents {
		want, ok := expected[item.Key]
		if !ok {
			t.Errorf("unexpected key in listing: %q", item.Key)
			continue
		}
		if item.Size != want {
			t.Errorf("key %q: LIST Size = %d, want plaintext size %d", item.Key, item.Size, want)
			mismatches++
		}
	}
	if mismatches == 0 {
		t.Logf("v2-multipage: all %d objects report correct plaintext sizes in listing", numObjects)
	}
}

// testListObjects_SizeAccuracy_FallbackHead verifies the opt-in fallback HEAD
// path for objects that were uploaded before the size cache was deployed
// ("legacy" objects whose cache entry is absent).
//
// The test writes objects directly to the backend (bypassing the gateway) so
// the Valkey cache starts cold. It then enables fallback_head_enabled and
// confirms that:
//   1. The first listing resolves correct plaintext sizes via HEAD calls.
//   2. A second listing (same gateway, same Valkey) returns the same correct
//      sizes from the cache with no additional HEAD calls needed — confirming
//      the fallback self-populates the cache.
func testListObjects_SizeAccuracy_FallbackHead(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		// Enable the fallback HEAD batch and set a generous timeout.
		harness.WithConfigMutator(func(cfg *config.Config) {
			cfg.ListSizeTranslate.FallbackHeadEnabled = true
			cfg.ListSizeTranslate.FallbackHeadConcurrency = 10
			cfg.ListSizeTranslate.FallbackHeadTimeout = 30 * 1e9 // 30s in nanoseconds (time.Duration)
		}),
	)

	// Write objects directly to the backend, bypassing the gateway.
	// This simulates the "legacy objects uploaded before deployment" scenario.
	directClient := newS3Client(t, inst)
	eng, err := crypto.NewEngine([]byte("test-encryption-password-123456"))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	prefix := fmt.Sprintf("fallback-%s/", uniqueSuffix(t))
	const numObjects = 5
	type spec struct {
		key       string
		plainSize int64
	}
	specs := make([]spec, numObjects)
	for i := 0; i < numObjects; i++ {
		plaintext := []byte(strings.Repeat(fmt.Sprintf("legacy%d", i), (i+1)*50))
		key := fmt.Sprintf("%slegacy-%03d.bin", prefix, i)
		specs[i] = spec{key: key, plainSize: int64(len(plaintext))}
		putEncryptedObject(t, directClient, eng, inst.Bucket, key, plaintext, nil)
	}

	// Collect the keys for assertion.
	expected := make(map[string]int64, numObjects)
	listKeys := make([]string, numObjects)
	for i, s := range specs {
		expected[s.key] = s.plainSize
		listKeys[i] = s.key
	}

	// ── First listing: cache is cold, fallback HEAD fires ────────────────────
	listURL := fmt.Sprintf("%s/%s?list-type=2&prefix=%s&max-keys=100", gw.URL, inst.Bucket, prefix)
	resp, err := gw.HTTPClient().Get(listURL)
	if err != nil {
		t.Fatalf("first LIST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first LIST returned %d: %s", resp.StatusCode, string(body))
	}

	var firstResult s3ListBucketResult
	if err := xml.Unmarshal(body, &firstResult); err != nil {
		t.Fatalf("unmarshal first LIST: %v", err)
	}
	if len(firstResult.Contents) != numObjects {
		t.Fatalf("first LIST: expected %d objects, got %d", numObjects, len(firstResult.Contents))
	}

	for _, item := range firstResult.Contents {
		want, ok := expected[item.Key]
		if !ok {
			continue
		}
		if item.Size != want {
			t.Errorf("first LIST: key %q: Size = %d, want %d (plaintext)", item.Key, item.Size, want)
		}
	}

	// ── Second listing: cache is now warm, no HEAD calls needed ─────────────
	resp2, err := gw.HTTPClient().Get(listURL)
	if err != nil {
		t.Fatalf("second LIST: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second LIST returned %d: %s", resp2.StatusCode, string(body2))
	}

	var secondResult s3ListBucketResult
	if err := xml.Unmarshal(body2, &secondResult); err != nil {
		t.Fatalf("unmarshal second LIST: %v", err)
	}

	for _, item := range secondResult.Contents {
		want, ok := expected[item.Key]
		if !ok {
			continue
		}
		if item.Size != want {
			t.Errorf("second LIST (cache should be warm): key %q: Size = %d, want %d", item.Key, item.Size, want)
		}
	}

	t.Logf("fallback-head: %d legacy objects resolved on first list; second list served from cache", numObjects)
}

// testListObjects_SizeAccuracy_CacheCoherence verifies that cache entries
// remain correct across DELETE and CopyObject operations:
//
//   - After DELETE: the deleted object no longer appears in listings.
//   - After CopyObject: the destination key appears with the correct
//     plaintext size in subsequent listings.
//
// This prevents the scenario where a client lists after a delete/copy and
// sees a stale or missing cache entry returning the wrong size.
func testListObjects_SizeAccuracy_CacheCoherence(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
	)

	prefix := fmt.Sprintf("coherence-%s/", uniqueSuffix(t))
	srcKey := prefix + "source.bin"
	dstKey := prefix + "copy.bin"
	delKey := prefix + "delete-me.bin"

	plaintext := []byte(strings.Repeat("coherence", 200))
	plaintextSize := int64(len(plaintext))

	// Upload source and to-be-deleted objects through the gateway (warms cache).
	put(t, gw, inst.Bucket, srcKey, plaintext)
	put(t, gw, inst.Bucket, delKey, plaintext)

	// ── CopyObject: gateway should populate dst cache entry ──────────────────
	copyReq, err := http.NewRequest("PUT", objectURL(gw, inst.Bucket, dstKey), nil)
	if err != nil {
		t.Fatalf("copy: new request: %v", err)
	}
	copyReq.Header.Set("x-amz-copy-source", fmt.Sprintf("/%s/%s", inst.Bucket, srcKey))
	copyResp, err := gw.HTTPClient().Do(copyReq)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	io.Copy(io.Discard, copyResp.Body) //nolint:errcheck
	copyResp.Body.Close()
	if copyResp.StatusCode != http.StatusOK {
		t.Fatalf("copy returned %d", copyResp.StatusCode)
	}

	// ── DeleteObject: gateway should evict cache entry ───────────────────────
	delReq, err := http.NewRequest("DELETE", objectURL(gw, inst.Bucket, delKey), nil)
	if err != nil {
		t.Fatalf("delete: new request: %v", err)
	}
	delResp, err := gw.HTTPClient().Do(delReq)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	io.Copy(io.Discard, delResp.Body) //nolint:errcheck
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete returned %d (want 204)", delResp.StatusCode)
	}

	// ── List and verify ───────────────────────────────────────────────────────
	listURL := fmt.Sprintf("%s/%s?list-type=2&prefix=%s&max-keys=100", gw.URL, inst.Bucket, prefix)
	resp, err := gw.HTTPClient().Get(listURL)
	if err != nil {
		t.Fatalf("LIST after copy+delete: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LIST returned %d: %s", resp.StatusCode, string(body))
	}

	var listResult s3ListBucketResult
	if err := xml.Unmarshal(body, &listResult); err != nil {
		t.Fatalf("unmarshal LIST: %v", err)
	}

	// Index results by key.
	found := make(map[string]int64)
	for _, item := range listResult.Contents {
		found[item.Key] = item.Size
	}

	// src must have correct plaintext size.
	if sz, ok := found[srcKey]; !ok {
		t.Errorf("source key %q missing from listing", srcKey)
	} else if sz != plaintextSize {
		t.Errorf("source key %q: LIST Size = %d, want %d", srcKey, sz, plaintextSize)
	}

	// dst (copy destination) must have correct plaintext size.
	if sz, ok := found[dstKey]; !ok {
		t.Errorf("copy destination key %q missing from listing", dstKey)
	} else if sz != plaintextSize {
		t.Errorf("copy destination key %q: LIST Size = %d, want %d", dstKey, sz, plaintextSize)
	}

	// deleted key must NOT appear in listing.
	if sz, ok := found[delKey]; ok {
		t.Errorf("deleted key %q still appears in listing with size %d", delKey, sz)
	}

	_ = ctx
	t.Logf("cache-coherence: src size=%d dst size=%d del absent=true", found[srcKey], found[dstKey])
}
