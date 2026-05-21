//go:build conformance

package conformance

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// testPutGet verifies basic PUT + GET round-trip encryption/decryption.
func testPutGet(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	cases := []struct {
		name string
		data []byte
	}{
		{"small", []byte("Hello, conformance!")},
		{"empty", []byte{}},
		{"medium_100KB", bytes.Repeat([]byte("x"), 100*1024)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			key := uniqueKey(t)
			put(t, gw, inst.Bucket, key, tc.data)
			got := get(t, gw, inst.Bucket, key)
			if !bytes.Equal(got, tc.data) {
				t.Errorf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(tc.data))
			}
		})
	}
}

// testPutGet_Large verifies encryption round-trip on a 10 MiB object.
// Under -short the test uses 100 KiB instead.
func testPutGet_Large(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	size := 10 * 1024 * 1024 // 10 MiB
	if testing.Short() {
		size = 100 * 1024 // 100 KiB under -short
	}

	data := bytes.Repeat([]byte("L"), size)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Errorf("large round-trip mismatch: got %d bytes, want %d bytes", len(got), len(data))
	}
}

// testHeadObject verifies that HEAD returns the correct Content-Length.
func testHeadObject(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	data := []byte("head-me")
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)

	req, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, key), nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD returned %d", resp.StatusCode)
	}
	// Content-Length from the gateway should reflect the plaintext length.
	if cl := resp.ContentLength; cl != int64(len(data)) {
		t.Errorf("Content-Length = %d, want %d", cl, len(data))
	}
}

// testListObjects verifies that objects written via the gateway appear in listing.
func testListObjects(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	prefix := fmt.Sprintf("list-%s/", uniqueSuffix(t))
	keys := []string{prefix + "a", prefix + "b", prefix + "c"}
	for _, k := range keys {
		put(t, gw, inst.Bucket, k, []byte("data-"+k))
	}

	// LIST via the gateway.
	listURL := fmt.Sprintf("%s/%s?prefix=%s", gw.URL, inst.Bucket, prefix)
	resp, err := gw.HTTPClient().Get(listURL)
	if err != nil {
		t.Fatalf("LIST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LIST returned %d: %s", resp.StatusCode, string(body))
	}

	for _, k := range keys {
		if !strings.Contains(string(body), k) {
			t.Errorf("key %q missing from listing", k)
		}
	}
}

// testDeleteObject verifies that objects deleted via the gateway are gone.
func testDeleteObject(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, []byte("delete-me"))

	req, _ := http.NewRequest("DELETE", objectURL(gw, inst.Bucket, key), nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE returned %d", resp.StatusCode)
	}

	// GET must now return 404.
	resp2, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
	if err != nil {
		t.Fatalf("GET after DELETE: %v", err)
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("GET after DELETE returned %d, want 404", resp2.StatusCode)
	}
}

// testDeleteObjects verifies the S3 batch-delete (DeleteObjects) operation.
func testDeleteObjects(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	prefix := fmt.Sprintf("batch-del-%s/", uniqueSuffix(t))
	keys := []string{prefix + "x", prefix + "y", prefix + "z"}
	for _, k := range keys {
		put(t, gw, inst.Bucket, k, []byte("to-be-deleted"))
	}

	// Build DeleteObjects request.
	var xmlBody strings.Builder
	xmlBody.WriteString(`<Delete>`)
	for _, k := range keys {
		xmlBody.WriteString(fmt.Sprintf(`<Object><Key>%s</Key></Object>`, k))
	}
	xmlBody.WriteString(`</Delete>`)
	body := xmlBody.String()

	// S3/MinIO require Content-MD5 on the multi-delete request.
	md5sum := md5.Sum([]byte(body))
	md5b64 := base64.StdEncoding.EncodeToString(md5sum[:])

	req, _ := http.NewRequest("POST",
		fmt.Sprintf("%s/%s?delete", gw.URL, inst.Bucket),
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Content-MD5", md5b64)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("DeleteObjects: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteObjects returned %d: %s", resp.StatusCode, string(respBody))
	}

	// All keys must be gone.
	for _, k := range keys {
		r, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, k))
		if err != nil {
			t.Fatalf("GET after batch delete (%s): %v", k, err)
		}
		defer r.Body.Close()
		io.Copy(io.Discard, r.Body)
		if r.StatusCode != http.StatusNotFound {
			t.Errorf("GET %q after batch delete returned %d, want 404", k, r.StatusCode)
		}
	}
}

// testCopyObject verifies CopyObject preserves plaintext round-trip.
func testCopyObject(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	srcKey := uniqueKey(t)
	dstKey := uniqueKey(t)
	data := []byte("copy-source-data")

	put(t, gw, inst.Bucket, srcKey, data)

	// CopyObject via x-amz-copy-source header.
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

	got := get(t, gw, inst.Bucket, dstKey)
	if !bytes.Equal(got, data) {
		t.Errorf("CopyObject round-trip mismatch")
	}
}

// testMetadataRoundTrip verifies that object metadata survives a PUT/GET cycle.
// This catches the "cipher: message authentication failed" class of bug that
// occurs when a backend mangles metadata (e.g. URL-encodes keys).
func testMetadataRoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	data := []byte("metadata-test-content")
	key := uniqueKey(t)

	req, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, key), bytes.NewReader(data))
	req.Header.Set("x-amz-meta-test-key", "test-value")
	req.Header.Set("x-amz-meta-another", "another-val")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("PUT with metadata: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}

	// GET must return the same plaintext (metadata mismatch causes AEAD failure).
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Errorf("metadata round-trip: content mismatch")
	}

	// HEAD must surface the metadata.
	req2, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, key), nil)
	resp2, err := gw.HTTPClient().Do(req2)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if v := resp2.Header.Get("x-amz-meta-test-key"); v != "test-value" {
		t.Errorf("HEAD x-amz-meta-test-key = %q, want %q", v, "test-value")
	}
}
