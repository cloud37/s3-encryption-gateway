//go:build conformance

package conformance

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testEncryptedMetadata_RoundTrip verifies full PUT/GET round-trip with
// metadata encryption enabled, and checks that gateway-reserved encryption
// markers and the encrypted metadata blob are hidden from object responses.
func testEncryptedMetadata_RoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()

	metaKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	gw := harness.StartGateway(t, inst, harness.WithMetadataEncryptionKey(metaKey))

	cases := []struct {
		name string
		data []byte
	}{
		{"small", []byte("Hello, encrypted metadata!")},
		{"empty", []byte{}},
		{"medium", bytes.Repeat([]byte("M"), 4096)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			key := uniqueKey(t)
			putReq, _ := http.NewRequest(http.MethodPut, objectURL(gw, inst.Bucket, key), bytes.NewReader(tc.data))
			for name, value := range map[string]string{
				"Content-Type":        "application/octet-stream",
				"Cache-Control":       "private",
				"Content-Disposition": "attachment",
				"Content-Encoding":    "br",
				"Content-Language":    "en-GB",
				"Expires":             "Mon, 21 Oct 2030 07:28:00 GMT",
			} {
				putReq.Header.Set(name, value)
			}
			putResp, err := gw.HTTPClient().Do(putReq)
			if err != nil {
				t.Fatalf("PUT %q: %v", key, err)
			}
			io.Copy(io.Discard, putResp.Body)
			putResp.Body.Close()
			if putResp.StatusCode != http.StatusOK {
				t.Fatalf("PUT %q returned %d", key, putResp.StatusCode)
			}

			assertStandardHeaders := func(t *testing.T, headers http.Header) {
				t.Helper()
				for name, want := range map[string]string{
					"Content-Type":        "application/octet-stream",
					"Cache-Control":       "private",
					"Content-Disposition": "attachment",
					"Content-Encoding":    "br",
					"Content-Language":    "en-GB",
					"Expires":             "Mon, 21 Oct 2030 07:28:00 GMT",
				} {
					if got := headers.Get(name); got != want {
						t.Errorf("%s = %q, want %q", name, got, want)
					}
				}
			}

			// HEAD must retain the plaintext standard headers without exposing
			// encrypted metadata internals.
			req, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, key), nil)
			resp, err := gw.HTTPClient().Do(req)
			if err != nil {
				t.Fatalf("HEAD %q: %v", key, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("HEAD %q returned %d", key, resp.StatusCode)
			}
			assertStandardHeaders(t, resp.Header)

			// Gateway-reserved markers and sealed metadata must never be exposed.
			for _, name := range []string{"x-amz-meta-encrypted", "x-amz-meta-e", "x-amz-meta-enc-metadata", "x-amz-meta-em"} {
				if value := resp.Header.Get(name); value != "" {
					t.Errorf("reserved metadata %s should be hidden, got %q", name, value)
				}
			}

			// Individual encryption keys should be hidden.
			if v := resp.Header.Get("x-amz-meta-encryption-algorithm"); v != "" {
				t.Errorf("x-amz-meta-encryption-algorithm should be hidden, got %q", v)
			}
			if v := resp.Header.Get("x-amz-meta-encryption-key-salt"); v != "" {
				t.Errorf("x-amz-meta-encryption-key-salt should be hidden, got %q", v)
			}

			// GET the object and verify data integrity.
			got := get(t, gw, inst.Bucket, key)
			if !bytes.Equal(got, tc.data) {
				t.Errorf("round-trip data mismatch: got %d bytes, want %d bytes", len(got), len(tc.data))
			}
			getResp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
			if err != nil {
				t.Fatalf("GET headers %q: %v", key, err)
			}
			defer getResp.Body.Close()
			if getResp.StatusCode != http.StatusOK {
				t.Fatalf("GET %q returned %d", key, getResp.StatusCode)
			}
			assertStandardHeaders(t, getResp.Header)
			if getResp.Header.Get("ETag") == "" {
				t.Error("GET ETag should be present")
			}
			if gotLength := getResp.Header.Get("Content-Length"); gotLength != fmt.Sprint(len(tc.data)) {
				t.Errorf("GET Content-Length = %q, want %d", gotLength, len(tc.data))
			}
			for _, name := range []string{"x-amz-meta-encrypted", "x-amz-meta-e", "x-amz-meta-enc-metadata", "x-amz-meta-em"} {
				if value := getResp.Header.Get(name); value != "" {
					t.Errorf("GET exposed reserved metadata %s=%q", name, value)
				}
			}
		})
	}
}

// testEncryptedMetadata_BackwardCompat verifies that objects written without
// metadata encryption are still readable when metadata encryption is enabled.
func testEncryptedMetadata_BackwardCompat(t *testing.T, inst provider.Instance) {
	t.Helper()

	// Step 1: Write objects WITHOUT metadata encryption.
	gwNoMeta := harness.StartGateway(t, inst)

	data := []byte("backward-compat-data")
	key := uniqueKey(t)
	put(t, gwNoMeta, inst.Bucket, key, data)

	// Step 2: Read objects WITH metadata encryption enabled.
	metaKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	gwWithMeta := harness.StartGateway(t, inst, harness.WithMetadataEncryptionKey(metaKey))

	got := get(t, gwWithMeta, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Fatalf("backward-compat data mismatch: got %d bytes, want %d bytes", len(got), len(data))
	}
}

// testEncryptedMetadata_ListObjects verifies that objects with encrypted
// metadata appear correctly in S3 listing.
func testEncryptedMetadata_ListObjects(t *testing.T, inst provider.Instance) {
	t.Helper()

	metaKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	gw := harness.StartGateway(t, inst, harness.WithMetadataEncryptionKey(metaKey))

	prefix := fmt.Sprintf("enc-meta-list-%s/", uniqueSuffix(t))
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

	// GET each object and verify data integrity.
	for _, k := range keys {
		got := get(t, gw, inst.Bucket, k)
		want := []byte("data-" + k)
		if !bytes.Equal(got, want) {
			t.Errorf("key %q: data mismatch: got %d bytes, want %d bytes", k, len(got), len(want))
		}
	}
}
