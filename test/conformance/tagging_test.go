//go:build conformance

package conformance

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// testTaggingPassthrough verifies that x-amz-tagging on PUT is forwarded to
// the backend and survives a round-trip (mirrors TestTaggingPassthrough).
func testTaggingPassthrough(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	data := []byte("tagged content")
	key := uniqueKey(t)

	req, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, key), bytes.NewReader(data))
	req.Header.Set("x-amz-tagging", "env=test&tier=gold")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("PUT with tagging: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT with tagging: status %d: %s", resp.StatusCode, string(body))
	}

	// Object must still decrypt correctly.
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Errorf("tagged object round-trip mismatch")
	}
}

// testTaggingGetPut exercises GET/PUT on the ?tagging subresource.
func testTaggingGetPut(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, []byte("data"))

	// PUT tags via ?tagging subresource.
	tagsXML := `<Tagging><TagSet><Tag><Key>owner</Key><Value>qa</Value></Tag></TagSet></Tagging>`
	req, _ := http.NewRequest("PUT",
		fmt.Sprintf("%s?tagging", objectURL(gw, inst.Bucket, key)),
		strings.NewReader(tagsXML))
	req.Header.Set("Content-Type", "application/xml")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("PUT ?tagging: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT ?tagging: status %d: %s", resp.StatusCode, string(body))
	}

	// GET tags via ?tagging.
	resp2, err := gw.HTTPClient().Get(
		fmt.Sprintf("%s?tagging", objectURL(gw, inst.Bucket, key)))
	if err != nil {
		t.Fatalf("GET ?tagging: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET ?tagging: status %d: %s", resp2.StatusCode, string(body2))
	}
	if !strings.Contains(string(body2), "owner") {
		t.Errorf("GET ?tagging: tag key 'owner' missing from response: %s", string(body2))
	}
}
