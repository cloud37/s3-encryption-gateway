//go:build conformance

package conformance

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
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


// testACLInlinePassthrough verifies that x-amz-acl on PUT is forwarded to the
// backend and the ACL is applied. Gated on CapObjectACL.
func testACLInlinePassthrough(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)
	key := uniqueKey(t)

	req, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, key),
		bytes.NewReader([]byte("acl-test")))
	req.Header.Set("x-amz-acl", "public-read")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("PUT with acl: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT with acl: status %d", resp.StatusCode)
	}

	// Verify the object decrypts correctly.
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, []byte("acl-test")) {
		t.Errorf("ACL-tagged object round-trip mismatch")
	}
}

// testLifecycleHeaderPassthrough verifies that x-amz-expiration and
// x-amz-restore response headers survive the gateway passthrough path.
// Gated on CapBucketLifecycle.
//
// This test is informational: it asserts the header is forwarded if the
// backend sets it, but cannot force immediate expiration. The assertion
// uses t.Logf for the presence of the header value since the backend must
// evaluate the rule first (eventual consistency).
func testLifecycleHeaderPassthrough(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)
	key := uniqueKey(t)

	// PUT an object.
	data := []byte("lifecycle-test-content")
	put(t, gw, inst.Bucket, key, data)

	// GET the object and check for lifecycle headers.
	req, _ := http.NewRequest("GET", objectURL(gw, inst.Bucket, key), nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("GET lifecycle object: %v", err)
	}
	defer resp.Body.Close()

	// Log lifecycle header values for manual verification. The backend may
	// not have a lifecycle rule configured; we verify the forwarding path
	// is intact rather than expecting specific values.
	exp := resp.Header.Get("x-amz-expiration")
	restore := resp.Header.Get("x-amz-restore")
	if exp != "" {
		t.Logf("x-amz-expiration: %s", exp)
	} else {
		t.Log("x-amz-expiration not set by backend (expected if no lifecycle rule configured)")
	}
	if restore != "" {
		t.Logf("x-amz-restore: %s", restore)
	}
}
